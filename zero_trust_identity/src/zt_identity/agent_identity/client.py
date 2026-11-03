"""Agent-side credential manager for scheme B.

* Enrolls with the pre-registered enrollment key (mounted only into this
  agent's container), proving possession via the CSR signature and a fresh
  issuer nonce, over the workload's own mTLS (SVID) connection.
* Renews at a fixed fraction of the certificate lifetime, always rotating to a
  NEW in-memory P-256 key (the renewal is authorized by a signature from the
  current key). The agent key is never the SVID key.
* Signs every outbound request with RFC 9421 using the current agent key.
"""
from __future__ import annotations

import asyncio
import base64
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..events import EventLog
from . import certs
from .httpsig import sign_request

PostJson = Callable[[str, dict], Awaitable[tuple[int, dict]]]


@dataclass(frozen=True)
class AgentCredential:
    key: object
    cert_der: bytes
    cert_header: str
    key_id: str          # "sha256:<cert fingerprint>"
    serial: str
    not_before: datetime
    not_after: datetime


class AgentCredentialManager:
    def __init__(
        self,
        *,
        agent_id: str,
        workload_spiffe_id: Callable[[], str],
        issuer_url: str,
        post_json: PostJson,
        enrollment_key_path: str,
        events: EventLog,
        renew_fraction: float = 0.5,
    ) -> None:
        self.agent_id = agent_id
        self.workload_spiffe_id = workload_spiffe_id
        self.issuer_url = issuer_url.rstrip("/")
        self.post_json = post_json
        self.enrollment_key_path = enrollment_key_path
        self.events = events
        self.renew_fraction = renew_fraction
        self.cred: AgentCredential | None = None
        self.time_to_first_credential_s: float | None = None
        self.renewals = 0
        self.renew_failures = 0
        self._task: asyncio.Task | None = None
        self._reenroll_lock = asyncio.Lock()
        self.reenrollments = 0

    # ------------------------------------------------------------------
    async def _nonce(self) -> str:
        status, body = await self.post_json(f"{self.issuer_url}/v1/agent-credentials/challenge",
                                            {"agent_id": self.agent_id})
        if status != 200:
            raise RuntimeError(f"challenge rejected: {status} {body}")
        return str(body["nonce"])

    def _install(self, key, resp: dict, kind: str, elapsed_s: float) -> None:
        der = base64.b64decode(resp["certificate"])
        cert = x509.load_der_x509_certificate(der)
        self.cred = AgentCredential(
            key=key,
            cert_der=der,
            cert_header=base64.b64encode(der).decode("ascii"),
            key_id=certs.fingerprint(der),
            serial=format(cert.serial_number, "x"),
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
        )
        self.events.emit(
            "agent_cert_" + kind, agent_id=self.agent_id, serial=self.cred.serial,
            not_after=self.cred.not_after.isoformat(), key_id=self.cred.key_id,
            duration_ms=round(elapsed_s * 1000, 3),
        )

    async def enroll(self) -> None:
        t0 = time.monotonic()
        key = serialization.load_pem_private_key(Path(self.enrollment_key_path).read_bytes(), password=None)
        nonce = await self._nonce()
        csr = certs.build_csr(key, self.agent_id, nonce)
        status, body = await self.post_json(
            f"{self.issuer_url}/v1/agent-credentials/enroll",
            {"agent_id": self.agent_id, "csr": base64.b64encode(csr).decode("ascii")},
        )
        if status != 200:
            raise RuntimeError(f"enroll rejected: {status} {body}")
        self._install(key, body, "enrolled", time.monotonic() - t0)

    async def renew(self) -> None:
        assert self.cred is not None
        t0 = time.monotonic()
        new_key = certs.new_key()
        nonce = await self._nonce()
        csr = certs.build_csr(new_key, self.agent_id, nonce)
        proof = certs.sign_renew_proof(self.cred.key, csr, nonce)
        status, body = await self.post_json(
            f"{self.issuer_url}/v1/agent-credentials/renew",
            {
                "agent_id": self.agent_id,
                "csr": base64.b64encode(csr).decode("ascii"),
                "current_certificate": self.cred.cert_header,
                "proof": proof,
            },
        )
        if status != 200:
            raise RuntimeError(f"renew rejected: {status} {body}")
        self._install(new_key, body, "renewed", time.monotonic() - t0)
        self.renewals += 1

    async def reenroll(self, reason: str) -> None:
        """Re-enroll with the pre-registered enrollment key after the current
        certificate was revoked (e.g. admin disable -> enable)."""
        if self._reenroll_lock.locked():
            return
        async with self._reenroll_lock:
            self.events.emit("agent_cert_reenroll_start", agent_id=self.agent_id, reason=reason)
            try:
                await self.enroll()
                self.reenrollments += 1
            except Exception as exc:
                self.events.emit("agent_cert_reenroll_failed", error=str(exc)[:200])

    async def start(self) -> None:
        t0 = time.monotonic()
        delay = 0.5
        while True:
            try:
                await self.enroll()
                break
            except Exception as exc:  # issuer may still be starting
                self.events.emit("agent_cert_enroll_retry", error=str(exc)[:200])
                await asyncio.sleep(delay)
                delay = min(delay * 2, 5.0)
        self.time_to_first_credential_s = time.monotonic() - t0
        self.events.emit("agent_cert_ready", agent_id=self.agent_id,
                         time_to_first_credential_s=round(self.time_to_first_credential_s, 4))
        self._task = asyncio.create_task(self._renew_loop())

    async def _renew_loop(self) -> None:
        while True:
            cred = self.cred
            assert cred is not None
            lifetime = (cred.not_after - cred.not_before).total_seconds()
            due = cred.not_before.timestamp() + lifetime * self.renew_fraction
            await asyncio.sleep(max(0.5, due - time.time()))
            try:
                await self.renew()
            except Exception as exc:
                self.renew_failures += 1
                self.events.emit("agent_cert_renew_failed", error=str(exc)[:200])
                if "current_cert_revoked" in str(exc):
                    await self.reenroll("renew_rejected_current_cert_revoked")
                await asyncio.sleep(2.0)

    # ------------------------------------------------------------------
    def sign(self, *, method: str, url: str, body: bytes, request_id: str, workflow_run_id: str) -> tuple[dict[str, str], float]:
        cred = self.cred
        if cred is None:
            raise RuntimeError("agent credential not ready")
        t0 = time.perf_counter_ns()
        headers = sign_request(
            method=method, url=url, body=body, private_key=cred.key, key_id=cred.key_id,
            agent_id=self.agent_id, workload_id=self.workload_spiffe_id(),
            request_id=request_id, workflow_run_id=workflow_run_id, cert_header=cred.cert_header,
        )
        return headers, (time.perf_counter_ns() - t0) / 1e6

    def status(self) -> dict:
        c = self.cred
        return {
            "agent_id": self.agent_id,
            "serial": c.serial if c else None,
            "not_after": c.not_after.isoformat() if c else None,
            "renewals": self.renewals,
            "renew_failures": self.renew_failures,
            "reenrollments": self.reenrollments,
            "time_to_first_credential_s": self.time_to_first_credential_s,
            "now": datetime.now(timezone.utc).isoformat(),
        }
