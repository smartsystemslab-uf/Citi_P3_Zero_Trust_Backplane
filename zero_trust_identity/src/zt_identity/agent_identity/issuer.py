"""Agent Identity Issuer + registry (scheme B).

Trust root: a dedicated Agent CA whose key exists only in this container
(separate from the SPIRE workload CA).

Enrollment (first credential):
  1. workload -> POST /v1/agent-credentials/challenge {agent_id}   over mTLS (SVID)
  2. workload -> POST /v1/agent-credentials/enroll {agent_id, csr} over mTLS
     issuer checks: peer SPIFFE ID is registered for agent_id, agent enabled,
     nonce fresh/single-use/bound to (agent_id, peer), CSR self-signature
     (proof of possession), CSR key == pre-registered enrollment key.
Renewal (rotation to a NEW key):
  challenge, then POST /renew {agent_id, csr(new key), current_cert, proof}
  proof = signature by the CURRENT agent key over (csr, nonce); current cert
  must chain to the Agent CA, be unexpired, unrevoked and name the same agent.
Registry snapshot for PEPs: GET /v1/registry/snapshot (gateway SPIFFE ID only).
Admin (disable/enable) is exposed only on a unix socket inside this container.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..events import EventLog
from ..identity import AuthenticationError
from ..workload_identity.spiffe_tls import WorkloadIdentity
from ..workload_identity.svid import PeerIdentityCache
from . import certs


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Challenge:
    agent_id: str
    peer: str
    expires: float


class IssuerState:
    """Registry + issuance state, persisted as JSON on the issuer's own volume."""

    def __init__(self, registry_file: Path, state_file: Path) -> None:
        self.state_file = state_file
        self.lock = threading.RLock()
        if state_file.exists():
            self.data = json.loads(state_file.read_text(encoding="utf-8"))
        else:
            reg = json.loads(registry_file.read_text(encoding="utf-8"))
            self.data = {
                "registry_version": 1,
                "agents": {
                    aid: {
                        "allowed_workloads": rec["allowed_workloads"],
                        "enrollment_public_key_pem": rec["enrollment_public_key_pem"],
                        "enabled": bool(rec.get("enabled", True)),
                        "identity_version": int(rec.get("identity_version", 1)),
                        "issued": {},        # serial -> {fingerprint, not_after, issued_at, kind}
                        "revoked_serials": [],
                    }
                    for aid, rec in reg["agents"].items()
                },
            }
            self.save()

    def save(self) -> None:
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=1, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.state_file)

    def agent(self, agent_id: str) -> dict[str, Any]:
        rec = self.data["agents"].get(agent_id)
        if rec is None:
            raise AuthenticationError("unknown_agent", agent_id)
        return rec

    def bump(self) -> None:
        self.data["registry_version"] += 1

    def snapshot(self, ca_fp: str) -> dict[str, Any]:
        with self.lock:
            return {
                "registry_version": self.data["registry_version"],
                "generated_at": utcnow().isoformat(),
                "ca_fingerprint": ca_fp,
                "agents": {
                    aid: {
                        "enabled": rec["enabled"],
                        "identity_version": f"agent-idv-{rec['identity_version']}",
                        "allowed_workloads": list(rec["allowed_workloads"]),
                        "revoked_serials": list(rec["revoked_serials"]),
                    }
                    for aid, rec in self.data["agents"].items()
                },
            }


class AgentIssuer:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.events = EventLog(args.events, component="agent-issuer")
        self.ca_key = serialization.load_pem_private_key(Path(args.ca_key).read_bytes(), password=None)
        self.ca_cert = x509.load_pem_x509_certificate(Path(args.ca_cert).read_bytes())
        self.ca_fp = certs.fingerprint(self.ca_cert.public_bytes(serialization.Encoding.DER))
        self.state = IssuerState(Path(args.registry), Path(args.state))
        self.ttl = int(args.cert_ttl_seconds)
        self.challenges: dict[str, Challenge] = {}
        self.gateway_ids = set(args.gateway_spiffe_id)
        self.peer_cache = PeerIdentityCache(args.trust_domain)
        self.counters = {"enroll": 0, "renew": 0, "challenge": 0, "snapshot": 0, "rejected": 0}
        self.issue_ms: list[float] = []

    # ------------------------------------------------------------------
    def _peer(self, request: web.Request) -> str:
        ssl_obj = request.transport.get_extra_info("ssl_object") if request.transport else None
        return self.peer_cache.identity_for(ssl_obj).spiffe_id

    def _reject(self, code: str, status: int = 403) -> web.Response:
        self.counters["rejected"] += 1
        self.events.emit("issuer_reject", code=code)
        return web.json_response({"error": code}, status=status)

    async def challenge(self, request: web.Request) -> web.Response:
        try:
            peer = self._peer(request)
            body = await request.json()
            agent_id = str(body["agent_id"])
            rec = self.state.agent(agent_id)
            if peer not in rec["allowed_workloads"]:
                return self._reject("workload_not_registered_for_agent")
            if not rec["enabled"]:
                return self._reject("agent_disabled")
        except AuthenticationError as exc:
            return self._reject(exc.code)
        now = time.monotonic()
        self.challenges = {k: v for k, v in self.challenges.items() if v.expires > now}
        nonce = secrets.token_urlsafe(24)
        self.challenges[nonce] = Challenge(agent_id=agent_id, peer=peer, expires=now + 60)
        self.counters["challenge"] += 1
        return web.json_response({"nonce": nonce, "expires_in": 60})

    def _consume_nonce(self, nonce: str, agent_id: str, peer: str) -> None:
        ch = self.challenges.pop(nonce, None)
        if ch is None or ch.expires < time.monotonic():
            raise AuthenticationError("nonce_invalid_or_used")
        if ch.agent_id != agent_id or ch.peer != peer:
            raise AuthenticationError("nonce_binding_mismatch")

    def _issue(self, agent_id: str, public_key, kind: str) -> dict[str, Any]:
        t0 = time.perf_counter()
        cert = certs.issue_agent_cert(self.ca_key, self.ca_cert, public_key, agent_id, self.ttl)
        der = cert.public_bytes(serialization.Encoding.DER)
        serial = format(cert.serial_number, "x")
        with self.state.lock:
            rec = self.state.agent(agent_id)
            # keep only unexpired issuance records
            now_iso = utcnow().isoformat()
            rec["issued"] = {s: v for s, v in rec["issued"].items() if v["not_after"] > now_iso}
            rec["issued"][serial] = {
                "fingerprint": certs.fingerprint(der),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "issued_at": now_iso,
                "kind": kind,
            }
            self.state.save()
        self.issue_ms.append((time.perf_counter() - t0) * 1000)
        self.counters[kind] += 1
        self.events.emit("agent_cert_issued", agent_id=agent_id, kind=kind, serial=serial,
                         not_after=cert.not_valid_after_utc.isoformat(), fingerprint=certs.fingerprint(der))
        return {
            "certificate": base64.b64encode(der).decode("ascii"),
            "ca_certificate": base64.b64encode(self.ca_cert.public_bytes(serialization.Encoding.DER)).decode("ascii"),
            "serial": serial,
            "not_after": cert.not_valid_after_utc.isoformat(),
        }

    async def enroll(self, request: web.Request) -> web.Response:
        try:
            peer = self._peer(request)
            body = await request.json()
            agent_id = str(body["agent_id"])
            csr_der = base64.b64decode(body["csr"])
            rec = self.state.agent(agent_id)
            if peer not in rec["allowed_workloads"]:
                return self._reject("workload_not_registered_for_agent")
            if not rec["enabled"]:
                return self._reject("agent_disabled")
            csr = x509.load_der_x509_csr(csr_der)
            if not csr.is_signature_valid:
                return self._reject("csr_signature_invalid")          # proof of possession
            self._consume_nonce(certs.csr_nonce(csr), agent_id, peer)
            registered = serialization.load_pem_public_key(rec["enrollment_public_key_pem"].encode())
            if certs.spki_der(csr.public_key()) != certs.spki_der(registered):
                return self._reject("csr_key_not_registered_enrollment_key")
        except (AuthenticationError, certs.AgentCertError) as exc:
            return self._reject(exc.code)
        except (KeyError, ValueError) as exc:
            return self._reject(f"bad_request:{type(exc).__name__}", 400)
        return web.json_response(self._issue(agent_id, csr.public_key(), "enroll"))

    async def renew(self, request: web.Request) -> web.Response:
        try:
            peer = self._peer(request)
            body = await request.json()
            agent_id = str(body["agent_id"])
            csr_der = base64.b64decode(body["csr"])
            current_der = base64.b64decode(body["current_certificate"])
            rec = self.state.agent(agent_id)
            if peer not in rec["allowed_workloads"]:
                return self._reject("workload_not_registered_for_agent")
            if not rec["enabled"]:
                return self._reject("agent_disabled")
            current = certs.verify_agent_cert(current_der, self.ca_cert)
            if current.agent_id != agent_id:
                return self._reject("current_cert_agent_mismatch")
            if current.serial in rec["revoked_serials"]:
                return self._reject("current_cert_revoked")
            csr = x509.load_der_x509_csr(csr_der)
            if not csr.is_signature_valid:
                return self._reject("csr_signature_invalid")
            nonce = certs.csr_nonce(csr)
            self._consume_nonce(nonce, agent_id, peer)
            certs.verify_renew_proof(x509.load_der_x509_certificate(current_der), csr_der, nonce, body["proof"])
        except (AuthenticationError, certs.AgentCertError) as exc:
            return self._reject(exc.code)
        except (KeyError, ValueError) as exc:
            return self._reject(f"bad_request:{type(exc).__name__}", 400)
        return web.json_response(self._issue(agent_id, csr.public_key(), "renew"))

    async def snapshot(self, request: web.Request) -> web.Response:
        try:
            peer = self._peer(request)
        except AuthenticationError as exc:
            return self._reject(exc.code)
        if peer not in self.gateway_ids:
            return self._reject("snapshot_caller_not_pep")
        self.counters["snapshot"] += 1
        return web.json_response(self.state.snapshot(self.ca_fp))

    async def health(self, request: web.Request) -> web.Response:
        return web.json_response({"status": "ok", "counters": self.counters,
                                  "registry_version": self.state.data["registry_version"]})

    # ---------------- admin (unix socket only) -------------------------
    async def admin(self, request: web.Request) -> web.Response:
        action = request.match_info["action"]
        agent_id = request.match_info["agent_id"]
        with self.state.lock:
            try:
                rec = self.state.agent(agent_id)
            except AuthenticationError:
                return web.json_response({"error": "unknown_agent"}, status=404)
            if action == "disable":
                rec["enabled"] = False
                rec["revoked_serials"] = sorted(set(rec["revoked_serials"]) | set(rec["issued"]))
            elif action == "enable":
                rec["enabled"] = True
            else:
                return web.json_response({"error": "unknown_action"}, status=400)
            rec["identity_version"] += 1
            self.state.bump()
            self.state.save()
            out = {"agent_id": agent_id, "enabled": rec["enabled"],
                   "identity_version": rec["identity_version"],
                   "registry_version": self.state.data["registry_version"],
                   "revoked_serials": rec["revoked_serials"]}
        self.events.emit("admin_" + action, **out)
        return web.json_response(out)

    async def stats(self, request: web.Request) -> web.Response:
        return web.json_response({"counters": self.counters, "issue_ms": self.issue_ms})


async def main_async(args: argparse.Namespace) -> None:
    issuer = AgentIssuer(args)
    wid = WorkloadIdentity(trust_domain=args.trust_domain, events=issuer.events)
    wid.bind_loop(asyncio.get_running_loop())
    app = web.Application()
    app.router.add_post("/v1/agent-credentials/challenge", issuer.challenge)
    app.router.add_post("/v1/agent-credentials/enroll", issuer.enroll)
    app.router.add_post("/v1/agent-credentials/renew", issuer.renew)
    app.router.add_get("/v1/registry/snapshot", issuer.snapshot)
    app.router.add_get("/health", issuer.health)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", args.port, ssl_context=wid.server_context()).start()

    admin_app = web.Application()
    admin_app.router.add_post("/admin/agents/{agent_id}/{action}", issuer.admin)
    admin_app.router.add_get("/admin/stats", issuer.stats)
    admin_runner = web.AppRunner(admin_app, access_log=None)
    await admin_runner.setup()
    admin_dir = Path(args.admin_socket).parent
    admin_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(admin_dir, 0o700)
    Path(args.admin_socket).unlink(missing_ok=True)
    await web.UnixSite(admin_runner, args.admin_socket).start()
    os.chmod(args.admin_socket, 0o600)
    issuer.events.emit("issuer_ready", spiffe_id=wid.spiffe_id, ttl=issuer.ttl, ca_fingerprint=issuer.ca_fp)
    await asyncio.Event().wait()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trust-domain", default=os.environ.get("CITI_TRUST_DOMAIN", "citi-p3.test"))
    ap.add_argument("--port", type=int, default=8444)
    ap.add_argument("--ca-key", default="/run/secrets/agent-ca/ca.key")
    ap.add_argument("--ca-cert", default="/etc/citi/agent-ca/ca.pem")
    ap.add_argument("--registry", default="/etc/citi/config/agent_registry.json")
    ap.add_argument("--state", default="/var/lib/agent-issuer/state.json")
    ap.add_argument("--cert-ttl-seconds", default=os.environ.get("AGENT_CERT_TTL_SECONDS", "86400"))
    ap.add_argument("--gateway-spiffe-id", action="append",
                    default=[os.environ.get("GATEWAY_SPIFFE_ID", "spiffe://citi-p3.test/ztbp/svc/zt-gateway")])
    ap.add_argument("--admin-socket", default="/var/lib/agent-issuer/admin/admin.sock")
    ap.add_argument("--events", default=os.environ.get("CITI_EVENTS_FILE"))
    asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__":
    main()
