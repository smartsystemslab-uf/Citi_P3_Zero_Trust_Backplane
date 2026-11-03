"""Scheme B PEP-side authenticator: workload mTLS AND agent credential.

Order of checks (any failure -> AuthenticationError, never a fallback to A):
 1. TLS peer SVID (already chain-verified by OpenSSL; SVID profile + expiry
    checked by PeerIdentityCache).
 2. Non-agent service callers (the CLI ingress) are resolved through the same
    controlled service map as in A; they carry no agent credential.
 3. Agent certificate from X-ZT-Agent-Cert: chains to the Agent CA (separate
    trust root), inside validity, agent-cert profile. Verified certs are cached
    by fingerprint until their notAfter.
 4. Registry snapshot (pulled from the issuer every `interval_s`, fail-closed
    when older than `max_staleness_s`): agent enabled, serial not revoked, the
    TLS peer SPIFFE ID is a workload allowed to carry this agent.
 5. Signed claims: X-ZT-Agent-Id == cert agent, X-ZT-Workload-Id == TLS peer,
    X-ZT-Request-Id / X-ZT-Workflow-Run-Id == body, Host == this PEP.
 6. Content-Digest == SHA-256 of the actual body (RFC 9530).
 7. RFC 9421 signature with the certificate's key, keyid == cert fingerprint,
    required components/tag/alg/created/expires/nonce.
 8. (keyid, nonce) not seen before within the signature window.
"""
from __future__ import annotations

import asyncio
import base64
import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from cryptography import x509

from ..events import EventLog
from ..identity import AuthenticatedIdentity, AuthenticationError, VerifiedTransportIdentity
from ..workload_identity.service_map import IdentityMap
from . import certs
from .httpsig import (
    H_AGENT_CERT, H_AGENT_ID, H_CONTENT_DIGEST, H_REQUEST_ID, H_WORKFLOW_RUN_ID, H_WORKLOAD_ID,
    REQUIRED_COMPONENTS, SignatureRejected, check_content_digest, mcp_required_components,
    verify_request_signature,
)


class RegistrySnapshotCache:
    def __init__(
        self,
        fetch: Callable[[], Awaitable[dict[str, Any]]],
        *,
        interval_s: float = 2.0,
        max_staleness_s: float = 10.0,
        events: EventLog | None = None,
        on_identity_change: Callable[[str, str, str], None] | None = None,
    ) -> None:
        self.fetch = fetch
        self.interval_s = interval_s
        self.max_staleness_s = max_staleness_s
        self.events = events or EventLog(None)
        self.on_identity_change = on_identity_change
        self.snapshot: dict[str, Any] | None = None
        self.fetched_at = 0.0
        self.refreshes = 0
        self.refresh_failures = 0
        self.refresh_ms: list[float] = []

    def _apply(self, snap: dict[str, Any]) -> None:
        old = (self.snapshot or {}).get("agents", {})
        for aid, rec in snap["agents"].items():
            prev = old.get(aid)
            if prev is not None and (prev["identity_version"] != rec["identity_version"]
                                     or prev["enabled"] != rec["enabled"]):
                self.events.emit("agent_registry_change", agent_id=aid, enabled=rec["enabled"],
                                 identity_version=rec["identity_version"],
                                 registry_version=snap["registry_version"])
                if self.on_identity_change:
                    self.on_identity_change(aid, rec["identity_version"], "agent")
        self.snapshot = snap
        self.fetched_at = time.monotonic()

    async def refresh_once(self) -> None:
        t0 = time.perf_counter()
        snap = await self.fetch()
        self.refresh_ms.append((time.perf_counter() - t0) * 1000)
        self._apply(snap)
        self.refreshes += 1

    async def run(self) -> None:
        while True:
            try:
                await self.refresh_once()
            except Exception as exc:
                self.refresh_failures += 1
                self.events.emit("agent_registry_refresh_failed", error=str(exc)[:200])
            await asyncio.sleep(self.interval_s)

    def current(self) -> dict[str, Any]:
        if self.snapshot is None:
            raise AuthenticationError("agent_registry_unavailable")
        if time.monotonic() - self.fetched_at > self.max_staleness_s:
            raise AuthenticationError("agent_registry_stale")
        return self.snapshot


class ReplayGuard:
    def __init__(self) -> None:
        self._seen: dict[tuple[str, str], float] = {}
        self._inserts = 0

    def check_and_add(self, key: tuple[str, str], expires_epoch: float) -> None:
        now = time.time()
        if key in self._seen and self._seen[key] > now:
            raise AuthenticationError("signature_replayed")
        self._seen[key] = expires_epoch + 5
        self._inserts += 1
        if self._inserts % 4096 == 0:
            self._seen = {k: v for k, v in self._seen.items() if v > now}


class AgentCredentialAuthenticator:
    mode = "B"

    def __init__(
        self,
        *,
        ca_cert: x509.Certificate,
        registry: RegistrySnapshotCache,
        service_map: IdentityMap,
        authority: str,
    ) -> None:
        self.ca_cert = ca_cert
        self.registry = registry
        self.service_map = service_map
        self.authority = authority
        self._cert_cache: dict[str, certs.VerifiedAgentCert] = {}
        self.replay = ReplayGuard()
        self.cert_cache_hits = 0
        self.cert_cache_misses = 0

    def _verified_cert(self, cert_der: bytes) -> certs.VerifiedAgentCert:
        fp = certs.fingerprint(cert_der)
        now = datetime.now(timezone.utc)
        vc = self._cert_cache.get(fp)
        if vc is not None and vc.not_after > now:
            self.cert_cache_hits += 1
            return vc
        self.cert_cache_misses += 1
        try:
            vc = certs.verify_agent_cert(cert_der, self.ca_cert, now=now)
        except certs.AgentCertError as exc:
            raise AuthenticationError(exc.code) from exc
        if len(self._cert_cache) > 10000:
            self._cert_cache = {k: v for k, v in self._cert_cache.items() if v.not_after > now}
        self._cert_cache[fp] = vc
        return vc

    def authenticate(self, request: Any, verified_transport_identity: VerifiedTransportIdentity | None,
                     *, body_json: dict[str, Any]) -> AuthenticatedIdentity:
        """HTTP JSON profile (gateway ingress and agent routes): correlation ids come from
        the signed JSON body."""
        return self._authenticate(
            request, verified_transport_identity,
            expected={H_REQUEST_ID: str(body_json.get("request_id", "")),
                      H_WORKFLOW_RUN_ID: str(body_json.get("workflow_run_id", ""))},
            required=REQUIRED_COMPONENTS, require_body=True)

    def authenticate_mcp(self, request: Any, verified_transport_identity: VerifiedTransportIdentity | None,
                         *, is_tools_call: bool, meta_request_id: str | None,
                         meta_workflow_run_id: str | None) -> AuthenticatedIdentity:
        """MCP Streamable HTTP profile (see httpsig.mcp_required_components).

        tools/call: X-ZT-Request-Id / X-ZT-Workflow-Run-Id must equal the
        `_meta` correlation ids inside the signed JSON-RPC body.
        Control messages (initialize, notifications, tools/list, DELETE, GET):
        a fresh X-ZT-Request-Id is required and covered; a workflow binding must
        not be present (none is invented for control traffic).
        """
        h = request.headers
        if is_tools_call:
            if not meta_request_id or not meta_workflow_run_id:
                raise AuthenticationError("tools_call_missing_correlation_meta")
            expected: dict[str, str | None] = {H_REQUEST_ID: meta_request_id, H_WORKFLOW_RUN_ID: meta_workflow_run_id}
        else:
            if h.get(H_WORKFLOW_RUN_ID):
                raise AuthenticationError("unexpected_workflow_binding_on_control_message")
            expected = {H_REQUEST_ID: None}
        names = {k.lower() for k in h.keys()}
        required = mcp_required_components(has_body=bool(request.body), is_tools_call=is_tools_call,
                                           header_names=names)
        return self._authenticate(request, verified_transport_identity, expected=expected,
                                  required=required, require_body=bool(request.body))

    def _authenticate(self, request: Any, verified_transport_identity: VerifiedTransportIdentity | None,
                      *, expected: dict[str, str | None], required: tuple[str, ...],
                      require_body: bool) -> AuthenticatedIdentity:
        t = verified_transport_identity
        if t is None:
            raise AuthenticationError("transport_not_authenticated")

        service = self.service_map.lookup(t.spiffe_id)
        if service is not None and service.kind == "service":
            if not service.enabled:
                raise AuthenticationError("identity_disabled", service.agent_id)
            return AuthenticatedIdentity(
                auth_mode="B", subject_kind="service", workload_spiffe_id=t.spiffe_id,
                agent_id=service.agent_id, agent_credential_id=None,
                authentication_method="mtls-x509svid(service-caller,no-agent-credential)",
                identity_version=service.identity_version, credential_expiry=t.not_after,
                details={"svid_serial": t.cert_serial},
            )

        h = request.headers
        raw_cert = h.get(H_AGENT_CERT)
        if not raw_cert:
            raise AuthenticationError("missing_agent_credential")
        try:
            cert_der = base64.b64decode(raw_cert, validate=True)
        except Exception as exc:
            raise AuthenticationError("agent_cert_encoding") from exc
        vc = self._verified_cert(cert_der)

        snap = self.registry.current()
        rec = snap["agents"].get(vc.agent_id)
        if rec is None:
            raise AuthenticationError("agent_not_registered", vc.agent_id)
        if not rec["enabled"]:
            raise AuthenticationError("agent_disabled", vc.agent_id)
        if vc.serial in rec["revoked_serials"]:
            raise AuthenticationError("agent_cert_revoked", vc.serial)
        if t.spiffe_id not in rec["allowed_workloads"]:
            raise AuthenticationError("workload_not_bound_to_agent", t.spiffe_id)

        if h.get(H_AGENT_ID) != vc.agent_id:
            raise AuthenticationError("claimed_agent_mismatch")
        if h.get(H_WORKLOAD_ID) != t.spiffe_id:
            raise AuthenticationError("signed_workload_binding_mismatch")
        for header, value in expected.items():
            got = h.get(header)
            if not got or (value is not None and got != value):
                raise AuthenticationError(f"{header.removeprefix('x-zt-').replace('-', '_')}_binding_mismatch")
        if h.get("Host") != self.authority:
            raise AuthenticationError("authority_mismatch", str(h.get("Host")))
        try:
            if require_body:
                check_content_digest(h.get(H_CONTENT_DIGEST), request.body)
            elif h.get(H_CONTENT_DIGEST):
                check_content_digest(h.get(H_CONTENT_DIGEST), request.body)
            sig = verify_request_signature(
                method=request.method,
                url=f"https://{self.authority}{request.path_qs}",
                headers=h,
                public_key=vc.public_key,
                key_id=vc.fingerprint,
                required=required,
            )
        except SignatureRejected as exc:
            raise AuthenticationError(exc.code) from exc
        self.replay.check_and_add((vc.fingerprint, sig.nonce), float(sig.expires))

        return AuthenticatedIdentity(
            auth_mode="B",
            subject_kind="agent",
            workload_spiffe_id=t.spiffe_id,
            agent_id=vc.agent_id,
            agent_credential_id=vc.serial,
            authentication_method="mtls-x509svid+rfc9421(ecdsa-p256-sha256)+agent-x509",
            identity_version=rec["identity_version"],
            credential_expiry=min(vc.not_after, t.not_after),
            details={"svid_serial": t.cert_serial, "agent_key_id": vc.fingerprint,
                     "registry_version": snap["registry_version"]},
        )
