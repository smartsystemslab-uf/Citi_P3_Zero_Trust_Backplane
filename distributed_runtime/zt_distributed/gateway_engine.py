"""The zt-adk ProtectionEngine as the distributed gateway's PDP client (runtime "gateway").

Differences from the in-process plugin's engine:

1. Every PDP request is built while the authenticated identity of THAT request is bound
   (``bound_identity``): SPIFFE scheme B factors (workload SVID verified over mTLS, agent
   certificate + RFC 9421 signature) and the authentication block go into the IdP-signed
   assertion the PDP re-checks (identity rules of the policy store). Without a bound identity
   no request is built (fail closed).
2. Identity-version changes of the agent registry (admin disable / enable, re-enrolment) are
   pushed into the Task 5 RevocationService: outstanding Permit Leases of that agent die.
3. Trusted outcome flags of the Permit Lease issuer / validator are recorded per request for
   the gateway's PSL monitors (``psl_guard``), with timing spans of the PDP round trip.
"""
from __future__ import annotations

import contextvars
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator

from zt_adk.engine import REQUEST_AUTH, ProtectionEngine, RequestAuth
from zt_identity.identity import AuthenticatedIdentity


@dataclass
class AuthContext:
    identity: AuthenticatedIdentity
    spans: dict[str, float] = field(default_factory=dict)
    flags: dict[str, bool] = field(default_factory=dict)


AUTH_CONTEXT: contextvars.ContextVar[AuthContext | None] = contextvars.ContextVar("zt_gw_auth", default=None)


def _authentication(ident: AuthenticatedIdentity) -> dict[str, Any]:
    return {
        "auth_mode": ident.auth_mode,
        "subject_kind": ident.subject_kind,
        "method": ident.authentication_method,
        "workload_spiffe_id": ident.workload_spiffe_id,
        "agent_id": ident.agent_id,
        "agent_credential_id": ident.agent_credential_id,
        "credential_expiry": ident.credential_expiry.isoformat() if ident.credential_expiry else None,
    }


@contextmanager
def bound_identity(ident: AuthenticatedIdentity, spans: dict[str, float], *, user_session: bool,
                   subject_identity_version: str | None = None) -> Iterator[AuthContext]:
    """Bind the verified identity of the current request for the engine calls inside.

    ``subject_identity_version``: when the gateway decides about an agent that is not the
    authenticated caller (output of an agent relayed to the ingress), the decision is bound to
    that agent's current registry identity version -- Permit Leases of an agent are revoked
    with its identity version, whoever asked."""
    ctx = AuthContext(identity=ident, spans=spans)
    factors = {k: bool(v) for k, v in ident.auth_factors().items()}
    factors["user_session"] = bool(user_session)
    t1 = AUTH_CONTEXT.set(ctx)
    t2 = REQUEST_AUTH.set(RequestAuth(factors=factors, authentication=_authentication(ident),
                                      identity_version=str(subject_identity_version or ident.identity_version or "1")))
    try:
        yield ctx
    finally:
        REQUEST_AUTH.reset(t2)
        AUTH_CONTEXT.reset(t1)


def _span(name: str, started_ns: int) -> None:
    ctx = AUTH_CONTEXT.get()
    if ctx is not None:
        ctx.spans[name] = ctx.spans.get(name, 0.0) + (time.perf_counter_ns() - started_ns) / 1e6


class GatewayEngine(ProtectionEngine):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(runtime="gateway", **kwargs)
        self.identity_changes: list[dict[str, Any]] = []
        self._instrument()

    def _request(self, run: Any, placement: dict[str, Any], **kwargs: Any) -> Any:
        if REQUEST_AUTH.get() is None:
            raise RuntimeError("fail-closed: PDP request built without an authenticated identity")
        return super()._request(run, placement, **kwargs)

    # identity lifecycle -> permit revocation ----------------------------------------------
    def canonical_subject(self, runtime_id: str) -> str | None:
        for canonical, rid in self.bridge.subject_runtime_ids.items():
            if rid == runtime_id:
                return canonical
        return None

    def on_identity_change(self, runtime_id: str, identity_version: str, kind: str = "agent") -> None:
        canonical = self.canonical_subject(runtime_id)
        if canonical is None:
            return
        epoch = self.components.revocations.set_identity_version(canonical, str(identity_version))
        rec = {"runtime_id": runtime_id, "canonical": canonical, "identity_version": str(identity_version),
               "revocation_epoch": epoch, "at": time.time()}
        self.identity_changes.append(rec)
        self.audit.write("IDENTITY_VERSION_CHANGED", durable=True, **rec)

    # trusted flags + spans ----------------------------------------------------------------
    def _instrument(self) -> None:
        bridge_cls = type(self.bridge)

        class TimedBridge(bridge_cls):  # type: ignore[misc, valid-type]
            def __call__(self, request):
                t = time.perf_counter_ns()
                try:
                    return super().__call__(request)
                finally:
                    _span("pdp_ms", t)

            def verify(self, envelope, decision, request):
                t = time.perf_counter_ns()
                try:
                    return super().verify(envelope, decision, request)
                finally:
                    _span("pdp_verify_ms", t)

        self.bridge.__class__ = TimedBridge
        issuer, validator = self.components.issuer, self.components.validator
        orig_issue, orig_validate = issuer.issue, validator.validate

        def issue(*a: Any, **k: Any):
            t = time.perf_counter_ns()
            ctx = AUTH_CONTEXT.get()
            if ctx is not None:
                ctx.flags["issue_called"] = True        # reached only after an allowing PDP decision
            try:
                return orig_issue(*a, **k)
            finally:
                _span("permit_issue_ms", t)

        def validate(*a: Any, **k: Any):
            t = time.perf_counter_ns()
            ctx = AUTH_CONTEXT.get()
            try:
                out = orig_validate(*a, **k)
                if ctx is not None:
                    ctx.flags["validate_ok"] = True
                return out
            except Exception:
                if ctx is not None:
                    ctx.flags["validate_error"] = True
                raise
            finally:
                _span("permit_validate_ms", t)

        issuer.issue = issue            # type: ignore[method-assign]
        validator.validate = validate   # type: ignore[method-assign]
