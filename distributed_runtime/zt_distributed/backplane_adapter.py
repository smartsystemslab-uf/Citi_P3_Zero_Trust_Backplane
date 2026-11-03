"""Identity-bound adapter over the Backplane's NativeMasBackplane (native_mas_runtime).

Bootstrap (Task 2 scan -> reconcile -> Task 3 placement -> signed PSL policy store ->
Task 4 PDP -> Task 5 Permit Lease), placement lookup, authorize / begin_tool /
finish_tool, the workflow_run PSL monitor and audit are the native engine's own code.
The adapter changes exactly:

1. ``_request_for``: the PDP request can only be built while a verified
   AuthenticatedIdentity is bound (fail closed); the verified authentication factors
   and identity version replace the in-process runtime's fixed factor claim; approval
   context comes from the workflow run (asserted by the authenticated ingress service)
   instead of process-wide flags.
2. The IdP-style authentication assertion carries the SPIFFE scheme B result
   (``authentication`` block: scheme, method, workload SPIFFE ID, agent, credential),
   signed as before -- the PDP re-checks it (policy_store/identity.psl).
3. Identity-version changes (agent registry) are pushed into the Task 5
   RevocationService, invalidating outstanding Permit Leases.
4. Trusted outcome flags of the permit issuer / validator for the gateway's PSL
   monitor, and timing spans around PDP call, decision verification, lease issue and
   validation.
"""
from __future__ import annotations

import contextvars
import os
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from zt_identity.identity import AuthenticatedIdentity

BACKPLANE_ROOT = Path(os.environ.get("CITI_BACKPLANE_ROOT", Path(__file__).resolve().parents[2]))
if str(BACKPLANE_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKPLANE_ROOT))

from native_mas_runtime import NativeMasBackplane  # noqa: E402


@dataclass
class RunContext:
    workflow_run_id: str
    trace_id: str
    session_id: str = ""
    user_role: str = ""                  # verified against the ingress service's allowed roles
    human_approval: bool = False
    secondary_authorization: bool = False
    change_ticket: str | None = None


@dataclass
class AuthContext:
    identity: AuthenticatedIdentity
    run: RunContext | None
    spans: dict[str, float] = field(default_factory=dict)
    # trusted outcome flags of the permit issuer / validator for this call (PSL events)
    flags: dict[str, bool] = field(default_factory=dict)


AUTH_CONTEXT: contextvars.ContextVar[AuthContext | None] = contextvars.ContextVar("zt_auth_context", default=None)


@contextmanager
def bound_identity(identity: AuthenticatedIdentity, run: RunContext | None,
                   spans: dict[str, float]) -> Iterator[AuthContext]:
    ctx = AuthContext(identity=identity, run=run, spans=spans)
    token = AUTH_CONTEXT.set(ctx)
    try:
        yield ctx
    finally:
        AUTH_CONTEXT.reset(token)


def _add_span(name: str, started_ns: int) -> None:
    ctx = AUTH_CONTEXT.get()
    if ctx is not None:
        ctx.spans[name] = ctx.spans.get(name, 0.0) + (time.perf_counter_ns() - started_ns) / 1e6


class IdentityAwareBackplane(NativeMasBackplane):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._instrument()
        self._install_authenticated_evidence()
        self.identity_changes: list[dict[str, Any]] = []

    # 1. identity-bound requests -------------------------------------------
    def _request_for(self, placement: dict[str, Any], **kwargs: Any):
        ctx = AUTH_CONTEXT.get()
        if ctx is None:
            raise RuntimeError("fail-closed: PDP request built without an authenticated identity")
        request = super()._request_for(placement, **kwargs)
        c = request.context
        for k in ("with_human_approval", "with_secondary_authorization", "change_ticket"):
            c.pop(k, None)
        c["auth_factors"] = ctx.identity.auth_factors()
        c["identity_version"] = ctx.identity.identity_version
        c["authenticated_identity"] = ctx.identity.as_audit()
        if ctx.run is not None:
            if ctx.run.human_approval:
                c["with_human_approval"] = True
            if ctx.run.secondary_authorization:
                c["with_secondary_authorization"] = True
            if ctx.run.change_ticket:
                c["change_ticket"] = ctx.run.change_ticket
        return request

    # 2. authenticated evidence -------------------------------------------
    def _install_authenticated_evidence(self) -> None:
        from zt_backplane.canonical import request_proof_payload
        from zt_backplane.crypto import load_private_key, sign_mapping

        base_builder = self.bridge._build_signed_request
        idp_key = load_private_key(self.task4_root / "security" / "dev_keys" / "idp_private.pem")
        pep_key = self.bridge._dev_pep_private_key

        def build(**kwargs: Any):
            ctx = AUTH_CONTEXT.get()
            if ctx is None:
                raise RuntimeError("fail-closed: no authenticated identity for PDP evidence")
            native = base_builder(**kwargs)
            extra = native.context.__pydantic_extra__
            auth = {k: v for k, v in dict(extra["auth_evidence"]).items() if k != "signature"}
            ident = ctx.identity
            auth["identity_version"] = ident.identity_version
            auth["authentication"] = {
                "auth_mode": ident.auth_mode,
                "subject_kind": ident.subject_kind,
                "method": ident.authentication_method,
                "workload_spiffe_id": ident.workload_spiffe_id,
                "agent_id": ident.agent_id,
                "agent_credential_id": ident.agent_credential_id,
                "credential_expiry": ident.credential_expiry.isoformat() if ident.credential_expiry else None,
            }
            auth["signature"] = sign_mapping(idp_key, auth)
            extra["auth_evidence"] = auth
            proof = dict(native.subject.identity_evidence or {})
            proof["signature"] = sign_mapping(pep_key, request_proof_payload(native))
            native.subject.identity_evidence = proof
            return native

        self.bridge._build_signed_request = build

    # 3. identity lifecycle -> permit revocation ---------------------------
    def canonical_subject(self, runtime_id: str) -> str | None:
        for canonical, rid in self.bridge.subject_runtime_ids.items():
            if rid == runtime_id:
                return canonical
        return None

    def on_identity_change(self, runtime_id: str, identity_version: str, kind: str = "agent") -> None:
        canonical = self.canonical_subject(runtime_id)
        if canonical is None:
            return
        epoch = self.components.revocations.set_identity_version(canonical, identity_version)
        self.identity_changes.append({"runtime_id": runtime_id, "canonical": canonical,
                                      "identity_version": identity_version, "revocation_epoch": epoch,
                                      "at": time.time()})

    # 4. trusted flags + spans ---------------------------------------------
    def _instrument(self) -> None:
        bridge_cls = type(self.bridge)

        class TimedBridge(bridge_cls):  # type: ignore[misc, valid-type]
            def __call__(self, request):  # PDP round trip incl. challenge + evidence
                t = time.perf_counter_ns()
                try:
                    return super().__call__(request)
                finally:
                    _add_span("pdp_ms", t)

            def verify(self, envelope, decision, request):  # signed decision verification
                t = time.perf_counter_ns()
                try:
                    return super().verify(envelope, decision, request)
                finally:
                    _add_span("pdp_verify_ms", t)

        self.bridge.__class__ = TimedBridge
        issuer, validator = self.components.issuer, self.components.validator
        orig_issue, orig_validate = issuer.issue, validator.validate

        def issue(*a: Any, **k: Any):
            t = time.perf_counter_ns()
            ctx = AUTH_CONTEXT.get()
            if ctx is not None:
                ctx.flags["issue_called"] = True        # only reached after an allowing PDP decision
            try:
                return orig_issue(*a, **k)
            finally:
                _add_span("permit_issue_ms", t)

        def validate(*a: Any, **k: Any):
            t = time.perf_counter_ns()
            ctx = AUTH_CONTEXT.get()
            try:
                out = orig_validate(*a, **k)
                if ctx is not None:
                    ctx.flags["validate_ok"] = True     # validator returned (no exception)
                return out
            except Exception:
                if ctx is not None:
                    ctx.flags["validate_error"] = True
                raise
            finally:
                _add_span("permit_validate_ms", t)

        issuer.issue = issue          # type: ignore[method-assign]
        validator.validate = validate  # type: ignore[method-assign]
