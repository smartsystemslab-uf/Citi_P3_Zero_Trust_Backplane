"""Permit Lease <-> PDP bridge of the zt-adk runtime (the PEP's PDP client).

For every Unified Authorization Request the bridge

1. obtains a challenge nonce from the PDP (``/v1/challenge``),
2. builds the signed PDP request with the deployment's issuer keys
   (``SignedRequestBuilder``): PEP request proof, risk / authentication / workflow
   assertions, the caller's authentication block, and -- when present -- the human
   approval and secondary authorization that an approver signed for this operation,
3. sends it to ``/v1/authorize`` (in-process ASGI app or a remote PDP service), and
4. verifies the signed decision (PDP decision key, native request hash) and that the
   decided operation is exactly the Permit Lease request before Permit Lease may issue a Permit Lease.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from zt_lease.context_binding import build_context_bindings
from zt_lease.errors import DecisionVerificationError
from zt_lease.models import PdpDecision, UnifiedAuthorizationRequest
from zt_lease.pdp_adapter import PdpDecisionEnvelope

from zt_pdp.decision_signing import verify_decision_headers
from zt_pdp.evidence_issuer import SignedRequestBuilder


def _header(headers: Mapping[str, str], name: str) -> str:
    lowered = {str(k).lower(): str(v) for k, v in headers.items()}
    return lowered.get(name.lower(), "")


def _parse_time(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class PdpBridge:
    def __init__(self, *, http_client: Any, builder: SignedRequestBuilder, decision_public_key: Path,
                 subject_runtime_ids: Mapping[str, str], resource_runtime_ids: Mapping[str, str]) -> None:
        self.http_client = http_client
        self.builder = builder
        self.public_key = Path(decision_public_key)
        self.subject_runtime_ids = dict(subject_runtime_ids)
        self.resource_runtime_ids = dict(resource_runtime_ids)
        self._pending: dict[str, Any] = {}

    def __call__(self, request: UnifiedAuthorizationRequest) -> PdpDecisionEnvelope:
        subject_runtime = self.subject_runtime_ids.get(request.subject)
        resource_runtime = self.resource_runtime_ids.get(request.resource)
        if not subject_runtime:
            raise ConnectionError(f"no runtime binding for subject {request.subject}")
        ctx = request.context
        challenge = self.http_client.post("/v1/challenge", json={
            "subject_canonical_id": request.subject, "subject_runtime_id": subject_runtime})
        if challenge.status_code >= 400:
            raise ConnectionError(f"PDP challenge failed: {challenge.status_code} {challenge.text[:200]}")
        native = self.builder.build(
            nonce=challenge.json()["nonce"],
            subject_canonical_id=request.subject,
            subject_runtime_id=subject_runtime,
            resource_canonical_id=request.resource,
            resource_runtime_id=resource_runtime,
            action=request.action,
            workflow_id=request.workflow_id or None,
            workflow_instance_id=str(ctx.get("workflow_instance_id") or "") or None,
            risk_score=int(ctx["risk_score"]),
            auth_factors=dict(ctx["auth_factors"]),
            parameters=request.parameters,
            identity_version=str(ctx.get("identity_version") or "identity-epoch-1"),
            authentication=ctx.get("authentication"),
            human_approval=ctx.get("human_approval_assertion"),
            secondary_authorization=ctx.get("secondary_authorization_assertion"),
            trace_id=str(ctx.get("trace_id") or "") or None,
        )
        extra = dict(native.context.__pydantic_extra__ or {})
        evidence: dict[str, Any] = {"identity": extra.get("auth_evidence", {}), "risk": extra.get("risk_evidence", {})}
        if extra.get("workflow_evidence"):
            evidence["workflow"] = extra["workflow_evidence"]
        if native.context.human_approval:
            evidence["human_approval"] = native.context.human_approval
        if extra.get("secondary_authorization"):
            evidence["secondary_authorization"] = extra["secondary_authorization"]
        request.evidence = evidence
        response = self.http_client.post("/v1/authorize", json=native.model_dump(mode="json"))
        if response.status_code >= 400:
            raise ConnectionError(f"PDP authorize failed: {response.status_code} {response.text[:200]}")
        self._pending[request.request_id] = native
        return PdpDecisionEnvelope(body=response.json(), headers=dict(response.headers))

    def verify(self, envelope: PdpDecisionEnvelope, decision: PdpDecision,
               request: UnifiedAuthorizationRequest) -> None:
        native = self._pending.pop(request.request_id, None)
        if native is None:
            raise DecisionVerificationError("no native PDP request for this decision")
        body = dict(envelope.body)
        if not verify_decision_headers(body, envelope.headers, self.public_key,
                                       expected_request_hash=native.request_hash):
            raise DecisionVerificationError("PDP decision signature verification failed")
        if body.get("request_id") != native.request_id or body.get("trace_id") != native.trace_id:
            raise DecisionVerificationError("PDP decision is not bound to its request / trace")
        for native_value, unified_value, name in (
                (native.subject.canonical_id, request.subject, "subject"),
                (native.resource.canonical_id, request.resource, "resource"),
                (native.action, request.action, "action"),
                (native.context.workflow_id or "", request.workflow_id or "", "workflow_id"),
                (native.parameters, request.parameters, "parameters")):
            if native_value != unified_value:
                raise DecisionVerificationError(f"PDP request and Permit Lease request differ in {name}")
        extra = dict(native.context.__pydantic_extra__ or {})
        identity_evidence = dict(extra.get("auth_evidence") or {})
        risk_evidence = dict(extra.get("risk_evidence") or {})
        proof = dict(native.subject.identity_evidence or {})
        # the PDP's own (signed) explanation, kept for the PEP's audit and denial messages
        decision.pdp_reason = str(body.get("reason") or "")
        decision.pdp_policy_id = str(body.get("policy_id") or "")
        decision.pdp_matched = list(body.get("matched_policy_ids") or [])
        decision.subject = request.subject
        decision.resource = request.resource
        decision.action = request.action
        decision.workflow_id = request.workflow_id
        decision.request_hash = request.request_hash()
        decision.identity_version = str(identity_evidence.get("identity_version") or "1")
        decision.risk_version = str(risk_evidence.get("risk_version") or "1")
        decision.nonce = str(proof.get("nonce") or "")
        decision.jti = str(proof.get("jti") or "")
        decision.decision_key_id = _header(envelope.headers, "X-ZT-Decision-Key-Id")
        decision.context_bindings = build_context_bindings(request.evidence)
        decided_at = _parse_time(body.get("decided_at"))
        if decided_at is not None:
            decision.issued_at = decided_at
        expirations = [_parse_time(identity_evidence.get("expires_at")), _parse_time(risk_evidence.get("expires_at"))]
        wf = dict(extra.get("workflow_evidence") or {})
        if wf:
            expirations.append(_parse_time(wf.get("expires_at")))
        expirations = [e for e in expirations if e is not None]
        if expirations:
            decision.expires_at = min(expirations)
