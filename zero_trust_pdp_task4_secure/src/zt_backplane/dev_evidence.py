"""Development-only signed evidence builder.

The private keys shipped under security/dev_keys exist only so the prototype can
run locally. Replace every issuer and key with Citi-managed identity, risk,
workflow, approval, and key-management services before integration.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from .canonical import compute_request_hash, request_proof_payload
from .crypto import load_private_key, sign_mapping
from .evidence import SecurityConfig
from .models import PDPRequest


ROOT = Path(__file__).resolve().parents[2]


def build_signed_request(
    *,
    nonce: str,
    subject_canonical_id: str,
    subject_runtime_id: str,
    resource_canonical_id: str,
    resource_runtime_id: str | None,
    action: str,
    workflow_id: str | None,
    workflow_instance_id: str | None,
    risk_score: int,
    auth_factors: dict[str, bool],
    parameters: dict[str, Any] | None = None,
    environment: str = "prototype",
    with_human_approval: bool = False,
    with_secondary_authorization: bool = False,
    now: datetime | None = None,
) -> PDPRequest:
    now = now or datetime.now(timezone.utc)
    expires = now + timedelta(seconds=60)
    config = SecurityConfig(ROOT / "config" / "security_context.yaml")
    risk_level = config.classify_risk(risk_score).value
    auth_strength = config.calculate_auth_strength(auth_factors)

    request = PDPRequest(
        schema_version="1.0",
        request_id=f"req-{uuid4()}",
        trace_id=f"trace-{uuid4()}",
        subject={
            "canonical_id": subject_canonical_id,
            "runtime_id": subject_runtime_id,
            "identity_evidence": {},
        },
        resource={"canonical_id": resource_canonical_id, "runtime_id": resource_runtime_id},
        action=action,
        context={
            "workflow_id": workflow_id,
            "workflow_instance_id": workflow_instance_id,
            "risk": risk_level,
            "timestamp": now,
            "environment": environment,
            "auth_strength": auth_strength,
            "human_approval": {},
        },
        parameters=parameters or {},
        request_hash=None,
    )
    request.request_hash = compute_request_hash(request)

    request.context.__pydantic_extra__["risk_evidence"] = _sign_assertion(
        {
            "issuer": "risk.prototype",
            "key_id": "risk-1",
            "evidence_id": f"risk-{uuid4()}",
            "score": risk_score,
            "level": risk_level,
            "model_id": "prototype_weighted_risk",
            "model_version": "1.0",
            "risk_version": "risk-epoch-1",
            "threshold_version": config.risk_threshold_version,
            "issued_at": _iso(now),
            "expires_at": _iso(expires),
        },
        "risk_private.pem",
    )
    request.context.__pydantic_extra__["auth_evidence"] = _sign_assertion(
        {
            "issuer": "idp.prototype",
            "key_id": "idp-1",
            "evidence_id": f"auth-{uuid4()}",
            "subject_canonical_id": subject_canonical_id,
            "factors": auth_factors,
            "strength": auth_strength,
            "identity_version": "identity-epoch-1",
            "mapping_version": config.auth_factor_mapping_version,
            "issued_at": _iso(now),
            "expires_at": _iso(expires),
        },
        "idp_private.pem",
    )
    if workflow_id is not None:
        request.context.__pydantic_extra__["workflow_evidence"] = _sign_assertion(
            {
                "issuer": "workflow.prototype",
                "key_id": "workflow-1",
                "evidence_id": f"workflow-{uuid4()}",
                "workflow_id": workflow_id,
                "workflow_instance_id": workflow_instance_id,
                "step": action,
                "issued_at": _iso(now),
                "expires_at": _iso(expires),
            },
            "workflow_private.pem",
        )
    if with_human_approval:
        request.context.human_approval = _sign_bound_decision(
            request,
            issuer="approval.prototype",
            key_id="approval-1",
            key_file="approval_private.pem",
            now=now,
            expires=expires,
        )
    if with_secondary_authorization:
        request.context.__pydantic_extra__["secondary_authorization"] = _sign_bound_decision(
            request,
            issuer="secondary.prototype",
            key_id="secondary-1",
            key_file="secondary_private.pem",
            now=now,
            expires=expires,
        )

    proof = {
        "issuer": "pep.prototype",
        "key_id": "pep-1",
        "jti": f"jti-{uuid4()}",
        "nonce": nonce,
        "subject_canonical_id": subject_canonical_id,
        "subject_runtime_id": subject_runtime_id,
        "request_hash": request.request_hash,
        "issued_at": _iso(now),
        "expires_at": _iso(expires),
    }
    request.subject.identity_evidence = proof
    proof["signature"] = sign_mapping(
        load_private_key(ROOT / "security" / "dev_keys" / "pep_private.pem"),
        request_proof_payload(request),
    )
    request.subject.identity_evidence = proof
    return request


def _sign_assertion(value: dict[str, Any], key_file: str) -> dict[str, Any]:
    value = dict(value)
    value["signature"] = sign_mapping(
        load_private_key(ROOT / "security" / "dev_keys" / key_file),
        value,
    )
    return value


def _sign_bound_decision(
    request: PDPRequest,
    *,
    issuer: str,
    key_id: str,
    key_file: str,
    now: datetime,
    expires: datetime,
) -> dict[str, Any]:
    value = {
        "issuer": issuer,
        "key_id": key_id,
        "evidence_id": f"decision-{uuid4()}",
        "decision": "ALLOW",
        "request_hash": request.request_hash,
        "subject_canonical_id": request.subject.canonical_id,
        "resource_canonical_id": request.resource.canonical_id,
        "action": request.action,
        "workflow_instance_id": request.context.workflow_instance_id,
        "issued_at": _iso(now),
        "expires_at": _iso(expires),
    }
    return _sign_assertion(value, key_file)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
