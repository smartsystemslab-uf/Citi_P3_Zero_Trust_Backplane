from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from zt_backplane.canonical import request_proof_payload
from zt_backplane.crypto import load_private_key, sign_mapping
from zt_backplane.dev_evidence import build_signed_request
from zt_backplane.models import PDPRequest
from zt_backplane.pdp_service import Runtime


ROOT = Path(__file__).resolve().parents[1]


def signed_request(
    runtime: Runtime,
    *,
    subject_canonical_id: str,
    subject_runtime_id: str,
    resource_canonical_id: str,
    resource_runtime_id: str | None,
    action: str,
    workflow_id: str | None = None,
    workflow_instance_id: str | None = None,
    risk_score: int = 300,
    auth_factors: dict[str, bool] | None = None,
    parameters: dict[str, Any] | None = None,
    with_human_approval: bool = False,
    with_secondary_authorization: bool = False,
    now: datetime | None = None,
) -> PDPRequest:
    now = now or runtime.engine.evidence_verifier.clock.now()
    challenge = runtime.replay_guard.issue(subject_canonical_id, subject_runtime_id, now=now)
    return build_signed_request(
        nonce=challenge.nonce,
        subject_canonical_id=subject_canonical_id,
        subject_runtime_id=subject_runtime_id,
        resource_canonical_id=resource_canonical_id,
        resource_runtime_id=resource_runtime_id,
        action=action,
        workflow_id=workflow_id,
        workflow_instance_id=workflow_instance_id,
        risk_score=risk_score,
        auth_factors=auth_factors or {"workload_identity": True, "user_session": True},
        parameters=parameters,
        with_human_approval=with_human_approval,
        with_secondary_authorization=with_secondary_authorization,
        now=now,
    )


def resign_request(request: PDPRequest) -> None:
    evidence = request.subject.identity_evidence
    evidence.pop("signature", None)
    request.subject.identity_evidence = evidence
    evidence["signature"] = sign_mapping(
        load_private_key(ROOT / "security" / "dev_keys" / "pep_private.pem"),
        request_proof_payload(request),
    )
    request.subject.identity_evidence = evidence
