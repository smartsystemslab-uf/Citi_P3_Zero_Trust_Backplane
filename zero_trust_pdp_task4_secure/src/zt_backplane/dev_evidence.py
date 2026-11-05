"""Development-only signed evidence builder (Task 4 harness, tests, Citi reference demo).

Uses ``evidence_issuer.SignedRequestBuilder`` with the development issuer keys of this
checkout (``security/dev_keys``, generated locally on first use by
``zt_backplane.dev_material``, never committed).

``with_human_approval`` / ``with_secondary_authorization`` make this harness sign the
approval assertions itself with the development approver keys -- a test convenience of the
prototype harness only. Generated deployments (``zt_adk``) never do that: there an approval
is signed by a human approver with a key the runtime does not hold.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .crypto import load_private_key
from .dev_material import dev_key_path
from .evidence import SecurityConfig
from .evidence_issuer import IssuerKey, SignedRequestBuilder, bound_decision_payload, sign_bound_decision
from .models import PDPRequest


ROOT = Path(__file__).resolve().parents[2]

_DEV_ISSUERS = {
    "pep": ("pep.prototype", "pep-1", "pep_private.pem"),
    "risk": ("risk.prototype", "risk-1", "risk_private.pem"),
    "idp": ("idp.prototype", "idp-1", "idp_private.pem"),
    "workflow": ("workflow.prototype", "workflow-1", "workflow_private.pem"),
    "approval": ("approval.prototype", "approval-1", "approval_private.pem"),
    "secondary": ("secondary.prototype", "secondary-1", "secondary_private.pem"),
}


def dev_issuer_key(role: str) -> IssuerKey:
    issuer, key_id, filename = _DEV_ISSUERS[role]
    return IssuerKey(issuer, key_id, load_private_key(dev_key_path(filename, ROOT)))


def dev_request_builder(environment: str = "prototype") -> SignedRequestBuilder:
    return SignedRequestBuilder(
        security_config=SecurityConfig(ROOT / "config" / "security_context.yaml"),
        pep=dev_issuer_key("pep"),
        risk=dev_issuer_key("risk"),
        idp=dev_issuer_key("idp"),
        workflow=dev_issuer_key("workflow"),
        environment=environment,
    )


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
    builder = dev_request_builder(environment)
    approvals: dict[str, Any] = {}
    if with_human_approval or with_secondary_authorization:
        unsigned = builder.unsigned_request(
            subject_canonical_id=subject_canonical_id, subject_runtime_id=subject_runtime_id,
            resource_canonical_id=resource_canonical_id, resource_runtime_id=resource_runtime_id,
            action=action, workflow_id=workflow_id, workflow_instance_id=workflow_instance_id,
            risk_score=risk_score, auth_factors=auth_factors, parameters=parameters, now=now)
        for flag, role, name in ((with_human_approval, "approval", "human_approval"),
                                 (with_secondary_authorization, "secondary", "secondary_authorization")):
            if flag:
                payload = bound_decision_payload(
                    request_hash=str(unsigned.request_hash), subject_canonical_id=subject_canonical_id,
                    resource_canonical_id=resource_canonical_id, action=action,
                    workflow_instance_id=workflow_instance_id, issued_at=now, lifetime_seconds=60)
                approvals[name] = sign_bound_decision(payload, dev_issuer_key(role))
    return builder.build(
        nonce=nonce,
        subject_canonical_id=subject_canonical_id,
        subject_runtime_id=subject_runtime_id,
        resource_canonical_id=resource_canonical_id,
        resource_runtime_id=resource_runtime_id,
        action=action,
        workflow_id=workflow_id,
        workflow_instance_id=workflow_instance_id,
        risk_score=risk_score,
        auth_factors=auth_factors,
        parameters=parameters,
        human_approval=approvals.get("human_approval"),
        secondary_authorization=approvals.get("secondary_authorization"),
        now=now,
    )
