"""Signed PDP requests: the PEP request proof and the context assertions the PDP verifies.

``SignedRequestBuilder`` is the PEP-side counterpart of ``evidence.EvidenceVerifier``. It is
parameterised with the issuer keys of one deployment (PEP request proof, risk, identity /
authentication, workflow) and the deployment's security configuration, so the same code
serves the development harness (``dev_evidence``, local development keys) and generated
deployments (``zt_adk``, keys generated per deployment).

Human approval and independent secondary authorization are NOT produced here: they are
assertions signed by an approver (``sign_bound_decision`` with the approver's own key) and
passed in already signed. ``bound_decision_payload`` gives the exact content an approver signs.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import compute_request_hash, request_proof_payload
from .crypto import sign_mapping
from .evidence import SecurityConfig
from .models import PDPRequest


@dataclass(frozen=True)
class IssuerKey:
    issuer: str
    key_id: str
    private_key: Ed25519PrivateKey


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def sign_assertion(value: Mapping[str, Any], key: IssuerKey) -> dict[str, Any]:
    out = dict(value)
    out.pop("signature", None)
    out["issuer"] = key.issuer
    out["key_id"] = key.key_id
    out["signature"] = sign_mapping(key.private_key, out)
    return out


def bound_decision_payload(
    *,
    request_hash: str,
    subject_canonical_id: str,
    resource_canonical_id: str,
    action: str,
    workflow_instance_id: str | None,
    decision: str = "ALLOW",
    issued_at: datetime,
    lifetime_seconds: int,
    evidence_id: str | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Unsigned content of an approval / secondary authorization bound to one operation
    (the PDP checks request_hash, subject, resource, action and workflow instance)."""
    value: dict[str, Any] = {
        "evidence_id": evidence_id or f"decision-{uuid4()}",
        "decision": decision,
        "request_hash": request_hash,
        "subject_canonical_id": subject_canonical_id,
        "resource_canonical_id": resource_canonical_id,
        "action": action,
        "workflow_instance_id": workflow_instance_id,
        "issued_at": iso(issued_at),
        "expires_at": iso(issued_at + timedelta(seconds=lifetime_seconds)),
    }
    if extra:
        value.update({k: v for k, v in extra.items() if k not in value})
    return value


def sign_bound_decision(payload: Mapping[str, Any], key: IssuerKey) -> dict[str, Any]:
    return sign_assertion(payload, key)


class SignedRequestBuilder:
    def __init__(
        self,
        *,
        security_config: SecurityConfig,
        pep: IssuerKey,
        risk: IssuerKey,
        idp: IssuerKey,
        workflow: IssuerKey,
        environment: str = "prototype",
        lifetime_seconds: int = 60,
        risk_model_id: str = "prototype_weighted_risk",
        risk_model_version: str = "1.0",
        risk_version: str = "risk-epoch-1",
    ) -> None:
        self.config = security_config
        self.pep = pep
        self.risk = risk
        self.idp = idp
        self.workflow = workflow
        self.environment = environment
        self.lifetime = timedelta(seconds=lifetime_seconds)
        self.risk_model_id = risk_model_id
        self.risk_model_version = risk_model_version
        self.risk_version = risk_version

    def unsigned_request(
        self,
        *,
        subject_canonical_id: str,
        subject_runtime_id: str,
        resource_canonical_id: str,
        resource_runtime_id: str | None,
        action: str,
        workflow_id: str | None,
        workflow_instance_id: str | None,
        risk_score: int,
        auth_factors: Mapping[str, bool],
        parameters: Mapping[str, Any] | None = None,
        trace_id: str | None = None,
        now: datetime | None = None,
    ) -> PDPRequest:
        """The request with its request_hash but without evidence. The request hash is what
        an approver binds an approval to (it is independent of nonce, ids and time)."""
        now = now or datetime.now(timezone.utc)
        request = PDPRequest(
            schema_version="1.0",
            request_id=f"req-{uuid4()}",
            trace_id=trace_id or f"trace-{uuid4()}",
            subject={"canonical_id": subject_canonical_id, "runtime_id": subject_runtime_id,
                     "identity_evidence": {}},
            resource={"canonical_id": resource_canonical_id, "runtime_id": resource_runtime_id},
            action=action,
            context={
                "workflow_id": workflow_id,
                "workflow_instance_id": workflow_instance_id,
                "risk": self.config.classify_risk(risk_score).value,
                "timestamp": now,
                "environment": self.environment,
                "auth_strength": self.config.calculate_auth_strength(dict(auth_factors)),
                "human_approval": {},
            },
            parameters=dict(parameters or {}),
            request_hash=None,
        )
        request.request_hash = compute_request_hash(request)
        return request

    def build(
        self,
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
        auth_factors: Mapping[str, bool],
        parameters: Mapping[str, Any] | None = None,
        identity_version: str = "identity-epoch-1",
        authentication: Mapping[str, Any] | None = None,
        human_approval: Mapping[str, Any] | None = None,
        secondary_authorization: Mapping[str, Any] | None = None,
        trace_id: str | None = None,
        now: datetime | None = None,
    ) -> PDPRequest:
        now = now or datetime.now(timezone.utc)
        expires = now + self.lifetime
        request = self.unsigned_request(
            subject_canonical_id=subject_canonical_id, subject_runtime_id=subject_runtime_id,
            resource_canonical_id=resource_canonical_id, resource_runtime_id=resource_runtime_id,
            action=action, workflow_id=workflow_id, workflow_instance_id=workflow_instance_id,
            risk_score=risk_score, auth_factors=auth_factors, parameters=parameters, trace_id=trace_id, now=now)
        extra = request.context.__pydantic_extra__
        risk_level = request.context.risk.value
        extra["risk_evidence"] = sign_assertion({
            "evidence_id": f"risk-{uuid4()}",
            "score": int(risk_score),
            "level": risk_level,
            "model_id": self.risk_model_id,
            "model_version": self.risk_model_version,
            "risk_version": self.risk_version,
            "threshold_version": self.config.risk_threshold_version,
            "issued_at": iso(now),
            "expires_at": iso(expires),
        }, self.risk)
        auth: dict[str, Any] = {
            "evidence_id": f"auth-{uuid4()}",
            "subject_canonical_id": subject_canonical_id,
            "factors": dict(auth_factors),
            "strength": request.context.auth_strength,
            "identity_version": identity_version,
            "mapping_version": self.config.auth_factor_mapping_version,
            "issued_at": iso(now),
            "expires_at": iso(expires),
        }
        if authentication:
            auth["authentication"] = dict(authentication)
        extra["auth_evidence"] = sign_assertion(auth, self.idp)
        if workflow_id is not None:
            extra["workflow_evidence"] = sign_assertion({
                "evidence_id": f"workflow-{uuid4()}",
                "workflow_id": workflow_id,
                "workflow_instance_id": workflow_instance_id,
                "step": action,
                "issued_at": iso(now),
                "expires_at": iso(expires),
            }, self.workflow)
        if human_approval:
            request.context.human_approval = dict(human_approval)
        if secondary_authorization:
            extra["secondary_authorization"] = dict(secondary_authorization)
        proof: dict[str, Any] = {
            "issuer": self.pep.issuer,
            "key_id": self.pep.key_id,
            "jti": f"jti-{uuid4()}",
            "nonce": nonce,
            "subject_canonical_id": subject_canonical_id,
            "subject_runtime_id": subject_runtime_id,
            "request_hash": request.request_hash,
            "issued_at": iso(now),
            "expires_at": iso(expires),
        }
        request.subject.identity_evidence = proof
        proof["signature"] = sign_mapping(self.pep.private_key, request_proof_payload(request))
        request.subject.identity_evidence = proof
        return request
