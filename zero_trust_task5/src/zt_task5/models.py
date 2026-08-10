from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .errors import InterfaceError
from .request_hash import calculate_request_hash


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    ALLOW_WITH_OBLIGATIONS = "ALLOW_WITH_OBLIGATIONS"
    REAUTHENTICATE = "REAUTHENTICATE"


class RuntimeState(str, Enum):
    NO_DECISION = "NO_DECISION"
    WAITING_FOR_PDP = "WAITING_FOR_PDP"
    ACTIVE_LEASE = "ACTIVE_LEASE"
    DENIED = "DENIED"


class ContextBinding(BaseModel):
    model_config = ConfigDict(extra="allow")

    kind: str
    assertion_id: str
    issuer: str = ""
    issuer_version: str = ""
    evidence_hash: str


class UnifiedAuthorizationRequest(BaseModel):
    """Normalized interface shared by generated PEPs, the PDP, and Task 5."""

    model_config = ConfigDict(extra="allow")

    interface_version: str = "1.0"
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    subject: str
    resource: str
    action: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)
    workflow_id: str = ""
    audience: str = ""
    endpoint: str = ""
    critical: bool = False
    risk: str = "low"
    idempotency_key: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def fill_context_aliases(self) -> "UnifiedAuthorizationRequest":
        if not self.workflow_id:
            self.workflow_id = str(
                self.context.get("workflow_id")
                or self.context.get("workflow_instance")
                or self.context.get("workflow")
                or ""
            )
        if not self.audience:
            self.audience = str(self.context.get("audience") or "")
        if not self.endpoint:
            self.endpoint = str(self.context.get("endpoint") or "")
        if not self.evidence:
            self.evidence = dict(
                self.context.get("evidence")
                or self.context.get("assertions")
                or {}
            )
        if self.idempotency_key is None:
            raw = self.context.get("idempotency_key")
            self.idempotency_key = str(raw) if raw is not None else None
        if self.risk == "low" and self.context.get("risk") is not None:
            self.risk = str(self.context.get("risk"))
        return self

    @field_validator("subject", "resource", "action")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("subject, resource, and action must be non-empty")
        return value

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "UnifiedAuthorizationRequest":
        context = dict(raw.get("context") or {})
        parameters = raw.get("parameters")
        if parameters is None:
            parameters = raw.get("params")
        if parameters is None:
            parameters = raw.get("input")
        if parameters is None:
            parameters = {}

        subject = raw.get("subject") or raw.get("subject_id") or raw.get("caller")
        resource = raw.get("resource") or raw.get("resource_id") or raw.get("target")
        action = raw.get("action") or raw.get("operation")
        if not subject or not resource or not action:
            raise InterfaceError("The unified request is missing subject, resource, or action")

        normalized = dict(raw)
        normalized.update(
            subject=str(subject),
            resource=str(resource),
            action=str(action),
            parameters=dict(parameters),
            context=context,
            workflow_id=str(
                raw.get("workflow_id")
                or context.get("workflow_id")
                or context.get("workflow_instance")
                or context.get("workflow")
                or ""
            ),
            audience=str(raw.get("audience") or context.get("audience") or ""),
            endpoint=str(raw.get("endpoint") or context.get("endpoint") or ""),
            evidence=dict(
                raw.get("evidence")
                or context.get("evidence")
                or context.get("assertions")
                or {}
            ),
            critical=bool(raw.get("critical") or context.get("critical") or False),
            risk=str(raw.get("risk") or context.get("risk") or "low"),
            idempotency_key=raw.get("idempotency_key")
            or context.get("idempotency_key"),
        )
        return cls.model_validate(normalized)

    def request_hash(self) -> str:
        # Stable operation fingerprint shared with Task 3 and Task 4. Freshness
        # fields and signed context assertions are validated separately, so a
        # legitimate retry can match a bounded lease without weakening binding.
        protected_operation = {
            "interface_version": self.interface_version,
            "subject": self.subject,
            "resource": self.resource,
            "action": self.action,
            "parameters": self.parameters,
            "workflow_id": self.workflow_id,
            "audience": self.audience,
            "endpoint": self.endpoint,
            "critical": self.critical,
            "idempotency_key": self.idempotency_key,
        }
        return calculate_request_hash(protected_operation)


class Task4Decision(BaseModel):
    model_config = ConfigDict(extra="allow")

    interface_version: str = "1.0"
    decision_id: str = Field(default_factory=lambda: str(uuid4()))
    decision: Decision
    subject: str
    resource: str
    action: str
    workflow_id: str = ""
    request_hash: str
    policy_version: str
    identity_version: str = "1"
    risk_version: str = "1"
    obligations: list[Any] = Field(default_factory=list)
    context_bindings: list[ContextBinding] = Field(default_factory=list)
    issued_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None
    nonce: str = ""
    jti: str = Field(default_factory=lambda: str(uuid4()))
    decision_key_id: str = ""

    @property
    def allows_execution(self) -> bool:
        return self.decision in {Decision.ALLOW, Decision.ALLOW_WITH_OBLIGATIONS}


class PermitLeaseClaims(BaseModel):
    model_config = ConfigDict(extra="forbid")

    interface_version: str = "1.0"
    permit_id: str = Field(default_factory=lambda: str(uuid4()))
    subject: str
    resource: str
    action: str
    request_hash: str
    workflow_id: str
    audience: str
    endpoint: str
    issued_at: datetime
    expires_at: datetime
    policy_version: str
    identity_version: str
    risk_version: str
    max_uses: int = 1
    obligations: list[Any] = Field(default_factory=list)
    pep_identity: str
    pep_key_thumbprint: str
    context_bindings: list[ContextBinding] = Field(default_factory=list)
    decision_id: str
    decision_signing_key_id: str
    permit_signing_key_id: str
    revocation_epoch: int
    nonce: str
    jti: str
    session_id: str | None = None
    critical: bool = False
    idempotency_key: str | None = None

    @model_validator(mode="after")
    def validate_times_and_use_count(self) -> "PermitLeaseClaims":
        if self.expires_at <= self.issued_at:
            raise ValueError("Permit Lease expiration must be after issue time")
        if self.max_uses < 1:
            raise ValueError("max_uses must be at least one")
        if self.critical and self.max_uses != 1:
            raise ValueError("Critical operations require a single-use Permit Lease")
        return self


class SignedPermitLease(BaseModel):
    token: str
    claims: PermitLeaseClaims


class ProofOfPossession(BaseModel):
    interface_version: str = "1.0"
    permit_id: str
    request_hash: str
    nonce: str
    jti: str
    audience: str
    endpoint: str
    key_thumbprint: str
    issued_at: datetime = Field(default_factory=utc_now)
    signature: str


class LeaseValidationResult(BaseModel):
    allowed: bool
    reason: str
    permit_id: str | None = None
    remaining_uses: int | None = None
    obligations: list[Any] = Field(default_factory=list)


class AuthorizationResult(BaseModel):
    state: RuntimeState
    allowed: bool
    reason: str
    permit_token: str | None = None
    permit_id: str | None = None
    used_cached_lease: bool = False
    decision: str | None = None
