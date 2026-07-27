from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    ALLOW_WITH_OBLIGATIONS = "ALLOW_WITH_OBLIGATIONS"
    REAUTHENTICATE = "REAUTHENTICATE"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SubjectRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    canonical_id: str = Field(min_length=1)
    runtime_id: str = Field(min_length=1)
    identity_evidence: dict[str, Any]


class ResourceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    canonical_id: str = Field(min_length=1)
    runtime_id: str | None


class PDPContext(BaseModel):
    """Version 1.0 context contract from the reusable interface standard.

    The schema deliberately allows additional properties. Security assertions use
    those existing extension points; the interface schema itself is unchanged.
    """

    model_config = ConfigDict(extra="allow")

    workflow_id: str | None
    workflow_instance_id: str | None = None
    risk: RiskLevel
    timestamp: datetime
    environment: str = Field(min_length=1)
    auth_strength: int = Field(default=0, ge=0, le=10)
    human_approval: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("context.timestamp must include a timezone")
        return value


class PDPRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    request_id: str = Field(min_length=1)
    trace_id: str = Field(min_length=1)
    subject: SubjectRef
    resource: ResourceRef
    action: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    context: PDPContext
    parameters: dict[str, Any]
    request_hash: str | None = None


class Obligation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(min_length=1)
    parameters: dict[str, Any] = Field(default_factory=dict)


class PDPResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    decision_id: str = Field(default_factory=lambda: str(uuid4()))
    request_id: str
    trace_id: str
    decision: Decision
    reason: str
    policy_id: str | None = None
    matched_policy_ids: list[str] = Field(default_factory=list)
    policy_version: str
    obligations: list[Obligation] = Field(default_factory=list)
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    cache_control: Literal["NO_STORE", "PERMIT_LEASE"] = "NO_STORE"
    permit_lease: dict[str, Any] | None = None


class IdentityRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    canonical_id: str
    type: str = "agent"
    roles: list[str] = Field(default_factory=list)
    domain: str | None = None
    enabled: bool = True
    attributes: dict[str, Any] = Field(default_factory=dict)


class ResourceRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    canonical_id: str
    actions: list[str]
    domain: str | None = None
    classification: str = "internal"
    critical: bool = False
    attributes: dict[str, Any] = Field(default_factory=dict)


class VerifiedSecurityContext(BaseModel):
    """Facts accepted only after signature, freshness, and binding checks."""

    model_config = ConfigDict(extra="forbid")

    decision_time: datetime
    identity_verified: bool
    identity_issuer: str
    request_jti: str
    request_nonce: str
    identity_version: str
    risk_verified: bool
    risk_issuer: str
    risk_score: int = Field(ge=0, le=1000)
    risk_level: RiskLevel
    risk_version: str
    auth_verified: bool
    auth_issuer: str
    auth_strength: int = Field(ge=0, le=10)
    workflow_verified: bool
    workflow_issuer: str | None = None
    approval_valid: bool = False
    approval_issuer: str | None = None
    secondary_authorization_valid: bool = False
    secondary_authorization_issuer: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class ChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject_canonical_id: str
    subject_runtime_id: str


class ChallengeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nonce: str
    subject_canonical_id: str
    subject_runtime_id: str
    issued_at: datetime
    expires_at: datetime
