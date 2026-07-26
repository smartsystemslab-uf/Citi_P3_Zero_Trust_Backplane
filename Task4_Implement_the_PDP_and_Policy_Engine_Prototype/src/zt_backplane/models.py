from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
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


class PDPContext(BaseModel):
    """Runtime facts supplied by a PEP.

    Extra context fields are accepted so Task 1-3 outputs can be connected later
    without changing the API contract immediately.
    """

    model_config = ConfigDict(extra="allow")

    workflow: str | None = None
    workflow_id: str | None = None
    risk: RiskLevel = RiskLevel.MEDIUM
    timestamp: datetime | None = None
    auth_strength: int = Field(default=1, ge=0, le=10)
    human_approved: bool = False
    source: str | None = None
    data_classification: str | None = None
    session_id: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)

    def effective_timestamp(self) -> datetime:
        ts = self.timestamp or datetime.now(timezone.utc)
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts


class PDPRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(default_factory=lambda: str(uuid4()))
    trace_id: str = Field(default_factory=lambda: str(uuid4()))
    subject: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    action: str = Field(min_length=1)
    context: PDPContext = Field(default_factory=PDPContext)
    parameters: dict[str, Any] = Field(default_factory=dict)

    @field_validator("subject", "resource", "action")
    @classmethod
    def normalize_identifier(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("identifier must not be blank")
        return value


class Obligation(BaseModel):
    type: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class PDPResponse(BaseModel):
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
    cache_control: str = "NO_STORE"


class IdentityRecord(BaseModel):
    id: str
    type: str = "agent"
    roles: list[str] = Field(default_factory=list)
    domain: str | None = None
    enabled: bool = True
    attributes: dict[str, Any] = Field(default_factory=dict)


class ResourceRecord(BaseModel):
    id: str
    actions: list[str]
    domain: str | None = None
    classification: str = "internal"
    critical: bool = False
    attributes: dict[str, Any] = Field(default_factory=dict)
