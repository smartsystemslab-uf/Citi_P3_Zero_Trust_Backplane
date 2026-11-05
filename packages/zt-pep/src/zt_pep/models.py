from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class LogicalPEP(BaseModel):
    model_config = ConfigDict(extra="forbid")

    placement_id: str
    physical_pep_id: str
    edge_id: str
    pep_type: Literal[
        "input", "agent_route", "tool", "mcp", "api", "data", "event", "output", "shared_middleware"
    ]
    mode: Literal["shadow", "enforce"]
    fail_mode: Literal["closed", "open_for_noncritical", "shadow_only"]
    subject_canonical_id: str
    subject_runtime_id: str | None
    target_id: str
    resource_canonical_id: str
    resource_runtime_id: str | None
    resource_type: str
    resource_classification: str
    action: str
    workflow_id: str | None
    interface_id: str | None
    interface_type: str | None
    trust_boundary_id: str | None
    risk: Literal["low", "medium", "high", "critical"]
    side_effect: bool
    critical: bool
    adapter_module: str
    source_status: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class PhysicalPEP(BaseModel):
    model_config = ConfigDict(extra="forbid")

    physical_pep_id: str
    pep_type: str
    adapter_module: str
    mode: str
    fail_mode: str
    logical_placements: list[str]
    interfaces: list[str]
    resources: list[str]
    description: str


class CoverageFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    severity: Literal["critical", "high", "medium", "low", "information"]
    category: str
    edge_id: str | None = None
    resource_id: str | None = None
    message: str
    blocks_milestone: bool = False


class PEPPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    manifest_name: str
    manifest_version: str
    environment_binding: str
    generated_at: str
    logical_peps: list[LogicalPEP]
    physical_peps: list[PhysicalPEP]
    coverage: dict[str, Any]
    findings: list[CoverageFinding]
    compatibility: dict[str, Any] = Field(default_factory=dict)
