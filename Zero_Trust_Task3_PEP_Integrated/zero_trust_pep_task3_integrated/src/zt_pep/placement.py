from __future__ import annotations

import re
from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from .manifest import record_index, runtime_binding
from .models import CoverageFinding, LogicalPEP, PEPPlan, PhysicalPEP


SENSITIVE_CLASSIFICATIONS = {"confidential", "restricted", "regulated"}
SUPPORTED_ADAPTERS = {
    "input": "input_output_pep.py",
    "agent_route": "agent_route_middleware.py",
    "tool": "tool_wrappers.py",
    "mcp": "mcp_wrappers.py",
    "api": "fastapi_dependencies.py",
    "data": "data_wrappers.py",
    "event": "event_wrappers.py",
    "output": "input_output_pep.py",
    "shared_middleware": "shared_middleware.py",
}


def _slug(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return value or "unknown"


def _action_record(resource: dict[str, Any], action_name: str) -> dict[str, Any]:
    for action in resource.get("actions", []):
        if action.get("name") == action_name:
            return action
    return {}


def _is_critical(edge: dict[str, Any], resource: dict[str, Any]) -> bool:
    action = _action_record(resource, str(edge.get("action", "")))
    return bool(
        edge.get("risk") == "critical"
        or action.get("criticality") == "critical"
        or (edge.get("side_effect") and resource.get("type") in {"ledger", "database", "api", "tool"})
    )


def _is_sensitive(edge: dict[str, Any], resource: dict[str, Any]) -> bool:
    action = _action_record(resource, str(edge.get("action", "")))
    return bool(
        edge.get("trust_boundary_id")
        or edge.get("risk") in {"medium", "high", "critical"}
        or edge.get("side_effect")
        or resource.get("classification") in SENSITIVE_CLASSIFICATIONS
        or action.get("criticality") in {"high", "critical"}
    )


def _infer_type(
    edge: dict[str, Any],
    resource: dict[str, Any],
    interface: dict[str, Any] | None,
    boundary: dict[str, Any] | None,
) -> str:
    boundary_id = str(edge.get("trust_boundary_id") or "")
    from_zone = str((boundary or {}).get("from_zone") or "")
    to_zone = str((boundary or {}).get("to_zone") or "")
    interface_type = (interface or {}).get("type")
    resource_type = resource.get("type")

    if "user" in boundary_id or from_zone == "user":
        return "input"
    if "event" in boundary_id or from_zone == "event":
        return "event"
    if "output" in boundary_id or "egress" in boundary_id or to_zone in {"external", "output"}:
        return "output"
    if "agent.agent" in boundary_id or (from_zone == "agent" and to_zone == "agent"):
        return "agent_route"
    if interface_type == "mcp":
        return "mcp"
    if interface_type in {"http", "grpc"}:
        return "api"
    if interface_type == "event_bus":
        return "event"
    if interface_type in {"database", "file"} or resource_type in {"data", "database", "ledger", "file", "knowledge_base"}:
        return "data"
    if interface_type == "python_function" or resource_type == "tool":
        return "tool"
    return "shared_middleware"


def _physical_group_key(logical: dict[str, Any]) -> str:
    # One physical adapter can protect many logical edges. The adapter still sends
    # the edge-specific canonical request to Task 4, so deduplication does not
    # weaken policy granularity.
    family = logical.get("interface_type") or logical.get("trust_boundary_id") or "generic"
    if logical["pep_type"] == "mcp":
        family = "shared_mcp_gateway"
    elif logical["pep_type"] == "data":
        family = "shared_data_access_guard"
    elif logical["pep_type"] == "api":
        family = "shared_api_dependency"
    return ":".join(
        [logical["pep_type"], logical["mode"], logical["fail_mode"], str(family)]
    )


def build_pep_plan(manifest: dict[str, Any]) -> tuple[PEPPlan, dict[str, Any]]:
    spec = manifest["spec"]
    environment = spec["defaults"]["environment_binding"]
    subjects = record_index(manifest, "subjects")
    resources = record_index(manifest, "resources")
    interfaces = record_index(manifest, "interfaces")
    boundaries = record_index(manifest, "trust_boundaries")

    logical_payloads: list[dict[str, Any]] = []
    findings: list[CoverageFinding] = []
    updated_manifest = deepcopy(manifest)
    updated_edges = {item["id"]: item for item in updated_manifest["spec"].get("interactions", [])}

    for edge in spec.get("interactions", []):
        resource = resources[edge["resource_id"]]
        subject = subjects[edge["caller_id"]]
        interface = interfaces.get(edge.get("interface_id"))
        boundary = boundaries.get(edge.get("trust_boundary_id"))
        explicit = edge.get("pep") or {}
        sensitive = _is_sensitive(edge, resource)
        critical = _is_critical(edge, resource)

        required = bool(explicit.get("required", False) or sensitive)
        if sensitive and explicit.get("required") is False:
            findings.append(
                CoverageFinding(
                    id=f"finding.{_slug(edge['id'])}.forced_protection",
                    severity="critical",
                    category="unsafe_manifest_override",
                    edge_id=edge["id"],
                    resource_id=edge["resource_id"],
                    message="Sensitive edge declared pep.required=false; Task 3 forced protection.",
                    blocks_milestone=True,
                )
            )

        inferred_type = _infer_type(edge, resource, interface, boundary)
        pep_type = explicit.get("type")
        if pep_type in {None, "none"} and required:
            pep_type = inferred_type
        if pep_type == "none" and not required:
            continue
        if pep_type not in SUPPORTED_ADAPTERS:
            findings.append(
                CoverageFinding(
                    id=f"finding.{_slug(edge['id'])}.unsupported_adapter",
                    severity="critical",
                    category="unsupported_pep_type",
                    edge_id=edge["id"],
                    resource_id=edge["resource_id"],
                    message=f"No generator exists for PEP type {pep_type!r}.",
                    blocks_milestone=True,
                )
            )
            continue

        mode = explicit.get("mode") or spec["defaults"].get("pep_mode", "enforce")
        fail_mode = explicit.get("fail_mode") or ("closed" if critical or edge.get("risk") in {"high", "critical"} else "open_for_noncritical")
        placement_id = explicit.get("placement_id") or f"pep.{edge['id'].removeprefix('edge.')}"

        subject_binding = runtime_binding(subject, environment)
        resource_binding = runtime_binding(resource, environment)
        source_status = str(edge.get("metadata", {}).get("status", "placeholder"))
        logical = {
            "placement_id": placement_id,
            "physical_pep_id": "",
            "edge_id": edge["id"],
            "pep_type": pep_type,
            "mode": mode,
            "fail_mode": fail_mode,
            "subject_canonical_id": edge["caller_id"],
            "subject_runtime_id": subject_binding.get("runtime_id"),
            "target_id": edge["target_id"],
            "resource_canonical_id": edge["resource_id"],
            "resource_runtime_id": resource_binding.get("runtime_id"),
            "resource_type": resource.get("type", "other"),
            "resource_classification": resource.get("classification", "internal"),
            "action": edge["action"],
            "workflow_id": edge.get("workflow_id"),
            "interface_id": edge.get("interface_id"),
            "interface_type": (interface or {}).get("type"),
            "trust_boundary_id": edge.get("trust_boundary_id"),
            "risk": edge["risk"],
            "side_effect": bool(edge.get("side_effect", False)),
            "critical": critical,
            "adapter_module": SUPPORTED_ADAPTERS[pep_type],
            "source_status": source_status,
            "attributes": {
                "manifest_pep_type": explicit.get("type"),
                "inferred_pep_type": inferred_type,
                "sensitive": sensitive,
            },
        }
        logical_payloads.append(logical)

        updated_edges[edge["id"]]["pep"] = {
            "required": required,
            "type": pep_type,
            "mode": mode,
            "placement_id": placement_id,
            "fail_mode": fail_mode,
        }

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for logical in logical_payloads:
        grouped[_physical_group_key(logical)].append(logical)

    physical_peps: list[PhysicalPEP] = []
    for group_key, items in sorted(grouped.items()):
        first = items[0]
        physical_id = f"physical_pep.{_slug(group_key)}"
        for item in items:
            item["physical_pep_id"] = physical_id
        physical_peps.append(
            PhysicalPEP(
                physical_pep_id=physical_id,
                pep_type=first["pep_type"],
                adapter_module=first["adapter_module"],
                mode=first["mode"],
                fail_mode=first["fail_mode"],
                logical_placements=sorted(item["placement_id"] for item in items),
                interfaces=sorted({item["interface_id"] for item in items if item.get("interface_id")}),
                resources=sorted({item["resource_canonical_id"] for item in items}),
                description=(
                    f"Shared {first['pep_type']} enforcement component. It routes each operation "
                    "using the logical placement ID and preserves per-edge PDP decisions."
                ),
            )
        )

    logical_peps = [LogicalPEP.model_validate(item) for item in logical_payloads]
    protected_edges = {item.edge_id for item in logical_peps}
    sensitive_edges = {
        edge["id"]
        for edge in spec.get("interactions", [])
        if _is_sensitive(edge, resources[edge["resource_id"]])
    }
    missing_sensitive = sorted(sensitive_edges - protected_edges)
    for edge_id in missing_sensitive:
        edge = next(item for item in spec["interactions"] if item["id"] == edge_id)
        findings.append(
            CoverageFinding(
                id=f"finding.{_slug(edge_id)}.unprotected",
                severity="critical",
                category="unprotected_sensitive_path",
                edge_id=edge_id,
                resource_id=edge["resource_id"],
                message="Sensitive interaction has no generated PEP.",
                blocks_milestone=True,
            )
        )

    incoming_resources = {edge["resource_id"] for edge in spec.get("interactions", [])}
    sensitive_inventory = set()
    for resource in spec.get("resources", []):
        action_critical = any(a.get("criticality") in {"high", "critical"} for a in resource.get("actions", []))
        if resource.get("classification") in SENSITIVE_CLASSIFICATIONS or action_critical:
            sensitive_inventory.add(resource["id"])
    unmapped_resources = sorted(sensitive_inventory - incoming_resources)
    for resource_id in unmapped_resources:
        findings.append(
            CoverageFinding(
                id=f"finding.{_slug(resource_id)}.no_discovered_path",
                severity="information",
                category="scanner_coverage_gap",
                resource_id=resource_id,
                message=(
                    "Sensitive resource exists in the inventory but no interaction edge reaches it. "
                    "Task 3 cannot prove or place path-specific enforcement until Task 2 discovers the path."
                ),
                blocks_milestone=False,
            )
        )

    coverage_percent = 100.0 if not sensitive_edges else round(100.0 * len(sensitive_edges & protected_edges) / len(sensitive_edges), 2)
    coverage = {
        "interaction_edges_total": len(spec.get("interactions", [])),
        "sensitive_interaction_edges": len(sensitive_edges),
        "protected_sensitive_edges": len(sensitive_edges & protected_edges),
        "sensitive_path_coverage_percent": coverage_percent,
        "known_direct_bypass_paths": len(missing_sensitive),
        "logical_pep_count": len(logical_peps),
        "physical_pep_count": len(physical_peps),
        "deduplicated_component_savings": max(0, len(logical_peps) - len(physical_peps)),
        "sensitive_inventory_resources_without_discovered_edges": unmapped_resources,
        "coverage_claim_scope": "Known interaction edges in the unified manifest only",
    }

    plan = PEPPlan(
        manifest_name=manifest["metadata"]["name"],
        manifest_version=manifest["metadata"]["manifest_version"],
        environment_binding=environment,
        generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        logical_peps=sorted(logical_peps, key=lambda item: item.placement_id),
        physical_peps=physical_peps,
        coverage=coverage,
        findings=findings,
        compatibility={},
    )
    return plan, updated_manifest
