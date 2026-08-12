from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

import yaml


_DOMAIN = {
    "front": "front_office",
    "front_office": "front_office",
    "mid": "mid_office",
    "mid_office": "mid_office",
    "back": "back_office",
    "back_office": "back_office",
    "shared": "shared",
    "external": "external",
}

_RISK = {1: "low", 2: "medium", 3: "high", 4: "critical", 5: "critical"}

# Runtime identities that need a stable canonical ID in the merged demo manifest.
# This keeps the actual caller identity instead of aliasing ledger_update_agent as the EOD agent.
_SUBJECT_OVERRIDES = {
    "ledger_update_agent": "agent.back_office.ledger_update",
}

# Scanner edges that correspond to semantic resources already defined by the
# unified interface. These overrides preserve the existing Task 4 policies.
_EDGE_OVERRIDES: dict[tuple[str, str], dict[str, Any]] = {
    ("fraud_detection_agent", "get_transaction_context"): {
        "resource_id": "resource.front_office.transaction_history",
        "action": "read",
        "workflow_id": "workflow.front_office.fraud_review",
        "placement_id": "pep.fraud_review.read_history",
    },
    ("transaction_processing_agent", "execute_transfer"): {
        "resource_id": "resource.front_office.banking_transfer",
        "interface_id": "interface.mcp.execute_transfer",
        "action": "execute",
        "workflow_id": "workflow.front_office.customer_transaction",
        "placement_id": "pep.customer_transaction.execute_transfer",
    },
    ("compliance_agent", "search_policies"): {
        "resource_id": "resource.front_office.policy_knowledge_base",
        "interface_id": "interface.mcp.search_policies",
        "action": "search",
        "workflow_id": "workflow.front_office.fraud_review",
        "placement_id": "pep.fraud_review.policy_search",
    },
    ("eod_processing_agent", "get_eod_batch"): {
        "resource_id": "resource.back_office.eod_batches",
        "interface_id": "interface.mcp.get_eod_batches",
        "action": "read",
        "workflow_id": "workflow.back_office.eod_processing",
        "placement_id": "pep.eod_processing.get_batches",
    },
    ("ledger_update_agent", "apply_ledger_updates"): {
        "resource_id": "resource.back_office.ledger",
        "interface_id": "interface.mcp.ledger_update",
        "action": "update",
        "workflow_id": "workflow.back_office.eod_processing",
        "placement_id": "pep.ledger_update.apply_ledger_updates",
    },
    ("financial_data_agent", "get_customer_financial_profile"): {
        "resource_id": "resource.mid_office.financial_customer_data",
        "action": "read",
        "workflow_id": None,
        "placement_id": "pep.mid_office.financial_data.read_profile",
    },
    ("data_analysis_agent", "get_operations_snapshot"): {
        "resource_id": "resource.mid_office.internal_operations_data",
        "action": "read",
        "workflow_id": None,
        "placement_id": "pep.mid_office.operations.read_snapshot",
    },
}

_INTERFACE_OVERRIDES = {
    "execute_transfer": "interface.mcp.execute_transfer",
    "search_policies": "interface.mcp.search_policies",
    "get_eod_batch": "interface.mcp.get_eod_batches",
    "apply_ledger_updates": "interface.mcp.ledger_update",
    "store_report": "interface.mcp.store_report",
    "create_exception_case": "interface.mcp.create_exception_case",
}


def _load(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"expected mapping in {path}")
    return data


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", value.lower()).strip("_") or "unknown"


def _domain(value: Any) -> str:
    return _DOMAIN.get(str(value or "shared").lower(), "shared")


def _metadata(display_name: str, description: str, reference: str = "Task 2 scanner") -> dict[str, Any]:
    return {
        "display_name": display_name,
        "description": description,
        "status": "provisional",
        "source": {
            "provided_by": "task2_scanner",
            "reference": reference,
            "verified_at": None,
            "notes": "Scanner-derived record merged by integrated_demo only.",
        },
        "owner": None,
        "tags": ["task2_discovered"],
        "extensions": {},
    }


def _binding(runtime_id: str, function_name: str | None = None, endpoint: str | None = None) -> dict[str, Any]:
    return {
        "runtime_id": runtime_id,
        "endpoint": endpoint,
        "function_name": function_name,
        "service_name": None,
        "namespace": None,
        "secret_refs": [],
        "extensions": {},
    }


def _record_runtime_index(items: list[dict[str, Any]], environment: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items:
        runtime = item.get("bindings", {}).get(environment, {}).get("runtime_id")
        if runtime:
            out[str(runtime)] = str(item["id"])
    return out


def _tool_action(tool_id: str, edge: dict[str, Any]) -> str:
    name = tool_id.lower()
    op = str(edge.get("operation_class") or "").lower()
    method = str(edge.get("http_method") or "").upper()
    db_op = str(edge.get("db_operation") or "").upper()
    if name.startswith("search_"):
        return "search"
    if name.startswith(("get_", "list_", "rank_", "validate_")) or op == "read" or method == "GET" or db_op == "SELECT":
        return "read"
    if name.startswith("execute_"):
        return "execute"
    if name.startswith(("apply_", "update_", "persist_")):
        return "update"
    if name.startswith("store_"):
        return "store"
    if name.startswith(("create_", "submit_")):
        return "create"
    if op in {"write", "financial"}:
        return "update"
    return "execute"


def _risk(edge: dict[str, Any]) -> str:
    try:
        return _RISK.get(int(edge.get("risk_level") or 2), "medium")
    except (TypeError, ValueError):
        return "medium"


def _classification(kind: str, item: dict[str, Any], edge: dict[str, Any]) -> str:
    if kind == "database":
        raw = str(item.get("classification") or "internal").lower()
        if raw in {"public", "internal", "confidential", "restricted", "regulated"}:
            return raw
    if bool(item.get("contains_pii")) or bool(item.get("contains_financial")):
        return "restricted"
    return "confidential" if _risk(edge) in {"high", "critical"} else "internal"


def _criticality(edge: dict[str, Any]) -> str:
    risk = _risk(edge)
    if risk == "critical":
        return "critical"
    if bool(edge.get("side_effects") or edge.get("side_effect")) or risk == "high":
        return "high"
    return "medium" if risk == "medium" else "low"


def merge_task2_graph_into_unified(
    manifest: dict[str, Any],
    scanner_output: Path,
    *,
    banking_repo: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Replace baseline interactions with the graph actually discovered by Task 2.

    Existing canonical records are reused whenever their runtime binding matches.
    Scanner-only agents/tools/APIs/databases receive provisional canonical records
    in the *demo output manifest only*. Task 1-5 source files are not modified.
    """

    merged = copy.deepcopy(manifest)
    spec = merged["spec"]
    environment = spec["defaults"]["environment_binding"]

    agents = [x for x in _load(scanner_output / "agents_draft.yaml").get("agents", [])]
    tools = [x for x in _load(scanner_output / "tools_draft.yaml").get("tools", []) if not str(x.get("tool_id", "")).startswith("_")]
    apis = [x for x in _load(scanner_output / "apis_draft.yaml").get("apis", [])]
    databases = [x for x in _load(scanner_output / "databases_draft.yaml").get("databases", [])]
    edges = [x for x in _load(scanner_output / "interaction_edges_draft.yaml").get("interaction_edges", [])]

    agent_by_id = {str(x["agent_id"]): x for x in agents}
    tool_by_id = {str(x["tool_id"]): x for x in tools}
    api_by_id = {str(x["api_id"]): x for x in apis}
    db_by_id = {str(x.get("database_id") or x.get("table_name")): x for x in databases}
    db_by_table = {str(x.get("table_name")): x for x in databases if x.get("table_name")}

    subject_runtime = _record_runtime_index(spec.get("subjects", []), environment)
    interface_runtime = _record_runtime_index(spec.get("interfaces", []), environment)
    resource_runtime = _record_runtime_index(spec.get("resources", []), environment)

    subject_ids = {x["id"] for x in spec.get("subjects", [])}
    interface_ids = {x["id"] for x in spec.get("interfaces", [])}
    resource_ids = {x["id"] for x in spec.get("resources", [])}
    boundary_ids = {x["id"] for x in spec.get("trust_boundaries", [])}

    created = {"subjects": 0, "interfaces": 0, "resources": 0, "interactions": 0}

    def ensure_subject(runtime_id: str, from_type: str) -> str:
        if runtime_id in subject_runtime:
            return subject_runtime[runtime_id]
        subject_override = _SUBJECT_OVERRIDES.get(runtime_id)
        if runtime_id in agent_by_id:
            source = agent_by_id[runtime_id]
        elif runtime_id in tool_by_id:
            source = tool_by_id[runtime_id]
        elif runtime_id in api_by_id:
            source = api_by_id[runtime_id]
        else:
            source = {}
        dom = _domain(source.get("domain"))
        prefix = "agent" if from_type in {"subject", "agent"} or runtime_id in agent_by_id else "service"
        canonical = subject_override or f"{prefix}.{dom}.{_slug(runtime_id)}"
        if canonical not in subject_ids:
            spec["subjects"].append({
                "id": canonical,
                "type": "agent" if prefix == "agent" else "service",
                "roles": [str(source.get("role") or "scanner_discovered")],
                "domain": dom,
                "enabled": True,
                "metadata": _metadata(runtime_id, f"Task 2 discovered subject {runtime_id}.", str(source.get("source", {}).get("reference") or "Task 2 scanner")),
                "bindings": {environment: _binding(runtime_id)},
                "attributes": {"scanner_source_type": from_type},
            })
            subject_ids.add(canonical)
            created["subjects"] += 1
        subject_runtime[runtime_id] = canonical
        return canonical

    def ensure_interface(runtime_id: str, target_type: str) -> str | None:
        override = _INTERFACE_OVERRIDES.get(runtime_id)
        if override and override in interface_ids:
            return override
        if runtime_id in interface_runtime:
            return interface_runtime[runtime_id]
        if target_type not in {"tool", "api"}:
            return None
        source = tool_by_id.get(runtime_id, {}) if target_type == "tool" else api_by_id.get(runtime_id, {})
        kind = "python_function" if target_type == "tool" else "http"
        canonical = f"interface.{kind}.{_slug(runtime_id)}"
        if canonical not in interface_ids:
            endpoint = None
            if target_type == "api":
                base = str(source.get("base_url") or "").rstrip("/")
                path = str(source.get("path") or "")
                endpoint = f"{base}{path}" if base else (path or None)
            spec["interfaces"].append({
                "id": canonical,
                "type": kind,
                "metadata": _metadata(runtime_id, f"Task 2 discovered {target_type} interface {runtime_id}.", str(source.get("source", {}).get("reference") or "Task 2 scanner")),
                "bindings": {environment: _binding(runtime_id, runtime_id if target_type == "tool" else None, endpoint)},
                "authentication": {
                    "method": "placeholder",
                    "issuer": None,
                    "audience": None,
                    "subject_claim": None,
                    "credential_ref": None,
                    "jwks_uri": None,
                    "extensions": {},
                },
                "request_schema_ref": None,
                "response_schema_ref": None,
                "timeout_ms": 5000,
                "retry_policy": {"max_attempts": 1},
                "extensions": {"scanner_discovered": True},
            })
            interface_ids.add(canonical)
            created["interfaces"] += 1
        interface_runtime[runtime_id] = canonical
        return canonical

    def ensure_resource(runtime_id: str, target_type: str, edge: dict[str, Any]) -> str:
        if runtime_id in resource_runtime:
            return resource_runtime[runtime_id]
        source: dict[str, Any]
        if target_type == "tool":
            source = tool_by_id.get(runtime_id, {})
        elif target_type == "api":
            source = api_by_id.get(runtime_id, {})
        elif target_type == "database":
            source = db_by_id.get(runtime_id) or db_by_table.get(runtime_id) or {}
        else:
            source = agent_by_id.get(runtime_id, {})
        dom = _domain(source.get("domain"))
        if target_type == "database" and dom == "shared":
            dom = "shared"
        kind = target_type if target_type in {"tool", "api", "database"} else "other"
        runtime_key = runtime_id if runtime_id != "unknown" else f"unknown_{target_type}"
        canonical = f"resource.{dom}.{_slug(kind + '_' + runtime_key)}"
        action = _tool_action(runtime_id, edge)
        if canonical not in resource_ids:
            spec["resources"].append({
                "id": canonical,
                "type": kind,
                "domain": dom,
                "classification": _classification(kind, source, edge),
                "actions": [{
                    "name": action,
                    "side_effect": bool(edge.get("side_effects") or edge.get("side_effect")),
                    "criticality": _criticality(edge),
                    "requires_human_approval": bool(_risk(edge) == "critical" and (edge.get("side_effects") or edge.get("side_effect"))),
                    "idempotent": not bool(edge.get("side_effects") or edge.get("side_effect")),
                    "parameter_schema_ref": None,
                }],
                "metadata": _metadata(runtime_id, f"Task 2 discovered {target_type} resource {runtime_id}.", str(source.get("source", {}).get("reference") or "Task 2 scanner")),
                "bindings": {environment: _binding(runtime_id)},
                "attributes": {"scanner_target_type": target_type},
            })
            resource_ids.add(canonical)
            created["resources"] += 1
        else:
            resource = next(x for x in spec["resources"] if x["id"] == canonical)
            if action not in {a["name"] for a in resource.get("actions", [])}:
                resource["actions"].append({
                    "name": action,
                    "side_effect": bool(edge.get("side_effects") or edge.get("side_effect")),
                    "criticality": _criticality(edge),
                    "requires_human_approval": False,
                    "idempotent": not bool(edge.get("side_effects") or edge.get("side_effect")),
                    "parameter_schema_ref": None,
                })
        resource_runtime[runtime_id] = canonical
        return canonical

    # Agent-agent boundaries are not present in the original minimal baseline.
    if "boundary.agent.agent" not in boundary_ids:
        spec["trust_boundaries"].append({
            "id": "boundary.agent.agent",
            "from_zone": "agent_runtime",
            "to_zone": "agent_runtime",
            "metadata": _metadata("Agent-to-Agent Boundary", "Task 2 discovered agent routing boundary."),
            "attributes": {},
        })
        boundary_ids.add("boundary.agent.agent")

    new_edges: list[dict[str, Any]] = []
    used_ids: set[str] = set()
    ignored_private = 0

    for i, edge in enumerate(edges, start=1):
        from_id = str(edge.get("from_id") or "unknown")
        to_id = str(edge.get("to_id") or "unknown")
        from_type = str(edge.get("from_type") or "service")
        target_type = str(edge.get("to_type") or "other")
        if from_id.startswith("_") or to_id.startswith("_"):
            ignored_private += 1
            continue

        caller_id = ensure_subject(from_id, from_type)
        override = _EDGE_OVERRIDES.get((from_id, to_id), {})
        resource_id = str(override.get("resource_id") or ensure_resource(to_id, target_type, edge))
        action = str(override.get("action") or _tool_action(to_id, edge))

        # Ensure the action exists on reused canonical resources.
        resource = next(x for x in spec["resources"] if x["id"] == resource_id)
        if action not in {a["name"] for a in resource.get("actions", [])}:
            resource["actions"].append({
                "name": action,
                "side_effect": bool(edge.get("side_effects") or edge.get("side_effect")),
                "criticality": _criticality(edge),
                "requires_human_approval": False,
                "idempotent": not bool(edge.get("side_effects") or edge.get("side_effect")),
                "parameter_schema_ref": None,
            })

        interface_id = override.get("interface_id")
        if interface_id is None:
            interface_id = ensure_interface(to_id, target_type)

        edge_type = str(edge.get("edge_type") or "")
        if edge_type == "agent_to_agent":
            boundary = "boundary.agent.agent"
            pep_type = "agent_route"
        elif target_type == "api":
            boundary = "boundary.agent.api"
            pep_type = "api"
        elif target_type == "database":
            boundary = "boundary.agent.data"
            pep_type = "data"
        elif interface_id and str(interface_id).startswith("interface.mcp."):
            boundary = "boundary.agent.mcp"
            pep_type = "mcp"
        elif target_type == "tool":
            boundary = None
            pep_type = "tool"
        else:
            boundary = None
            pep_type = "shared_middleware"

        raw_id = _slug(f"scan_{edge.get('edge_id') or i}_{from_id}_{to_id}")
        canonical_edge_id = f"edge.scanner.{raw_id}"
        # interaction id has exactly 3 dot-separated components by schema pattern.
        canonical_edge_id = f"edge.scanner.{raw_id}"
        if canonical_edge_id in used_ids:
            canonical_edge_id = f"edge.scanner.{raw_id}_{i}"
        used_ids.add(canonical_edge_id)

        placement_id = str(override.get("placement_id") or f"pep.scanner.{raw_id}")
        new_edges.append({
            "id": canonical_edge_id,
            "caller_id": caller_id,
            "target_id": resource_id,
            "resource_id": resource_id,
            "action": action,
            "workflow_id": override.get("workflow_id"),
            "interface_id": interface_id,
            "trust_boundary_id": boundary,
            "risk": _risk(edge),
            "data_types": [str(edge.get("data_type"))] if edge.get("data_type") else [],
            "side_effect": bool(edge.get("side_effects") or edge.get("side_effect")),
            "pep": {
                "required": bool(edge.get("pep_required", True)),
                "type": pep_type,
                "mode": "enforce",
                "placement_id": placement_id,
                "fail_mode": "closed" if _risk(edge) in {"high", "critical"} else "open_for_noncritical",
            },
            "metadata": _metadata(
                f"Scanner Edge {from_id} -> {to_id}",
                f"Task 2 discovered {edge_type or 'interaction'} edge.",
                str(edge.get("source", {}).get("reference") or "Task 2 scanner"),
            ),
            "attributes": {
                "task2_edge_id": edge.get("edge_id"),
                "task2_edge_type": edge_type,
                "task2_from_id": from_id,
                "task2_to_id": to_id,
                "task2_operation_class": edge.get("operation_class"),
                "banking_repo": str(banking_repo),
            },
        })

    spec["interactions"] = new_edges
    created["interactions"] = len(new_edges)
    merged["metadata"]["source_revision"] = "task1+task2-runtime-graph-reconciled"

    report = {
        "scanner_edges_input": len(edges),
        "scanner_edges_merged": len(new_edges),
        "ignored_private_helper_edges": ignored_private,
        "scanner_agents": len(agents),
        "scanner_tools": len(tools),
        "scanner_apis": len(apis),
        "scanner_databases": len(databases),
        "created": created,
        "note": "Task 3 interactions now come from Task 2's discovered testbed graph; canonical policy resources are reused for known Citi operations.",
    }
    return merged, report
