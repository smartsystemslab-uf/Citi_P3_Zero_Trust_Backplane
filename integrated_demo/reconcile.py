from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


def _load(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(value, dict):
        raise ValueError(f"expected mapping in {path}")
    return value


def _index(items: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    return {str(item[key]): item for item in items if item.get(key) is not None}


def reconcile_task1_task2_to_unified(
    project_root: Path,
    scanner_output: Path,
    output_manifest: Path,
    report_path: Path,
) -> dict[str, Any]:
    """Reconcile Task 1 legacy names and Task 2 discoveries into the unified manifest.

    The project already contains a canonical unified baseline. This function does
    not invent a second schema. It verifies selected runtime bindings against both
    Task 1 and Task 2, updates only the environment bindings, and leaves canonical
    IDs/policy IDs unchanged for Task 3/4/5.
    """

    baseline = _load(project_root / "interface_standard" / "examples" / "citi_project_baseline.yaml")
    binding_map = _load(project_root / "integrated_demo" / "task1_unified_bindings.yaml")

    task1_root = project_root / "zero_trust_task1" / "manifest"
    task1_agents = _index(_load(task1_root / "agents.yaml")["agents"], "agent_id")
    task1_tools = _index(_load(task1_root / "tools.yaml")["tools"], "tool_id")
    task1_databases = _load(task1_root / "databases.yaml")["databases"]
    task1_tables = {str(item.get("table_name")): item for item in task1_databases}

    task2_agents = _index(_load(scanner_output / "agents_draft.yaml")["agents"], "agent_id")
    task2_tools = _index(_load(scanner_output / "tools_draft.yaml")["tools"], "tool_id")
    task2_databases = _load(scanner_output / "databases_draft.yaml")["databases"]
    task2_tables = {str(item.get("table_name")): item for item in task2_databases}

    manifest = copy.deepcopy(baseline)
    environment = manifest["spec"]["defaults"]["environment_binding"]
    collections = {
        "subjects": {item["id"]: item for item in manifest["spec"]["subjects"]},
        "interfaces": {item["id"]: item for item in manifest["spec"]["interfaces"]},
        "resources": {item["id"]: item for item in manifest["spec"]["resources"]},
    }

    checks: list[dict[str, Any]] = []

    for canonical_id, mapping in binding_map.get("subjects", {}).items():
        runtime_id = str(mapping["discovered_runtime_id"])
        task1_id = str(mapping["task1_id"])
        task1_present = task1_id in task1_agents
        task2_present = runtime_id in task2_agents
        if not task1_present or not task2_present:
            raise RuntimeError(
                f"subject binding {canonical_id} failed reconciliation: "
                f"task1={task1_present}, task2={task2_present}"
            )
        record = collections["subjects"][canonical_id]
        old_runtime = record["bindings"][environment].get("runtime_id")
        record["bindings"][environment]["runtime_id"] = runtime_id
        record["metadata"]["source"]["notes"] = "Runtime binding verified by Task 2 demo scan."
        checks.append(
            {
                "type": "subject",
                "canonical_id": canonical_id,
                "task1_id": task1_id,
                "task2_runtime_id": runtime_id,
                "previous_runtime_id": old_runtime,
                "status": "verified",
            }
        )

    for canonical_id, mapping in binding_map.get("interfaces", {}).items():
        runtime_id = str(mapping["discovered_runtime_id"])
        task1_id = str(mapping["task1_id"])
        task1_present = task1_id in task1_tools
        task2_present = runtime_id in task2_tools
        if not task1_present or not task2_present:
            raise RuntimeError(
                f"interface binding {canonical_id} failed reconciliation: "
                f"task1={task1_present}, task2={task2_present}"
            )
        record = collections["interfaces"][canonical_id]
        old_runtime = record["bindings"][environment].get("runtime_id")
        record["bindings"][environment]["runtime_id"] = runtime_id
        record["bindings"][environment]["function_name"] = runtime_id
        record["metadata"]["source"]["notes"] = "Runtime binding verified by Task 2 demo scan."
        checks.append(
            {
                "type": "interface",
                "canonical_id": canonical_id,
                "task1_id": task1_id,
                "task2_runtime_id": runtime_id,
                "previous_runtime_id": old_runtime,
                "status": "verified",
            }
        )

    for canonical_id, mapping in binding_map.get("resources", {}).items():
        runtime_id = str(mapping["discovered_runtime_id"])
        task1_table = str(mapping["task1_table_name"])
        task1_present = task1_table in task1_tables
        task2_present = runtime_id in task2_tables
        if not task1_present or not task2_present:
            raise RuntimeError(
                f"resource binding {canonical_id} failed reconciliation: "
                f"task1={task1_present}, task2={task2_present}"
            )
        record = collections["resources"][canonical_id]
        old_runtime = record["bindings"][environment].get("runtime_id")
        record["bindings"][environment]["runtime_id"] = runtime_id
        record["metadata"]["source"]["notes"] = "Runtime data binding verified by Task 2 demo scan."
        checks.append(
            {
                "type": "resource",
                "canonical_id": canonical_id,
                "task1_table": task1_table,
                "task2_runtime_id": runtime_id,
                "previous_runtime_id": old_runtime,
                "status": "verified",
            }
        )

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    manifest["metadata"]["updated_at"] = now
    manifest["metadata"]["source_revision"] = "task1+task2-demo-reconciled"

    output_manifest.parent.mkdir(parents=True, exist_ok=True)
    output_manifest.write_text(
        yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )
    report = {
        "generated_at": now,
        "environment": environment,
        "checks": checks,
        "verified_count": len(checks),
        "status": "PASS",
        "note": (
            "Canonical IDs remain unchanged. Task 2 only verifies/updates runtime bindings; "
            "Task 3/4/5 consume the canonical unified interface."
        ),
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return report
