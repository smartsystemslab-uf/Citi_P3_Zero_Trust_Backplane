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


def reconcile_manifest_scanner_to_unified(
    project_root: Path,
    scanner_output: Path,
    output_manifest: Path,
    report_path: Path,
) -> dict[str, Any]:
    """Reconcile Unified Interface legacy names and static scanner discoveries into the unified manifest.

    The project already contains a canonical unified baseline. This function does
    not invent a second schema. It verifies selected runtime bindings against both
    Unified Interface and static scanner, updates only the environment bindings, and leaves canonical
    IDs/policy IDs unchanged for PEP generator/4/5.
    """

    baseline = _load(project_root / "packages/zt-interface" / "examples" / "citi_project_baseline.yaml")
    binding_map = _load(project_root / "legacy/citi_p3/integrated_demo" / "manifest_bindings.yaml")

    manifest_root = project_root / "legacy/citi_p3/manifest_spec" / "manifest"
    manifest_agents = _index(_load(manifest_root / "agents.yaml")["agents"], "agent_id")
    manifest_tools = _index(_load(manifest_root / "tools.yaml")["tools"], "tool_id")
    manifest_databases = _load(manifest_root / "databases.yaml")["databases"]
    manifest_tables = {str(item.get("table_name")): item for item in manifest_databases}

    scanner_agents = _index(_load(scanner_output / "agents_draft.yaml")["agents"], "agent_id")
    scanner_tools = _index(_load(scanner_output / "tools_draft.yaml")["tools"], "tool_id")
    scanner_databases = _load(scanner_output / "databases_draft.yaml")["databases"]
    scanner_tables = {str(item.get("table_name")): item for item in scanner_databases}

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
        manifest_id = str(mapping["manifest_id"])
        manifest_present = manifest_id in manifest_agents
        scanner_present = runtime_id in scanner_agents
        if not manifest_present or not scanner_present:
            raise RuntimeError(
                f"subject binding {canonical_id} failed reconciliation: "
                f"manifest={manifest_present}, scanner={scanner_present}"
            )
        record = collections["subjects"][canonical_id]
        old_runtime = record["bindings"][environment].get("runtime_id")
        record["bindings"][environment]["runtime_id"] = runtime_id
        record["metadata"]["source"]["notes"] = "Runtime binding verified by the static scanner demo scan."
        checks.append(
            {
                "type": "subject",
                "canonical_id": canonical_id,
                "manifest_id": manifest_id,
                "scanner_runtime_id": runtime_id,
                "previous_runtime_id": old_runtime,
                "status": "verified",
            }
        )

    for canonical_id, mapping in binding_map.get("interfaces", {}).items():
        runtime_id = str(mapping["discovered_runtime_id"])
        manifest_id = str(mapping["manifest_id"])
        manifest_present = manifest_id in manifest_tools
        scanner_present = runtime_id in scanner_tools
        if not manifest_present or not scanner_present:
            raise RuntimeError(
                f"interface binding {canonical_id} failed reconciliation: "
                f"manifest={manifest_present}, scanner={scanner_present}"
            )
        record = collections["interfaces"][canonical_id]
        old_runtime = record["bindings"][environment].get("runtime_id")
        record["bindings"][environment]["runtime_id"] = runtime_id
        record["bindings"][environment]["function_name"] = runtime_id
        record["metadata"]["source"]["notes"] = "Runtime binding verified by the static scanner demo scan."
        checks.append(
            {
                "type": "interface",
                "canonical_id": canonical_id,
                "manifest_id": manifest_id,
                "scanner_runtime_id": runtime_id,
                "previous_runtime_id": old_runtime,
                "status": "verified",
            }
        )

    for canonical_id, mapping in binding_map.get("resources", {}).items():
        runtime_id = str(mapping["discovered_runtime_id"])
        manifest_table = str(mapping["manifest_table_name"])
        manifest_present = manifest_table in manifest_tables
        scanner_present = runtime_id in scanner_tables
        if not manifest_present or not scanner_present:
            raise RuntimeError(
                f"resource binding {canonical_id} failed reconciliation: "
                f"manifest={manifest_present}, scanner={scanner_present}"
            )
        record = collections["resources"][canonical_id]
        old_runtime = record["bindings"][environment].get("runtime_id")
        record["bindings"][environment]["runtime_id"] = runtime_id
        record["metadata"]["source"]["notes"] = "Runtime data binding verified by the static scanner demo scan."
        checks.append(
            {
                "type": "resource",
                "canonical_id": canonical_id,
                "manifest_table": manifest_table,
                "scanner_runtime_id": runtime_id,
                "previous_runtime_id": old_runtime,
                "status": "verified",
            }
        )

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    manifest["metadata"]["updated_at"] = now
    manifest["metadata"]["source_revision"] = "manifest+scanner-demo-reconciled"

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
            "Canonical IDs remain unchanged. The static scanner only verifies/updates runtime bindings; "
            "PEP generator/4/5 consume the canonical unified interface."
        ),
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return report
