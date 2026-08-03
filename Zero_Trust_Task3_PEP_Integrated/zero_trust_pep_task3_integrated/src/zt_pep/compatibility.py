from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml

from .models import PEPPlan


def _load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(value, dict):
        raise ValueError(f"YAML root must be mapping: {path}")
    return value


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_task4_compatibility(plan: PEPPlan, task4_root: str | Path, interface_contract: str | Path) -> dict[str, Any]:
    root = Path(task4_root).resolve()
    interface_root = Path(interface_contract).resolve()
    task4_schema_root = root / "interface_contract" / "schemas"
    local_schema_root = interface_root / "schemas"

    schema_names = ["pdp_request.schema.json", "pdp_response.schema.json", "audit_event.schema.json", "zt_manifest.schema.json"]
    schema_checks = []
    for name in schema_names:
        left = local_schema_root / name
        right = task4_schema_root / name
        schema_checks.append(
            {
                "schema": name,
                "task3_sha256": _sha(left) if left.exists() else None,
                "task4_sha256": _sha(right) if right.exists() else None,
                "match": bool(left.exists() and right.exists() and _sha(left) == _sha(right)),
            }
        )

    identities_raw = _load_yaml(root / "config" / "identities.yaml")
    resources_raw = _load_yaml(root / "config" / "resources.yaml")
    identities = {item["canonical_id"]: item for item in identities_raw.get("identities", [])}
    resources = {item["canonical_id"]: item for item in resources_raw.get("resources", [])}

    policy_files = sorted((root / "policy_store").glob("*.yaml"))
    policies: list[dict[str, Any]] = []
    for source in policy_files:
        bundle = _load_yaml(source)
        for policy in bundle.get("policies", []):
            policies.append({**policy, "_source": source.name})

    edge_checks = []
    for pep in plan.logical_peps:
        identity = identities.get(pep.subject_canonical_id)
        resource = resources.get(pep.resource_canonical_id)
        candidate_policies = []
        for policy in policies:
            match = policy.get("match", {})
            if match.get("subjects") and pep.subject_canonical_id not in match["subjects"]:
                continue
            if match.get("resources") and pep.resource_canonical_id not in match["resources"]:
                continue
            if match.get("actions") and pep.action not in match["actions"]:
                continue
            if match.get("workflows") and pep.workflow_id not in match["workflows"]:
                continue
            candidate_policies.append(policy.get("id"))
        edge_checks.append(
            {
                "placement_id": pep.placement_id,
                "edge_id": pep.edge_id,
                "identity_present": identity is not None,
                "identity_runtime_matches": bool(identity and identity.get("id") == pep.subject_runtime_id),
                "resource_present": resource is not None,
                "resource_runtime_matches": bool(resource and resource.get("id") == pep.resource_runtime_id),
                "action_present": bool(resource and pep.action in resource.get("actions", [])),
                "candidate_policy_ids": candidate_policies,
                "expected_if_no_policy": "DENY (Task 4 default-deny)",
            }
        )

    all_schema_match = all(item["match"] for item in schema_checks)
    all_registry_match = all(
        item["identity_present"]
        and item["identity_runtime_matches"]
        and item["resource_present"]
        and item["resource_runtime_matches"]
        and item["action_present"]
        for item in edge_checks
    )
    return {
        "task4_package": root.name,
        "schema_checks": schema_checks,
        "edge_registry_checks": edge_checks,
        "summary": {
            "interface_schemas_match": all_schema_match,
            "all_pep_requests_resolve_in_task4_registry": all_registry_match,
            "compatible": all_schema_match and all_registry_match,
            "note": (
                "Compatibility means Task 4 accepts the canonical request contract and can return a policy decision. "
                "Edges without a candidate allow policy are intentionally denied by Task 4 default-deny."
            ),
        },
    }
