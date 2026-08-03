from __future__ import annotations

from pathlib import Path

from zt_pep.manifest import validate_manifest
from zt_pep.placement import build_pep_plan


ROOT = Path(__file__).resolve().parents[1]


def test_baseline_validates_against_unchanged_interface_schema(manifest):
    errors = validate_manifest(manifest, ROOT / "interface_contract" / "schemas" / "zt_manifest.schema.json")
    assert errors == []


def test_sensitive_known_paths_have_full_coverage(manifest):
    plan, updated = build_pep_plan(manifest)
    assert plan.coverage["sensitive_path_coverage_percent"] == 100.0
    assert plan.coverage["known_direct_bypass_paths"] == 0
    assert plan.coverage["logical_pep_count"] == len(manifest["spec"]["interactions"])
    assert plan.coverage["physical_pep_count"] < plan.coverage["logical_pep_count"]
    assert all(edge["pep"]["placement_id"] for edge in updated["spec"]["interactions"])


def test_task4_canonical_request_fields_are_preserved(manifest):
    plan, _ = build_pep_plan(manifest)
    placement = next(item for item in plan.logical_peps if item.edge_id == "edge.fraud_review.read_history")
    assert placement.subject_canonical_id == "agent.front_office.fraud"
    assert placement.subject_runtime_id == "fraud_agent"
    assert placement.resource_canonical_id == "resource.front_office.transaction_history"
    assert placement.resource_runtime_id == "transaction_history"
    assert placement.action == "read"
    assert placement.workflow_id == "workflow.front_office.fraud_review"
    assert placement.pep_type == "data"


def test_unmapped_sensitive_resources_are_reported_not_falsely_claimed(manifest):
    plan, _ = build_pep_plan(manifest)
    unmapped = plan.coverage["sensitive_inventory_resources_without_discovered_edges"]
    assert isinstance(unmapped, list)
    assert all(
        finding.category == "scanner_coverage_gap" and not finding.blocks_milestone
        for finding in plan.findings
        if finding.resource_id in unmapped
    )
