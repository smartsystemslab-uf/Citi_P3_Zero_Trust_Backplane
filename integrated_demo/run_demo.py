from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
TASK2_ROOT = PROJECT_ROOT / "zero_trust_task2"
TASK3_ROOT = PROJECT_ROOT / "Zero_Trust_Task3_PEP_Integrated" / "zero_trust_pep_task3_integrated"
TASK4_ROOT = PROJECT_ROOT / "zero_trust_pdp_task4_secure"
TASK5_ROOT = PROJECT_ROOT / "zero_trust_task5"
INTERFACE_ROOT = PROJECT_ROOT / "interface_standard"

for path in (
    TASK3_ROOT / "src",
    TASK4_ROOT / "src",
    TASK5_ROOT / "src",
    INTERFACE_ROOT / "src",
    HERE,
):
    sys.path.insert(0, str(path))

from native_task4_bridge import NativeTask4InProcessBridge
from reconcile import reconcile_task1_task2_to_unified
from zt_interface.compiler import compile_task4
from zt_interface.loader import load_yaml
from zt_interface.validator import validate_manifest as validate_unified_manifest
from zt_pep.compatibility import check_task4_compatibility
from zt_pep.generator import generate_artifacts
from zt_pep.manifest import validate_manifest as validate_task3_manifest
from zt_pep.placement import build_pep_plan
from zt_task5.models import UnifiedAuthorizationRequest
from zt_task5.service import build_task5_components, register_generated_pep
from zt_task5.task3_adapter import PEPDenied, Task3PEPAdapter


def banner(text: str) -> None:
    print(f"\n{'=' * 78}\n{text}\n{'=' * 78}")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def selected_placement(plan: dict[str, Any], placement_id: str) -> dict[str, Any]:
    for item in plan["logical_peps"]:
        if item["placement_id"] == placement_id:
            return item
    raise KeyError(placement_id)


def task5_request_from_placement(
    placement: dict[str, Any],
    *,
    parameters: dict[str, Any],
    context: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> UnifiedAuthorizationRequest:
    return UnifiedAuthorizationRequest(
        subject=placement["subject_canonical_id"],
        resource=placement["resource_canonical_id"],
        action=placement["action"],
        workflow_id=placement.get("workflow_id") or "",
        audience=placement.get("interface_id") or placement.get("physical_pep_id") or "local-data-plane",
        endpoint=placement.get("interface_id") or placement["resource_canonical_id"],
        critical=bool(placement.get("critical")),
        risk=str(placement.get("risk") or "low"),
        parameters=parameters,
        context=context or {},
        idempotency_key=idempotency_key,
    )


def build_runtime_maps(manifest: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    environment = manifest["spec"]["defaults"]["environment_binding"]
    subjects = {}
    resources = {}
    for item in manifest["spec"].get("subjects", []):
        runtime = item.get("bindings", {}).get(environment, {}).get("runtime_id")
        if runtime:
            subjects[item["id"]] = str(runtime)
    for item in manifest["spec"].get("resources", []):
        runtime = item.get("bindings", {}).get(environment, {}).get("runtime_id")
        if runtime:
            resources[item["id"]] = str(runtime)
    return subjects, resources


def prepare_task4_compatibility_view(output: Path, config_dir: Path) -> Path:
    view = output / "task4_compatibility_view"
    if view.exists():
        shutil.rmtree(view)
    (view / "config").mkdir(parents=True)
    shutil.copytree(TASK4_ROOT / "interface_contract", view / "interface_contract")
    shutil.copytree(TASK4_ROOT / "policy_store", view / "policy_store")
    for name in ("identities.yaml", "resources.yaml", "citi_interfaces.yaml"):
        shutil.copy2(config_dir / name, view / "config" / name)
    return view


def run(args: argparse.Namespace) -> int:
    output = Path(args.output).resolve()
    if output.exists() and args.clean:
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    banking_repo = Path(args.banking_repo).resolve()

    banner("TASK 1 — Requirements / system model + unified interface")
    task1_agents = load_yaml(PROJECT_ROOT / "zero_trust_task1" / "manifest" / "agents.yaml")["agents"]
    task1_tools = load_yaml(PROJECT_ROOT / "zero_trust_task1" / "manifest" / "tools.yaml")["tools"]
    task1_edges = load_yaml(PROJECT_ROOT / "zero_trust_task1" / "manifest" / "interaction_edges.yaml")["interaction_edges"]
    baseline_manifest = load_yaml(INTERFACE_ROOT / "examples" / "citi_project_baseline.yaml")
    interface_errors = validate_unified_manifest(baseline_manifest)
    if interface_errors:
        raise RuntimeError("unified baseline invalid: " + "; ".join(interface_errors[:5]))
    print(f"Task 1 inventory: {len(task1_agents)} agents, {len(task1_tools)} tools, {len(task1_edges)} interaction edges")
    print("Unified interface baseline: VALID")

    banner("TASK 2 — Scan banking source and generate draft ZT-IR")
    task2_output = output / "task2" / "draft_manifests"
    command = [
        sys.executable,
        str(TASK2_ROOT / "zt_scan.py"),
        "--repo-root",
        str(banking_repo),
        "--output-dir",
        str(task2_output),
    ]
    subprocess.run(command, check=True)
    coverage = load_yaml(task2_output.parent / "coverage_report.yaml")
    print(json.dumps(coverage, indent=2))

    banner("TASK 1 + 2 -> Unified runtime-binding reconciliation")
    reconciled_manifest = output / "reconciled_manifest.yaml"
    reconciliation_report = output / "task1_task2_reconciliation.json"
    report = reconcile_task1_task2_to_unified(
        PROJECT_ROOT,
        task2_output,
        reconciled_manifest,
        reconciliation_report,
    )
    manifest = load_yaml(reconciled_manifest)
    errors = validate_unified_manifest(manifest)
    if errors:
        raise RuntimeError("reconciled unified manifest invalid: " + "; ".join(errors[:5]))
    print(f"Reconciled runtime bindings: {report['verified_count']} verified; unified manifest VALID")
    for item in report["checks"]:
        print(
            f"  {item['canonical_id']}: {item.get('previous_runtime_id')} -> "
            f"{item['task2_runtime_id']}"
        )

    banner("TASK 3 — Generate PEP placement plan and adapters")
    task3_schema = TASK3_ROOT / "interface_contract" / "schemas" / "zt_manifest.schema.json"
    task3_errors = validate_task3_manifest(manifest, task3_schema)
    if task3_errors:
        raise RuntimeError("Task 3 manifest validation failed: " + "; ".join(task3_errors[:5]))
    plan, updated_manifest = build_pep_plan(manifest)

    task4_config = output / "task4_config"
    compile_task4(manifest, task4_config)
    compatibility_view = prepare_task4_compatibility_view(output, task4_config)
    plan.compatibility = check_task4_compatibility(
        plan,
        compatibility_view,
        TASK3_ROOT / "interface_contract",
    )
    task3_generated = output / "task3_generated"
    generate_artifacts(plan, updated_manifest, task3_generated)
    print(json.dumps(plan.coverage, indent=2))
    print("Task 3 / Task 4 registry compatibility:", plan.compatibility["summary"]["compatible"])

    banner("TASK 4 — Start real in-process signed PDP")
    os.environ["ZT_IDENTITY_FILE"] = str(task4_config / "identities.yaml")
    os.environ["ZT_RESOURCE_FILE"] = str(task4_config / "resources.yaml")
    os.environ["ZT_AUDIT_LOG"] = str(output / "task4_decision_log.jsonl")
    os.environ["ZT_POLICY_VERSION_STORE"] = str(output / "task4_policy_versions.json")

    from fastapi.testclient import TestClient
    from zt_backplane.pdp_service import build_runtime, create_app

    task4_runtime = build_runtime()
    task4_client = TestClient(create_app(task4_runtime))
    health = task4_client.get("/health").json()
    print(
        f"Task 4 PDP healthy: policy_version={health['policy_version']}, "
        f"identities={health['identity_count']}, resources={health['resource_count']}"
    )

    subject_runtime_ids, resource_runtime_ids = build_runtime_maps(manifest)
    bridge = NativeTask4InProcessBridge(
        http_client=task4_client,
        task4_root=TASK4_ROOT,
        subject_runtime_ids=subject_runtime_ids,
        resource_runtime_ids=resource_runtime_ids,
    )

    banner("TASK 5 — Permit Lease / cache safety / revocation integrated with Task 3 + real Task 4")
    components = build_task5_components(
        bridge,
        current_policy_version=task4_runtime.engine.bundle.version,
        normal_ttl_seconds=60,
        critical_ttl_seconds=15,
        normal_max_uses=3,
    )
    plan_json = load_json(task3_generated / "generated_pep_plan.json")
    fraud_placement = selected_placement(plan_json, "pep.fraud_review.read_history")
    ledger_placement = selected_placement(plan_json, "pep.eod_processing.ledger_update")

    pep_keys: dict[str, Ed25519PrivateKey] = {}

    def build_pep(placement: dict[str, Any]) -> Task3PEPAdapter:
        physical_id = placement["physical_pep_id"]
        key = pep_keys.setdefault(physical_id, Ed25519PrivateKey.generate())
        pep_identity = f"pep://task3/{physical_id}"
        # Same physical PEP may protect multiple logical placements, so registration
        # is idempotent from the demo's perspective.
        try:
            register_generated_pep(components, pep_identity, key)
        except Exception:
            pass
        return Task3PEPAdapter(
            components.state_machine,
            bridge,
            pep_identity=pep_identity,
            pep_private_key=key,
            idempotency_guard=components.idempotency_guard,
        )

    fraud_pep = build_pep(fraud_placement)
    ledger_pep = build_pep(ledger_placement)

    results: list[dict[str, Any]] = []

    # Scenario A: normal allow with Task 4 masking obligation preserved through Task 5.
    fraud_request = task5_request_from_placement(
        fraud_placement,
        parameters={"transaction_id": "tx-100"},
        context={"workflow_instance_id": "fraud-demo-001", "risk_score": 350},
    )
    masked = fraud_pep.execute(
        fraud_request,
        lambda: {
            "transaction_id": "tx-100",
            "full_account_number": "123456789",
            "ssn": "111-22-3333",
            "amount": 100.0,
        },
    )
    print("A. Fraud read: ALLOW; data masking applied ->", masked)
    results.append({"scenario": "fraud_read_allow_mask", "passed": masked["ssn"] == "***MASKED***"})

    # Scenario B: exact noncritical retry may use the bounded cached lease during PDP timeout.
    original_call = fraud_pep.task4_call

    def timeout(_request):
        raise TimeoutError("simulated PDP timeout")

    fraud_pep.task4_call = timeout
    retry = fraud_request.model_copy(update={"request_id": "fraud-retry-002"})
    cached = fraud_pep.authorize(retry)
    print(f"B. Exact retry during PDP timeout: {cached.state.value} via {cached.source}")
    results.append({"scenario": "timeout_exact_cached_lease", "passed": cached.allowed and cached.source == "CACHE"})

    # Scenario C: parameter modification cannot reuse that lease.
    modified = fraud_request.model_copy(
        update={"request_id": "fraud-modified-003", "parameters": {"transaction_id": "tx-999"}}
    )
    denied = fraud_pep.authorize(modified)
    print(f"C. Modified request during PDP timeout: {denied.state.value} ({denied.reason})")
    results.append({"scenario": "modified_request_rejected", "passed": not denied.allowed})

    # Scenario D: PEP restart clears cache and disables fallback until fresh PDP synchronization.
    components.lease_cache.restart()
    after_restart = fraud_pep.authorize(retry)
    print(f"D. After PEP restart with PDP down: {after_restart.state.value} ({after_restart.reason})")
    results.append({"scenario": "restart_clears_cache", "passed": not after_restart.allowed})
    fraud_pep.task4_call = original_call

    # Scenario E: critical ledger update is blocked without signed approvals.
    ledger_request_no_approval = task5_request_from_placement(
        ledger_placement,
        parameters={
            "batch_id": "batch-77",
            "idempotency_key": "idem-ledger-77",
            "change_ticket": "CHG-77",
        },
        context={"workflow_instance_id": "eod-demo-001", "risk_score": 900},
        idempotency_key="idem-ledger-77",
    )
    no_approval = ledger_pep.authorize(ledger_request_no_approval)
    print(
        f"E. Ledger update without approvals: {no_approval.state.value}; "
        f"Task 4 decision={no_approval.decision.decision.value if no_approval.decision else 'n/a'}"
    )
    results.append(
        {
            "scenario": "critical_manual_review",
            "passed": (not no_approval.allowed)
            and bool(no_approval.decision)
            and no_approval.decision.decision.value == "MANUAL_REVIEW",
        }
    )

    # Scenario F: signed approval + independent authorization + obligations -> allowed once.
    ledger_request = task5_request_from_placement(
        ledger_placement,
        parameters={
            "batch_id": "batch-78",
            "idempotency_key": "idem-ledger-78",
            "change_ticket": "CHG-78",
        },
        context={
            "workflow_instance_id": "eod-demo-002",
            "risk_score": 900,
            "with_human_approval": True,
            "with_secondary_authorization": True,
        },
        idempotency_key="idem-ledger-78",
    )
    ledger_result = ledger_pep.execute(ledger_request, lambda: {"ledger": "updated", "batch_id": "batch-78"})
    print("F. Ledger update with approvals: ALLOW ->", ledger_result)
    results.append({"scenario": "critical_approved_update", "passed": ledger_result["ledger"] == "updated"})

    # Scenario G: critical leases are single-use, so they cannot rescue a later PDP outage.
    ledger_pep.task4_call = timeout
    critical_retry = ledger_request.model_copy(update={"request_id": "ledger-retry-009"})
    critical_timeout = ledger_pep.authorize(critical_retry)
    print(
        f"G. Critical retry with PDP down: {critical_timeout.state.value} "
        f"({critical_timeout.reason})"
    )
    results.append({"scenario": "critical_single_use_fail_closed", "passed": not critical_timeout.allowed})

    audit_path = output / "task5_audit.json"
    audit_path.write_text(
        json.dumps(components.audit_log.events(), indent=2, sort_keys=True), encoding="utf-8"
    )
    audit_valid = components.audit_log.verify()
    print(f"Task 5 hash-chained audit valid: {audit_valid}; events={len(components.audit_log.events())}")
    results.append({"scenario": "audit_chain_valid", "passed": audit_valid})

    summary = {
        "all_passed": all(item["passed"] for item in results),
        "results": results,
        "task3_coverage": plan.coverage,
        "task3_task4_compatible": plan.compatibility["summary"]["compatible"],
        "task4_policy_version": task4_runtime.engine.bundle.version,
        "task5_audit_valid": audit_valid,
        "artifacts": {
            "task2": str(task2_output),
            "reconciled_manifest": str(reconciled_manifest),
            "task3_generated": str(task3_generated),
            "task4_config": str(task4_config),
            "task4_audit": str(output / "task4_decision_log.jsonl"),
            "task5_audit": str(audit_path),
        },
    }
    (output / "demo_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )

    banner("DEMO RESULT")
    for item in results:
        print(f"{'PASS' if item['passed'] else 'FAIL'}  {item['scenario']}")
    print("\nALL TASKS 1-5 INTEGRATED:", "PASS" if summary["all_passed"] else "FAIL")
    print("Artifacts:", output)
    return 0 if summary["all_passed"] else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the integrated Zero Trust Backplane Task 1-5 demo")
    parser.add_argument(
        "--banking-repo",
        default=str(HERE / "sample_banking_system"),
        help="Banking repository scanned by Task 2. Defaults to the bundled static-analysis fixture.",
    )
    parser.add_argument(
        "--output",
        default=str(HERE / "output"),
        help="Directory for generated demo artifacts.",
    )
    parser.add_argument("--clean", action="store_true", help="Delete the output directory before running")
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(run(parse_args()))
