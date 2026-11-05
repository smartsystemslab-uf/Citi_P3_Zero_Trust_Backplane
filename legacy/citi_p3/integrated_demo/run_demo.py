from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
SCANNER_ROOT = PROJECT_ROOT / "packages/zt-scanner"
PEP_ROOT = PROJECT_ROOT / "packages" / "zt-pep"
PDP_ROOT = PROJECT_ROOT / "packages/zt-pdp"
LEASE_ROOT = PROJECT_ROOT / "packages/zt-lease"
INTERFACE_ROOT = PROJECT_ROOT / "packages/zt-interface"

for path in (
    PEP_ROOT / "src",
    PDP_ROOT / "src",
    LEASE_ROOT / "src",
    INTERFACE_ROOT / "src",
    PROJECT_ROOT / "packages/zt-psl" / "src",
    HERE,
):
    sys.path.insert(0, str(path))

from native_pdp_bridge import NativePdpInProcessBridge
from reconcile import reconcile_manifest_scanner_to_unified
from scanner_merge import merge_scanner_graph_into_unified
from testbed_runtime import TestbedToolError, TestbedToolRuntime
from real_workflows import (
    ProtectedTestbedRuntime,
    RealWorkflowRunner,
    audit_completeness,
    build_default_workflows,
    build_workflow_policy_bundle,
    required_tool_ids,
    verify_unique_workload_identities,
    workflow_agents,
)
from zt_interface.compiler import compile_pdp
from zt_interface.loader import load_yaml
from zt_interface.validator import validate_manifest as validate_unified_manifest
from zt_pep.compatibility import check_pdp_compatibility
from zt_pep.generator import generate_artifacts
from zt_pep.manifest import validate_manifest as validate_pep_manifest
from zt_pep.placement import build_pep_plan
from zt_lease.models import UnifiedAuthorizationRequest
from zt_lease.service import build_lease_components, register_generated_pep
from zt_lease.pep_adapter import PEPDenied, GeneratedPepAdapter
from zt_pdp.dev_material import dev_key_path
from zt_pdp.psl_translate import bundle_to_psl, rebind_subject
from zt_psl.fields import FieldCatalog
from zt_psl.signing import load_private_key, sign_file


def banner(text: str) -> None:
    print(f"\n{'=' * 78}\n{text}\n{'=' * 78}")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def decode_tool_result(value: Any) -> Any:
    """Decode JSON strings returned by the original Citi ADK tools."""
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text:
        return value
    try:
        return json.loads(text)
    except Exception:
        return value


def require_backend_health(base_url: str) -> dict[str, Any]:
    """Fail clearly before a real transfer if the Citi FastAPI backend is not running."""
    url = base_url.rstrip("/") + "/health"
    try:
        with urllib.request.urlopen(url, timeout=3.0) as response:
            body = response.read().decode("utf-8")
            data = json.loads(body) if body else {}
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "Real backend execution requires the Citi P3 FastAPI backend. "
            f"Health check failed at {url}: {exc}. "
            "Start citi_banking_backend first, then rerun the Backplane."
        ) from exc
    if str(data.get("status", "")).lower() != "ok":
        raise RuntimeError(f"Citi backend health check returned unexpected payload: {data}")
    return data


def selected_placement(plan: dict[str, Any], placement_id: str) -> dict[str, Any]:
    for item in plan["logical_peps"]:
        if item["placement_id"] == placement_id:
            return item
    raise KeyError(placement_id)


def lease_request_from_placement(
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


def prepare_pdp_compatibility_view(output: Path, config_dir: Path) -> Path:
    view = output / "pdp_compatibility_view"
    if view.exists():
        shutil.rmtree(view)
    (view / "config").mkdir(parents=True)
    shutil.copytree(PDP_ROOT / "interface_contract", view / "interface_contract")
    shutil.copytree(PDP_ROOT / "policy_store", view / "policy_store")
    for name in ("identities.yaml", "resources.yaml", "citi_interfaces.yaml"):
        shutil.copy2(config_dir / name, view / "config" / name)
    return view


def _write_signed_psl(policy_path: Path, text: str) -> None:
    """Write a demo-specific PSL policy under output/ and sign it with the DEVELOPMENT key."""
    policy_path.write_text(text, encoding="utf-8")
    sign_file(
        policy_path,
        load_private_key(dev_key_path("policy_private.pem", PDP_ROOT)),
        issuer="policy.prototype",
        key_id="policy-1",
    )


def prepare_real_testbed_policy_store(
    output: Path,
    manifest: dict[str, Any],
    *,
    workflow_bundle: dict[str, Any] | None = None,
) -> Path:
    """Stage signed PDP policies for real-testbed runtime identities.

    Source PDP policies remain untouched. Integration-specific bindings and
    the narrowly-scoped real-workflow bundle are written only under output/.
    """
    policy_dir = output / "pdp_policy_store"
    if policy_dir.exists():
        shutil.rmtree(policy_dir)
    shutil.copytree(PDP_ROOT / "policy_store", policy_dir)

    subject_ids = {item["id"] for item in manifest["spec"].get("subjects", [])}
    ledger_subject = "agent.back_office.ledger_update"
    if ledger_subject in subject_ids:
        ledger_path = policy_dir / "ledger_access.psl"
        text, changed = rebind_subject(
            ledger_path.read_text(encoding="utf-8"),
            ["policy.ledger.eod_approved_update", "policy.ledger.eod_pending_review"],
            "agent.back_office.eod",
            ledger_subject,
        )
        if changed:
            _write_signed_psl(ledger_path, text)
            print(
                "PDP runtime policy binding: agent.back_office.ledger_update "
                "(ledger_update_agent) may request the EOD ledger-update policy."
            )

    if workflow_bundle is not None:
        workflow_path = policy_dir / "real_workflows.psl"
        windows = FieldCatalog.load(policy_dir / "policy_fields.yaml").windows
        _write_signed_psl(
            workflow_path,
            bundle_to_psl(workflow_bundle, windows=windows, source="integrated_demo: build_workflow_policy_bundle"),
        )
        print(
            "Real-workflow runtime policy bundle staged: "
            f"{len(workflow_bundle.get('policies', []))} representative workflow policies."
        )

    return policy_dir


def verify_workflow_trace_correlation(pdp_audit_path: Path, workflow_runs: list[dict[str, Any]]) -> dict[str, Any]:
    expected = {str(item.get("trace_id") or "") for item in workflow_runs if item.get("trace_id")}
    observed: set[str] = set()
    if pdp_audit_path.exists():
        for line in pdp_audit_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            trace_id = str(event.get("trace_id") or "")
            if trace_id in expected:
                observed.add(trace_id)
    return {
        "passed": bool(expected) and observed == expected,
        "expected_trace_ids": sorted(expected),
        "observed_in_pdp_audit": sorted(observed),
        "missing_from_pdp_audit": sorted(expected - observed),
    }


def run(args: argparse.Namespace) -> int:
    output = Path(args.output).resolve()
    if output.exists() and args.clean:
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    banking_repo = Path(args.banking_repo).resolve()

    if args.execute_real_writes or (args.workflow_real_workflows and args.workflow_external_backend):
        os.environ["BANKING_USE_EXTERNAL_API"] = "true"
        os.environ["BANKING_BACKEND_BASE_URL"] = args.banking_backend_url.rstrip("/")
        health = require_backend_health(args.banking_backend_url)
        print(
            "Citi P3 backend preflight: OK -> "
            f"{args.banking_backend_url.rstrip('/')} ({health.get('service', 'banking backend')})"
        )

    banner("UNIFIED INTERFACE — Requirements / system model + unified interface")
    manifest_agents = load_yaml(PROJECT_ROOT / "legacy/citi_p3/manifest_spec" / "manifest" / "agents.yaml")["agents"]
    manifest_tools = load_yaml(PROJECT_ROOT / "legacy/citi_p3/manifest_spec" / "manifest" / "tools.yaml")["tools"]
    manifest_edges = load_yaml(PROJECT_ROOT / "legacy/citi_p3/manifest_spec" / "manifest" / "interaction_edges.yaml")["interaction_edges"]
    baseline_manifest = load_yaml(INTERFACE_ROOT / "examples" / "citi_project_baseline.yaml")
    interface_errors = validate_unified_manifest(baseline_manifest)
    if interface_errors:
        raise RuntimeError("unified baseline invalid: " + "; ".join(interface_errors[:5]))
    print(f"Unified Interface inventory: {len(manifest_agents)} agents, {len(manifest_tools)} tools, {len(manifest_edges)} interaction edges")
    print("Unified interface baseline: VALID")

    banner("STATIC SCANNER — Scan banking source and generate draft ZT-IR")
    scanner_output = output / "scanner" / "draft_manifests"
    command = [
        sys.executable,
        "-m",
        "zt_scanner",
        "--repo-root",
        str(banking_repo),
        "--output-dir",
        str(scanner_output),
    ]
    subprocess.run(command, check=True)
    coverage = load_yaml(scanner_output.parent / "coverage_report.yaml")
    print(json.dumps(coverage, indent=2))

    banner("UNIFIED INTERFACE + 2 -> Unified runtime-binding reconciliation")
    reconciled_manifest = output / "reconciled_manifest.yaml"
    reconciliation_report = output / "manifest_scanner_reconciliation.json"
    report = reconcile_manifest_scanner_to_unified(
        PROJECT_ROOT,
        scanner_output,
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
            f"{item['scanner_runtime_id']}"
        )

    scanner_merge_report = None
    if args.scanner_graph or args.execute_real_tools or args.execute_real_writes or args.workflow_real_workflows:
        banner("STATIC SCANNER -> Unified Interface — Merge the real discovered testbed graph")
        manifest, scanner_merge_report = merge_scanner_graph_into_unified(
            manifest,
            scanner_output,
            banking_repo=banking_repo,
        )
        errors = validate_unified_manifest(manifest)
        if errors:
            raise RuntimeError("scanner-derived unified manifest invalid: " + "; ".join(errors[:8]))
        reconciled_manifest.write_text(
            yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        scanner_report_path = output / "scanner_graph_merge.json"
        scanner_report_path.write_text(
            json.dumps(scanner_merge_report, indent=2, sort_keys=True), encoding="utf-8"
        )
        print(json.dumps(scanner_merge_report, indent=2))
        print(
            "The PEP generator will now consume the static scanner's discovered interaction graph "
            f"({scanner_merge_report['scanner_edges_merged']} merged edges), not the 10-edge baseline fixture."
        )

    banner("PEP GENERATOR — Generate PEP placement plan and adapters")
    pep_schema = PEP_ROOT / "interface_contract" / "schemas" / "zt_manifest.schema.json"
    pep_errors = validate_pep_manifest(manifest, pep_schema)
    if pep_errors:
        raise RuntimeError("PEP generator manifest validation failed: " + "; ".join(pep_errors[:5]))
    plan, updated_manifest = build_pep_plan(manifest)

    pdp_config = output / "pdp_config"
    compile_pdp(manifest, pdp_config)
    compatibility_view = prepare_pdp_compatibility_view(output, pdp_config)
    plan.compatibility = check_pdp_compatibility(
        plan,
        compatibility_view,
        PEP_ROOT / "interface_contract",
    )
    pep_generated = output / "pep_generated"
    generate_artifacts(plan, updated_manifest, pep_generated)
    plan_json = load_json(pep_generated / "generated_pep_plan.json")
    workflow_inputs = load_yaml(Path(args.workflow_inputs).resolve()) if args.workflow_real_workflows else {}
    workflows = build_default_workflows(workflow_inputs) if args.workflow_real_workflows else []
    workflow_policy_bundle = (
        build_workflow_policy_bundle(plan_json, workflows)
        if args.workflow_real_workflows
        else None
    )
    print(json.dumps(plan.coverage, indent=2))
    print("PEP generator / PDP registry compatibility:", plan.compatibility["summary"]["compatible"])

    banner("PDP — Start real in-process signed PDP")
    os.environ["ZT_IDENTITY_FILE"] = str(pdp_config / "identities.yaml")
    os.environ["ZT_RESOURCE_FILE"] = str(pdp_config / "resources.yaml")
    runtime_policy_dir = prepare_real_testbed_policy_store(
        output, manifest, workflow_bundle=workflow_policy_bundle
    )
    os.environ["ZT_POLICY_DIR"] = str(runtime_policy_dir)
    os.environ["ZT_AUDIT_LOG"] = str(output / "pdp_decision_log.jsonl")
    os.environ["ZT_POLICY_VERSION_STORE"] = str(output / "pdp_policy_versions.json")

    from fastapi.testclient import TestClient
    from zt_pdp.pdp_service import build_runtime, create_app

    pdp_runtime = build_runtime()
    pdp_client = TestClient(create_app(pdp_runtime))
    health = pdp_client.get("/health").json()
    print(
        f"PDP healthy: policy_version={health['policy_version']}, "
        f"identities={health['identity_count']}, resources={health['resource_count']}"
    )

    subject_runtime_ids, resource_runtime_ids = build_runtime_maps(manifest)
    bridge = NativePdpInProcessBridge(
        http_client=pdp_client,
        pdp_root=PDP_ROOT,
        subject_runtime_ids=subject_runtime_ids,
        resource_runtime_ids=resource_runtime_ids,
    )

    banner("PERMIT LEASE — Permit Lease / cache safety / revocation integrated with PEP generator + real PDP")
    components = build_lease_components(
        bridge,
        current_policy_version=pdp_runtime.engine.bundle.version,
        normal_ttl_seconds=60,
        critical_ttl_seconds=15,
        normal_max_uses=3,
    )
    fraud_placement = selected_placement(plan_json, "pep.fraud_review.read_history")

    # The baseline fixture models EOD -> ledger as a direct protected operation.
    # The real three-office testbed may insert a dedicated ledger_update_agent, so
    # that exact legacy placement ID is not guaranteed to exist in the scanner graph.
    # Do not spoof/alias that agent just to satisfy the old policy. Instead, use the
    # already policy-covered transfer path for the generic Permit Lease critical-write tests.
    try:
        critical_placement = selected_placement(plan_json, "pep.ledger_update.apply_ledger_updates")
        critical_demo_kind = "ledger"
        print(
            "Permit Lease critical-write fixture: using real testbed identity "
            "ledger_update_agent -> apply_ledger_updates."
        )
    except KeyError:
        try:
            critical_placement = selected_placement(plan_json, "pep.eod_processing.ledger_update")
            critical_demo_kind = "ledger"
        except KeyError:
            critical_placement = selected_placement(plan_json, "pep.customer_transaction.execute_transfer")
            critical_demo_kind = "transfer"
            print(
                "Permit Lease critical-write fixture: no ledger-write placement was discovered; "
                "using the policy-covered execute_transfer path instead."
            )

    pep_keys: dict[str, Ed25519PrivateKey] = {}

    def build_pep(placement: dict[str, Any]) -> GeneratedPepAdapter:
        physical_id = placement["physical_pep_id"]
        key = pep_keys.setdefault(physical_id, Ed25519PrivateKey.generate())
        pep_identity = f"pep://pep/{physical_id}"
        # Same physical PEP may protect multiple logical placements, so registration
        # is idempotent from the demo's perspective.
        try:
            register_generated_pep(components, pep_identity, key)
        except Exception:
            pass
        return GeneratedPepAdapter(
            components.state_machine,
            bridge,
            pep_identity=pep_identity,
            pep_private_key=key,
            idempotency_guard=components.idempotency_guard,
        )

    fraud_pep = build_pep(fraud_placement)
    critical_pep = build_pep(critical_placement)

    results: list[dict[str, Any]] = []

    # Scenario A: normal allow with PDP masking obligation preserved through Permit Lease.
    fraud_request = lease_request_from_placement(
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
    original_call = fraud_pep.pdp_call

    def timeout(_request):
        raise TimeoutError("simulated PDP timeout")

    fraud_pep.pdp_call = timeout
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
    fraud_pep.pdp_call = original_call

    # Scenario E: a critical financial write is blocked without signed approvals.
    if critical_demo_kind == "ledger":
        # Arguments follow the real tool signature apply_ledger_updates(batch_id, posting_instructions);
        # the PSL intent rule apply-ledger-updates-pipeline-gate requires posting_instructions.
        critical_parameters = {
            "batch_id": "batch-77",
            "posting_instructions": "post batch-77 totals",
            "idempotency_key": "idem-critical-77",
            "change_ticket": "CHG-77",
        }
        approved_parameters = {
            "batch_id": "batch-78",
            "posting_instructions": "post batch-78 totals",
            "idempotency_key": "idem-critical-78",
            "change_ticket": "CHG-78",
        }
        workflow_prefix = "eod-demo"
    else:
        # Arguments follow the real tool signature execute_transfer(source_account, destination_account,
        # amount, ...); the PSL intent rule execute-transfer-caller-restriction requires all three.
        critical_parameters = {
            "source_account": "acct-demo-a",
            "destination_account": "acct-demo-b",
            "amount": 100.0,
            "currency": "USD",
            "idempotency_key": "idem-critical-77",
        }
        approved_parameters = dict(critical_parameters)
        approved_parameters["idempotency_key"] = "idem-critical-78"
        workflow_prefix = "transfer-demo"

    critical_request_no_approval = lease_request_from_placement(
        critical_placement,
        parameters=critical_parameters,
        context={"workflow_instance_id": f"{workflow_prefix}-001", "risk_score": 900},
        idempotency_key="idem-critical-77",
    )
    no_approval = critical_pep.authorize(critical_request_no_approval)
    print(
        f"E. Critical {critical_demo_kind} write without approvals: {no_approval.state.value}; "
        f"PDP decision={no_approval.decision.decision.value if no_approval.decision else 'n/a'}"
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
    critical_request = lease_request_from_placement(
        critical_placement,
        parameters=approved_parameters,
        context={
            "workflow_instance_id": f"{workflow_prefix}-002",
            "risk_score": 900,
            "with_human_approval": True,
            "with_secondary_authorization": True,
        },
        idempotency_key="idem-critical-78",
    )
    critical_result = critical_pep.execute(
        critical_request,
        lambda: {"status": "executed", "operation": critical_demo_kind},
    )
    print(f"F. Critical {critical_demo_kind} write with approvals: ALLOW ->", critical_result)
    results.append({"scenario": "critical_approved_update", "passed": critical_result["status"] == "executed"})

    # Scenario G: critical leases are single-use, so they cannot rescue a later PDP outage.
    critical_pep.pdp_call = timeout
    critical_retry = critical_request.model_copy(update={"request_id": "critical-retry-009"})
    critical_timeout = critical_pep.authorize(critical_retry)
    print(
        f"G. Critical retry with PDP down: {critical_timeout.state.value} "
        f"({critical_timeout.reason})"
    )
    results.append({"scenario": "critical_single_use_fail_closed", "passed": not critical_timeout.allowed})

    if args.execute_real_tools:
        banner("REAL THREE-OFFICE TESTBED — Execute original tools behind generated PEPs")
        inputs_path = Path(args.testbed_inputs).resolve()
        real_inputs = load_yaml(inputs_path)
        testbed_runtime = TestbedToolRuntime(banking_repo, scanner_output)
        for office in ("front_office", "mid_office", "back_office"):
            cfg = dict(real_inputs.get(office) or {})
            placement_id = str(cfg.get("placement_id") or "")
            tool_id = str(cfg.get("tool_id") or "")
            parameters = dict(cfg.get("parameters") or {})
            context = dict(cfg.get("context") or {})
            scenario_name = f"real_{office}_tool"
            try:
                placement = selected_placement(plan_json, placement_id)
                pep = build_pep(placement)
                request = lease_request_from_placement(
                    placement,
                    parameters=parameters,
                    context=context,
                    idempotency_key=parameters.get("idempotency_key"),
                )
                value = pep.execute(
                    request,
                    lambda tid=tool_id, params=parameters: testbed_runtime.invoke(tid, params),
                )
                print(f"{office}: REAL TOOL {tool_id} -> ALLOW -> {value}")
                results.append({
                    "scenario": scenario_name,
                    "passed": True,
                    "tool_id": tool_id,
                    "placement_id": placement_id,
                    "result": value,
                })
            except (KeyError, TestbedToolError, PEPDenied, ConnectionError) as exc:
                print(f"{office}: REAL TOOL {tool_id} -> FAIL -> {exc}")
                results.append({
                    "scenario": scenario_name,
                    "passed": False,
                    "tool_id": tool_id,
                    "placement_id": placement_id,
                    "error": str(exc),
                })

    if args.execute_real_writes:
        banner("REAL WRITE OPERATIONS — Protected transfer + protected ledger update")
        real_write_inputs = load_yaml(Path(args.real_write_inputs).resolve())
        testbed_runtime = TestbedToolRuntime(banking_repo, scanner_output)

        for name in ("front_office_transfer", "back_office_ledger_update"):
            cfg = dict(real_write_inputs.get(name) or {})
            placement_id = str(cfg.get("placement_id") or "")
            tool_id = str(cfg.get("tool_id") or "")
            parameters = dict(cfg.get("parameters") or {})
            context = dict(cfg.get("context") or {})
            scenario_name = f"real_write_{name}"
            try:
                placement = selected_placement(plan_json, placement_id)
                pep = build_pep(placement)
                request = lease_request_from_placement(
                    placement,
                    parameters=parameters,
                    context=context,
                    idempotency_key=parameters.get("idempotency_key"),
                )
                raw_value = pep.execute(
                    request,
                    lambda tid=tool_id, params=parameters: testbed_runtime.invoke(tid, params),
                )
                value = decode_tool_result(raw_value)

                if name == "front_office_transfer":
                    passed = (
                        isinstance(value, dict)
                        and bool(value.get("transaction_id"))
                        and value.get("status") not in {None, "backend_error"}
                    )
                else:
                    passed = isinstance(value, dict) and value.get("status") == "ledger_updated"

                print(
                    f"{name}: REAL WRITE {tool_id} -> "
                    f"{'ALLOW + EXECUTED' if passed else 'EXECUTED BUT UNEXPECTED RESULT'} -> {value}"
                )
                results.append({
                    "scenario": scenario_name,
                    "passed": passed,
                    "tool_id": tool_id,
                    "placement_id": placement_id,
                    "result": value,
                })
            except (KeyError, TestbedToolError, PEPDenied, ConnectionError, RuntimeError) as exc:
                print(f"{name}: REAL WRITE {tool_id} -> FAIL -> {exc}")
                results.append({
                    "scenario": scenario_name,
                    "passed": False,
                    "tool_id": tool_id,
                    "placement_id": placement_id,
                    "error": str(exc),
                })

    workflow_report = None
    if args.workflow_real_workflows:
        banner("INTEGRATED WORKFLOW — Full real-testbed workflow integration")
        base_runtime = TestbedToolRuntime(banking_repo, scanner_output)
        protected_runtime = ProtectedTestbedRuntime(base_runtime)
        protected_runtime.install(required_tool_ids(workflows))
        workflow_dir = output / "workflow"
        runner = RealWorkflowRunner(
            plan_json=plan_json,
            build_pep=build_pep,
            request_builder=lease_request_from_placement,
            runtime=protected_runtime,
            output_dir=workflow_dir,
        )
        identity_check = verify_unique_workload_identities(
            plan_json, workflow_agents(workflows)
        )
        print(
            "Real workflows: workload identities: "
            f"{'PASS' if identity_check['passed'] else 'FAIL'} "
            f"({identity_check['checked_agents']} workflow agents checked)"
        )

        workflow_runs = []
        try:
            for workflow in workflows:
                run_result = runner.run_workflow(workflow, mode=args.workflow_mode)
                workflow_runs.append(run_result.__dict__)
                print(
                    f"{workflow.name}: {'PASS' if run_result.passed else 'FAIL'} "
                    f"mode={args.workflow_mode} trace={run_result.trace_id} "
                    f"duration_ms={run_result.duration_ms:.3f}"
                )
                if run_result.error:
                    print(f"  error: {run_result.error}")

            negative_checks = runner.run_negative_tests()
            for check in negative_checks:
                print(
                    f"Real workflows: security check {check['name']}: "
                    f"{'PASS' if check['passed'] else 'FAIL'}"
                )
        finally:
            protected_runtime.restore()

        completeness = audit_completeness(runner.audit_path)
        print(
            "Real workflows: audit completeness: "
            f"{'PASS' if completeness['passed'] else 'FAIL'} "
            f"({completeness['sensitive_event_count']} sensitive records)"
        )
        trace_correlation = verify_workflow_trace_correlation(
            output / "pdp_decision_log.jsonl", workflow_runs
        )
        print(
            "Real workflows: end-to-end trace correlation: "
            f"{'PASS' if trace_correlation['passed'] else 'FAIL'}"
        )
        workflow_passed = (
            identity_check["passed"]
            and all(item["passed"] for item in workflow_runs)
            and all(item["passed"] for item in negative_checks)
            and completeness["passed"]
            and trace_correlation["passed"]
        )
        workflow_report = {
            "passed": workflow_passed,
            "mode": args.workflow_mode,
            "workload_identity_check": identity_check,
            "workflows": workflow_runs,
            "negative_and_mode_checks": negative_checks,
            "audit_completeness": completeness,
            "trace_correlation": trace_correlation,
            "audit_path": str(runner.audit_path),
            "completion_criteria": {
                "all_three_workflows_successful": all(item["passed"] for item in workflow_runs),
                "authorized_requests_complete": all(item["passed"] for item in workflow_runs),
                "unauthorized_requests_blocked": all(
                    item["passed"] for item in negative_checks
                    if item["name"] in {
                        "unauthorized_transfer_blocked",
                        "unauthorized_ledger_update_blocked",
                        "direct_protected_tool_bypass_blocked",
                    }
                ),
                "shadow_mode_supported": any(
                    item["name"] == "shadow_mode_would_block_but_safe_read_continues"
                    and item["passed"]
                    for item in negative_checks
                ),
                "audit_record_complete": completeness["passed"],
                "end_to_end_trace_id": trace_correlation["passed"],
            },
        }
        (workflow_dir / "workflow_report.json").write_text(
            json.dumps(workflow_report, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )
        results.append({"scenario": "workflow_full_real_testbed", "passed": workflow_passed})

    audit_path = output / "lease_audit.json"
    audit_path.write_text(
        json.dumps(components.audit_log.events(), indent=2, sort_keys=True), encoding="utf-8"
    )
    audit_valid = components.audit_log.verify()
    print(f"Permit Lease hash-chained audit valid: {audit_valid}; events={len(components.audit_log.events())}")
    results.append({"scenario": "audit_chain_valid", "passed": audit_valid})

    summary = {
        "all_passed": all(item["passed"] for item in results),
        "results": results,
        "pep_coverage": plan.coverage,
        "pep_pdp_compatible": plan.compatibility["summary"]["compatible"],
        "pdp_policy_version": pdp_runtime.engine.bundle.version,
        "lease_audit_valid": audit_valid,
        "scanner_graph_merge": scanner_merge_report,
        "workflow": workflow_report,
        "artifacts": {
            "scanner": str(scanner_output),
            "reconciled_manifest": str(reconciled_manifest),
            "pep_generated": str(pep_generated),
            "pdp_config": str(pdp_config),
            "pdp_audit": str(output / "pdp_decision_log.jsonl"),
            "lease_audit": str(audit_path),
            "workflow_report": str(output / "workflow" / "workflow_report.json") if workflow_report else None,
            "workflow_audit": str(output / "workflow" / "workflow_audit.jsonl") if workflow_report else None,
        },
    }
    (output / "demo_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )

    banner("DEMO RESULT")
    for item in results:
        print(f"{'PASS' if item['passed'] else 'FAIL'}  {item['scenario']}")
    task_label = "ALL COMPONENTS AND REAL WORKFLOWS INTEGRATED" if args.workflow_real_workflows else "ALL COMPONENTS INTEGRATED"
    print(f"\n{task_label}:", "PASS" if summary["all_passed"] else "FAIL")
    print("Artifacts:", output)
    return 0 if summary["all_passed"] else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the integrated Zero Trust Backplane Unified Interface-6 demo")
    parser.add_argument(
        "--banking-repo",
        default=str(HERE / "sample_banking_system"),
        help="Banking repository scanned by the static scanner. Defaults to the bundled static-analysis fixture.",
    )
    parser.add_argument(
        "--output",
        default=str(HERE / "output"),
        help="Directory for generated demo artifacts.",
    )
    parser.add_argument(
        "--scanner-graph",
        action="store_true",
        help=(
            "Replace the 10-edge baseline interaction fixture with the static scanner's actually discovered "
            "testbed graph before PEP placement."
        ),
    )
    parser.add_argument(
        "--execute-real-tools",
        action="store_true",
        help=(
            "After authorization, invoke the original Front/Mid/Back Office Python tools discovered "
            "by the static scanner. This implies --scanner-graph behavior and may require the banking backend to be running."
        ),
    )
    parser.add_argument(
        "--testbed-inputs",
        default=str(HERE / "testbed_inputs.yaml"),
        help="YAML file containing safe test IDs/parameters for real three-office tool execution.",
    )
    parser.add_argument(
        "--execute-real-writes",
        action="store_true",
        help=(
            "Execute the real protected Front Office transfer and Back Office ledger-update tools. "
            "The Citi FastAPI backend must already be running for execute_transfer."
        ),
    )
    parser.add_argument(
        "--real-write-inputs",
        default=str(HERE / "real_write_inputs.yaml"),
        help="YAML file containing synthetic write-operation parameters for the protected real-write demo.",
    )
    parser.add_argument(
        "--banking-backend-url",
        default=os.getenv("BANKING_BACKEND_BASE_URL", "http://127.0.0.1:8000"),
        help="Citi P3 FastAPI backend base URL used by the real transfer tool.",
    )
    parser.add_argument(
        "--workflow-real-workflows",
        action="store_true",
        help=(
            "Run the three representative real workflows against the original multi-agent "
            "testbed tools behind generated PEP/PDP/Permit-Lease enforcement. Implies scanner-graph merge."
        ),
    )
    parser.add_argument(
        "--workflow-external-backend",
        action="store_true",
        help=(
            "Use the running Citi P3 FastAPI backend for real-workflow customer-transfer execution. "
            "Without this flag the original Citi testbed local repository is used."
        ),
    )
    parser.add_argument(
        "--workflow-inputs",
        default=str(HERE / "workflows.yaml"),
        help="YAML inputs for real-workflow deterministic real-testbed workflow execution.",
    )
    parser.add_argument(
        "--workflow-mode",
        choices=["enforce", "shadow"],
        default="enforce",
        help="real-workflow mode. The built-in M6 checks also exercise safe shadow behavior.",
    )
    parser.add_argument("--clean", action="store_true", help="Delete the output directory before running")
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(run(parse_args()))
