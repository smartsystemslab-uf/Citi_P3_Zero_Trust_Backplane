"""intent.no-cross-domain-transfers, enforced on the real MAS graph by the native runtime.

The rule was disabled while the Task 2 scanner put the factory-built mid-office workflow agents
into domain 'shared' (13 legitimate routes would have been denied). With the corrected domain
inference it is enabled; these tests use the REAL bootstrap (Task 2 scan of the MAS, Task 3
placements, signed PSL store, in-process Task 4 PDP) plus the agent-tree edges the ADK plugin
passes at start-up, and check both directions: no legitimate route is refused by the rule, and a
cross-domain route is. Skipped if the MAS repository is not available.
"""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest

BACKPLANE = Path(__file__).resolve().parents[2]
# The Citi_P3 checkout (read only: the static scan never writes into it). CITI_MAS_REPO overrides
# the default location next to this repository.
MAS_ROOT = Path(os.environ.get("CITI_MAS_REPO") or BACKPLANE.parent / "Citi_P3")
RULE = "intent.no-cross-domain-transfers"

# The instantiated ADK tree of citi_banking_adk (bank_adk.agents.root.build_root_agent(), walked
# over sub_agents exactly as bank_adk/zero_trust/plugin.py does), captured 2026-11-03.
REAL_TREE_EDGES = [
    ("user_proxy_agent", "front_office_router"),
    ("front_office_router", "front_office_transaction_workflow"),
    ("front_office_transaction_workflow", "transaction_monitoring_agent"),
    ("front_office_transaction_workflow", "fraud_detection_agent"),
    ("front_office_transaction_workflow", "compliance_agent"),
    ("front_office_transaction_workflow", "decision_making_agent"),
    ("front_office_router", "customer_service_chatbot_workflow"),
    ("customer_service_chatbot_workflow", "chatbot_intent_agent"),
    ("customer_service_chatbot_workflow", "knowledge_base_agent"),
    ("customer_service_chatbot_workflow", "customer_service_agent"),
    ("customer_service_chatbot_workflow", "transaction_processing_agent"),
    ("user_proxy_agent", "mid_office_router"),
    ("mid_office_router", "mid_office_planning_workflow"),
    ("mid_office_planning_workflow", "data_analysis_agent"),
    ("mid_office_planning_workflow", "forecasting_agent"),
    ("mid_office_planning_workflow", "staff_scheduling_agent"),
    ("mid_office_planning_workflow", "mid_office_planning_parallel"),
    ("mid_office_planning_parallel", "validation_agent"),
    ("mid_office_planning_parallel", "support_guidance_agent"),
    ("mid_office_planning_workflow", "planning_summary_agent"),
    ("mid_office_router", "representative_assistant_workflow"),
    ("representative_assistant_workflow", "representative_assist_parallel"),
    ("representative_assist_parallel", "financial_data_agent"),
    ("representative_assist_parallel", "recommender_agent"),
    ("representative_assist_parallel", "loan_agent"),
    ("representative_assist_parallel", "risk_compliance_agent"),
    ("representative_assistant_workflow", "representative_merge_agent"),
    ("user_proxy_agent", "back_office_router"),
    ("back_office_router", "back_office_eod_workflow"),
    ("back_office_eod_workflow", "validation_checkpoint_agent"),
    ("back_office_eod_workflow", "eod_processing_agent"),
    ("back_office_eod_workflow", "ledger_update_agent"),
    ("back_office_eod_workflow", "reconciliation_agent"),
    ("back_office_eod_workflow", "report_writing_agent"),
    ("back_office_eod_workflow", "exception_agent"),
]

# the 13 routes the rule used to conflict with (docs/PSL_INTENT_CONSISTENCY.md before the fix)
FORMERLY_CONFLICTING = [
    ("mid_office_router", "mid_office_planning_workflow"),
    ("mid_office_router", "representative_assistant_workflow"),
    ("mid_office_planning_parallel", "validation_agent"),
    ("mid_office_planning_parallel", "support_guidance_agent"),
    ("mid_office_planning_workflow", "data_analysis_agent"),
    ("mid_office_planning_workflow", "forecasting_agent"),
    ("mid_office_planning_workflow", "staff_scheduling_agent"),
    ("mid_office_planning_workflow", "planning_summary_agent"),
    ("representative_assist_parallel", "financial_data_agent"),
    ("representative_assist_parallel", "recommender_agent"),
    ("representative_assist_parallel", "loan_agent"),
    ("representative_assist_parallel", "risk_compliance_agent"),
    ("representative_assistant_workflow", "representative_merge_agent"),
]

# Not in the MAS: routes injected as runtime-tree edges so that they get a placement (and the
# generated least-privilege permit). Only the domain differs between the two.
CROSS_DOMAIN = ("customer_service_chatbot_workflow", "ledger_update_agent")      # front -> back
SAME_DOMAIN = ("customer_service_chatbot_workflow", "fraud_detection_agent")     # front -> front


@pytest.fixture(scope="module")
def nb(tmp_path_factory):
    if not (MAS_ROOT / "citi_banking_adk").exists():
        pytest.skip("MAS repository not available")
    import sys
    sys.path.insert(0, str(BACKPLANE))
    from native_mas_runtime.engine import NativeMasBackplane
    return NativeMasBackplane(backplane_root=BACKPLANE, mas_repo_root=MAS_ROOT,
                              output_dir=tmp_path_factory.mktemp("native_xdomain"),
                              runtime_agent_edges=[*REAL_TREE_EDGES, CROSS_DOMAIN, SAME_DOMAIN])


def route(nb, caller, target):
    wi = f"wf-{uuid.uuid4()}"
    placement = nb.find_route_placement(caller, target)
    assert placement is not None, (caller, target)
    return nb.authorize(placement, parameters={"target_agent": target}, trace_id=wi, workflow_instance_id=wi,
                        event_type="AGENT_ROUTE_AUTHORIZATION", caller_runtime_id=caller, target_runtime_id=target)


def violated(nb, auth) -> list[str]:
    """PSL rules the PDP reported as violated for this decision (from the PDP decision log;
    the PDP reason is 'psl_violation:<rule>,<rule>,...' and lists every violated rule)."""
    if auth.allowed:
        return []
    decision_id = auth.runtime_authorization.decision.decision_id
    log = (nb.output_dir / "task4_decision_log.jsonl").read_text(encoding="utf-8").splitlines()
    record = next(json.loads(x) for x in reversed(log) if json.loads(x).get("decision_id") == decision_id)
    reason = str(record["reason"])
    return reason.split(":", 1)[1].split(",") if reason.startswith("psl_violation:") else []


def test_rule_is_enabled_in_the_signed_store(nb):
    rule = nb.task4_runtime.engine.bundle.policy_set.rule(RULE)
    assert rule.scope == "pdp_request" and not rule.disabled


def test_mid_office_workflow_agents_are_in_the_mid_office_domain(nb):
    import yaml
    ids = {i["id"]: i for i in yaml.safe_load((nb.output_dir / "task4_config" / "identities.yaml")
                                               .read_text(encoding="utf-8"))["identities"]}
    for name in ("mid_office_planning_workflow", "mid_office_planning_parallel",
                 "representative_assistant_workflow", "representative_assist_parallel"):
        assert ids[name]["domain"] == "mid_office", name
        assert ids[name]["canonical_id"] == f"agent.mid_office.{name}"


def test_no_route_of_the_real_agent_tree_is_refused_by_the_rule(nb):
    for caller, target in REAL_TREE_EDGES:
        auth = route(nb, caller, target)
        assert RULE not in violated(nb, auth), (caller, target, auth.reason)


def test_formerly_conflicting_mid_office_routes_are_allowed(nb):
    for caller, target in FORMERLY_CONFLICTING:
        auth = route(nb, caller, target)
        assert auth.allowed, (caller, target, auth.reason)


def test_user_proxy_may_enter_every_office(nb):
    for office in ("front_office_router", "mid_office_router", "back_office_router"):
        assert route(nb, "user_proxy_agent", office).allowed, office


def test_cross_domain_route_is_refused_by_the_rule(nb):
    auth = route(nb, *CROSS_DOMAIN)
    assert not auth.allowed and auth.decision == "DENY"
    assert violated(nb, auth) == [RULE], auth.reason          # the domain is the only reason


def test_same_domain_control_route_is_allowed(nb):
    auth = route(nb, *SAME_DOMAIN)
    assert auth.allowed, auth.reason


def test_scan_cache_from_another_scanner_is_rescanned(nb):
    """A cached Task 2 inventory written by an older scanner (stale 'shared' domains) must not be
    reused: the MAS plugin bootstraps with refresh=False from a persistent output directory."""
    import shutil
    import yaml
    from native_mas_runtime.engine import NativeMasBackplane
    out = nb.output_dir.parent / "native_stale_cache"
    shutil.copytree(nb.output_dir / "task2", out / "task2")
    drafts = out / "task2" / "draft_manifests" / "agents_draft.yaml"
    doc = yaml.safe_load(drafts.read_text(encoding="utf-8"))
    for a in doc["agents"]:
        if a["agent_id"] == "mid_office_planning_workflow":
            a["domain"] = "shared"                          # what the old scanner wrote
            a.pop("domain_source", None)
    drafts.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    stamp = out / "task2" / "scan_fingerprint.json"
    stamp.write_text(json.dumps({"scanner_sha256": "0" * 64, "mas_repo_root": MAS_ROOT.as_posix()}), encoding="utf-8")
    again = NativeMasBackplane(backplane_root=BACKPLANE, mas_repo_root=MAS_ROOT, output_dir=out)  # refresh=False
    ids = {i["id"]: i for i in yaml.safe_load((out / "task4_config" / "identities.yaml")
                                               .read_text(encoding="utf-8"))["identities"]}
    assert ids["mid_office_planning_workflow"]["domain"] == "mid_office"
    assert json.loads(stamp.read_text(encoding="utf-8")) == again._scan_fingerprint()
    again.close()
