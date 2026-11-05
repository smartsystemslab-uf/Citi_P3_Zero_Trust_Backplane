"""Temporal PSL intent rules enforced by the native MAS runtime.

Uses the REAL bootstrap (static scanner scan of the MAS repository, PEP generator placements, signed PSL
policy store, in-process PDP) and drives it with the same calls the ADK plugin makes
(authorize for routes, begin_tool / finish_tool for tools). No LLM is involved; outputs go
to a temporary directory. Skipped if the MAS repository is not available.
"""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest

BACKPLANE = Path(__file__).resolve().parents[4]          # repository root
# The Citi_P3 checkout (read only: the static scan never writes into it). CITI_MAS_REPO overrides
# the default location next to this repository.
MAS_ROOT = Path(os.environ.get("CITI_MAS_REPO") or BACKPLANE.parent / "Citi_P3")


@pytest.fixture(scope="module")
def nb(tmp_path_factory):
    if not (MAS_ROOT / "citi_banking_adk").exists():
        pytest.skip("MAS repository not available")
    import sys
    sys.path.insert(0, str(BACKPLANE / "legacy" / "citi_p3"))
    from native_runtime.engine import NativeMasBackplane
    return NativeMasBackplane(backplane_root=BACKPLANE, mas_repo_root=MAS_ROOT,
                              output_dir=tmp_path_factory.mktemp("native"),
                              human_approval=True, secondary_authorization=True, change_ticket="CHG-TEST-1")


def wf() -> str:
    return f"wf-{uuid.uuid4()}"


def tool(nb, wi, agent, name, args, *, result=None):
    placement = nb.find_tool_placement(agent, name, workflow_id=None)
    assert placement is not None, (agent, name)
    pending = nb.begin_tool(placement, tool_args=args, trace_id=wi, workflow_instance_id=wi,
                            workflow_id=placement.get("workflow_id"), idempotency_key=f"{wi}:{name}:{uuid.uuid4()}",
                            caller_runtime_id=agent, tool_name=name)
    if pending.authorization.allowed and result is not None:
        nb.finish_tool(pending, json.dumps(result))
    return pending.authorization


def route(nb, wi, caller, target):
    placement = nb.find_route_placement(caller, target)
    assert placement is not None, (caller, target)
    return nb.authorize(placement, parameters={"target_agent": target}, trace_id=wi, workflow_instance_id=wi,
                        event_type="AGENT_ROUTE_AUTHORIZATION", caller_runtime_id=caller, target_runtime_id=target)


LEDGER_ARGS = {"batch_id": "EOD-2026-11-02", "posting_instructions": "post batch totals"}


def test_ledger_update_is_refused_before_validation_and_batch_retrieval(nb):
    wi = wf()
    auth = tool(nb, wi, "ledger_update_agent", "apply_ledger_updates", LEDGER_ARGS)
    assert not auth.allowed and auth.source == "PSL_WORKFLOW_MONITOR"
    assert "intent.apply-ledger-updates-pipeline-gate.order" in auth.reason
    assert "intent.require-validation-before-ledger.order" in auth.reason


def test_ledger_update_is_refused_when_validation_said_not_ready(nb):
    wi = wf()
    assert tool(nb, wi, "validation_checkpoint_agent", "validate_eod_readiness", {"batch_id": "EOD-1"},
                result={"batch_id": "EOD-1", "ready": False}).allowed
    assert tool(nb, wi, "eod_processing_agent", "get_eod_batch", {"batch_id": "EOD-1"},
                result={"batch_id": "EOD-1", "items": []}).allowed
    auth = tool(nb, wi, "ledger_update_agent", "apply_ledger_updates", LEDGER_ARGS)
    assert not auth.allowed and "intent.require-validation-before-ledger.order" in auth.reason


def test_ledger_update_is_admitted_after_the_trusted_pipeline(nb):
    wi = wf()
    assert tool(nb, wi, "validation_checkpoint_agent", "validate_eod_readiness", {"batch_id": "EOD-1"},
                result={"batch_id": "EOD-1", "ready": True}).allowed
    assert tool(nb, wi, "eod_processing_agent", "get_eod_batch", {"batch_id": "EOD-1"},
                result={"batch_id": "EOD-1", "items": []}).allowed
    auth = tool(nb, wi, "ledger_update_agent", "apply_ledger_updates", LEDGER_ARGS)
    assert auth.allowed, auth.reason


def test_workflow_runs_are_isolated(nb):
    a, b = wf(), wf()
    tool(nb, a, "validation_checkpoint_agent", "validate_eod_readiness", {"batch_id": "EOD-1"},
         result={"ready": True})
    tool(nb, a, "eod_processing_agent", "get_eod_batch", {"batch_id": "EOD-1"}, result={"items": []})
    assert not tool(nb, b, "ledger_update_agent", "apply_ledger_updates", LEDGER_ARGS).allowed   # b has no pipeline
    assert tool(nb, a, "ledger_update_agent", "apply_ledger_updates", LEDGER_ARGS).allowed


def test_pdp_intent_rule_requires_posting_instructions(nb):
    wi = wf()
    tool(nb, wi, "validation_checkpoint_agent", "validate_eod_readiness", {"batch_id": "EOD-1"},
         result={"ready": True})
    tool(nb, wi, "eod_processing_agent", "get_eod_batch", {"batch_id": "EOD-1"}, result={"items": []})
    auth = tool(nb, wi, "ledger_update_agent", "apply_ledger_updates", {"batch_id": "EOD-1", "posting_instructions": " "})
    assert not auth.allowed and auth.decision == "DENY"
    assert auth.source != "PSL_WORKFLOW_MONITOR"         # refused by the PDP's intent rule, before the monitor
    last = json.loads((nb.output_dir / "pdp_decision_log.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert last["decision"] == "DENY"
    assert "intent.apply-ledger-updates-pipeline-gate" in last["reason"]
    assert "intent.require-validation-before-ledger" in last["reason"]


def test_decision_agent_route_needs_all_three_specialist_results(nb):
    wi = wf()
    caller = "front_office_transaction_workflow"
    assert not route(nb, wi, caller, "decision_making_agent").allowed
    for agent, tname in [("transaction_monitoring_agent", "get_transaction_context"),
                         ("fraud_detection_agent", "get_transaction_context")]:
        tool(nb, wi, agent, tname, {"transaction_id": "TXN-1001"}, result={"transaction_id": "TXN-1001"})
    blocked = route(nb, wi, caller, "decision_making_agent")
    assert not blocked.allowed and "intent.require-upstream-reports-before-decision.order" in blocked.reason
    tool(nb, wi, "compliance_agent", "get_transaction_context", {"transaction_id": "TXN-1001"},
         result={"transaction_id": "TXN-1001"})
    assert route(nb, wi, caller, "decision_making_agent").allowed
