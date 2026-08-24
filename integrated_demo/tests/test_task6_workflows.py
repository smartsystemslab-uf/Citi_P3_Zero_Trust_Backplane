from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT / "zero_trust_task5" / "src", ROOT / "integrated_demo"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from task6_real_workflows import (
    WorkflowDefinition,
    ToolStep,
    RouteStep,
    audit_completeness,
    build_task6_policy_bundle,
    find_route_placement,
    find_tool_placement,
)


def _plan() -> dict:
    return {
        "logical_peps": [
            {
                "placement_id": "pep.route",
                "subject_runtime_id": "workflow_agent",
                "resource_runtime_id": "worker_agent",
                "subject_canonical_id": "agent.demo.workflow",
                "resource_canonical_id": "agent.demo.worker",
                "action": "read",
                "pep_type": "agent_route",
                "resource_type": "agent",
            },
            {
                "placement_id": "pep.tool",
                "edge_id": "edge.demo_worker_agent_get_demo",
                "subject_runtime_id": "worker_agent",
                "subject_canonical_id": "agent.demo.worker",
                "resource_runtime_id": "get_demo",
                "resource_canonical_id": "resource.demo.data",
                "interface_id": "interface.python_function.get_demo",
                "action": "read",
                "pep_type": "tool",
                "resource_type": "data",
                "critical": False,
            },
        ]
    }


def test_find_tool_placement_prefers_exact_interface_name():
    placement = find_tool_placement(_plan(), subject_runtime_id="worker_agent", tool_id="get_demo")
    assert placement["placement_id"] == "pep.tool"


def test_find_route_placement():
    placement = find_route_placement(
        _plan(), subject_runtime_id="workflow_agent", target_runtime_id="worker_agent"
    )
    assert placement is not None
    assert placement["placement_id"] == "pep.route"


def test_generated_task6_policy_is_lower_priority_than_hand_authored_policies():
    workflow = WorkflowDefinition(
        name="demo",
        workflow_id="workflow.demo",
        routes=(RouteStep("route.demo", "workflow_agent", "worker_agent"),),
        tools=(ToolStep("tool.demo", "worker_agent", "get_demo", {}),),
    )
    bundle = build_task6_policy_bundle(_plan(), [workflow])
    assert len(bundle["policies"]) == 2
    assert all(policy["priority"] == 120 for policy in bundle["policies"])
    assert all(policy["match"]["workflows"] == ["workflow.demo"] for policy in bundle["policies"])


def test_audit_completeness_requires_m6_fields(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    event = {
        "trace_id": "trace-1",
        "workflow_id": "workflow.demo",
        "caller_identity": "agent.demo.worker",
        "target_resource": "resource.demo.data",
        "requested_action": "read",
        "pdp_decision": "ALLOW",
        "policy_version": "v1",
        "permit_id": "permit-1",
        "execution_result": "EXECUTED",
        "logical_pep_id": "pep.tool",
    }
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    result = audit_completeness(path)
    assert result["passed"] is True
    assert result["sensitive_event_count"] == 1
