from __future__ import annotations

import pytest

from zt_pep.runtime import ObligationError, PEPDenied, PEPEnforcer, PDPUnavailable


class FakeClient:
    def __init__(self, decision: dict | None = None, error: Exception | None = None):
        self.decision = decision or {
            "decision": "ALLOW",
            "reason": "allowed",
            "policy_version": "test",
            "obligations": [],
        }
        self.error = error

    def authorize(self, placement, **kwargs):
        if self.error:
            raise self.error
        return self.decision, {"request_id": "req-1", "trace_id": "trace-1"}


def plan(*, critical=True, fail_mode="closed", mode="enforce"):
    return {
        "environment_binding": "prototype",
        "logical_peps": [
            {
                "placement_id": "pep.test.edge",
                "physical_pep_id": "physical_pep.test",
                "edge_id": "edge.test.edge",
                "mode": mode,
                "fail_mode": fail_mode,
                "critical": critical,
                "subject_canonical_id": "agent.front_office.fraud",
                "subject_runtime_id": "fraud_agent",
                "resource_canonical_id": "resource.front_office.transaction_history",
                "resource_runtime_id": "transaction_history",
                "action": "read",
                "workflow_id": "workflow.front_office.fraud_review",
            }
        ],
    }


def test_deny_blocks_business_operation():
    client = FakeClient({"decision": "DENY", "reason": "policy", "policy_version": "1", "obligations": []})
    enforcer = PEPEnforcer(plan(), pdp_client=client)
    with pytest.raises(PEPDenied):
        enforcer.enforce("pep.test.edge", lambda: "must not run")


def test_data_masking_obligation_is_enforced():
    client = FakeClient(
        {
            "decision": "ALLOW_WITH_OBLIGATIONS",
            "reason": "allowed",
            "policy_version": "1",
            "obligations": [{"type": "data_masking", "parameters": {"fields": ["ssn"]}}],
        }
    )
    enforcer = PEPEnforcer(plan(), pdp_client=client)
    result = enforcer.enforce("pep.test.edge", lambda: {"name": "A", "ssn": "123"})
    assert result == {"name": "A", "ssn": "***MASKED***"}


def test_required_idempotency_key_is_checked_before_execution():
    client = FakeClient(
        {
            "decision": "ALLOW_WITH_OBLIGATIONS",
            "reason": "allowed",
            "policy_version": "1",
            "obligations": [{"type": "require_idempotency_key", "parameters": {}}],
        }
    )
    enforcer = PEPEnforcer(plan(), pdp_client=client)
    with pytest.raises(ObligationError):
        enforcer.enforce("pep.test.edge", lambda: "update", parameters={})


def test_critical_pdp_failure_is_fail_closed():
    enforcer = PEPEnforcer(plan(critical=True, fail_mode="closed"), pdp_client=FakeClient(error=PDPUnavailable("down")))
    with pytest.raises(PDPUnavailable):
        enforcer.enforce("pep.test.edge", lambda: "must not run")


def test_noncritical_explicit_fail_open_can_execute():
    enforcer = PEPEnforcer(
        plan(critical=False, fail_mode="open_for_noncritical"),
        pdp_client=FakeClient(error=PDPUnavailable("down")),
    )
    assert enforcer.enforce("pep.test.edge", lambda: "ran") == "ran"
