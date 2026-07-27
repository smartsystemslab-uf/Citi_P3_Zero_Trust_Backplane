from zt_backplane.models import Decision

from .helpers import signed_request


def test_fraud_agent_may_read_transaction_history(runtime):
    request = signed_request(
        runtime,
        subject_canonical_id="agent.front_office.fraud",
        subject_runtime_id="fraud_agent",
        resource_canonical_id="resource.front_office.transaction_history",
        resource_runtime_id="transaction_history",
        action="read",
        workflow_id="workflow.front_office.fraud_review",
        workflow_instance_id="fraud-wf-1",
    )
    result = runtime.engine.evaluate(request)
    assert result.decision == Decision.ALLOW_WITH_OBLIGATIONS
    assert result.policy_id == "policy.front_office.fraud_read_transaction_history"
    assert {item.type for item in result.obligations} == {"enhanced_logging", "data_masking"}


def test_fraud_agent_cannot_execute_transfer(runtime):
    request = signed_request(
        runtime,
        subject_canonical_id="agent.front_office.fraud",
        subject_runtime_id="fraud_agent",
        resource_canonical_id="resource.front_office.banking_transfer",
        resource_runtime_id="banking_transfer",
        action="execute",
        workflow_id="workflow.front_office.customer_transaction",
        workflow_instance_id="transfer-wf-1",
    )
    result = runtime.engine.evaluate(request)
    assert result.decision == Decision.DENY
    assert result.policy_id == "policy.front_office.fraud_deny_transfer"


def test_report_agent_may_read_reconciliation_results(runtime):
    request = signed_request(
        runtime,
        subject_canonical_id="agent.back_office.report",
        subject_runtime_id="report_agent",
        resource_canonical_id="resource.back_office.reconciliation_results",
        resource_runtime_id="reconciliation_results",
        action="read",
        workflow_id="workflow.back_office.eod_processing",
        workflow_instance_id="eod-1",
    )
    result = runtime.engine.evaluate(request)
    assert result.decision == Decision.ALLOW_WITH_OBLIGATIONS


def test_report_agent_cannot_update_ledger(runtime):
    request = signed_request(
        runtime,
        subject_canonical_id="agent.back_office.report",
        subject_runtime_id="report_agent",
        resource_canonical_id="resource.back_office.ledger",
        resource_runtime_id="ledger",
        action="update",
        workflow_id="workflow.back_office.eod_processing",
        workflow_instance_id="eod-1",
    )
    result = runtime.engine.evaluate(request)
    assert result.decision == Decision.DENY
    assert result.policy_id == "policy.ledger.report_deny_update"


def test_critical_write_requires_signed_approval_and_secondary_decision(runtime):
    pending = signed_request(
        runtime,
        subject_canonical_id="agent.back_office.eod",
        subject_runtime_id="eod_agent",
        resource_canonical_id="resource.back_office.ledger",
        resource_runtime_id="ledger",
        action="update",
        workflow_id="workflow.back_office.eod_processing",
        workflow_instance_id="eod-2",
        parameters={"idempotency_key": "ledger-1"},
    )
    assert runtime.engine.evaluate(pending).decision == Decision.MANUAL_REVIEW

    approved = signed_request(
        runtime,
        subject_canonical_id="agent.back_office.eod",
        subject_runtime_id="eod_agent",
        resource_canonical_id="resource.back_office.ledger",
        resource_runtime_id="ledger",
        action="update",
        workflow_id="workflow.back_office.eod_processing",
        workflow_instance_id="eod-3",
        parameters={"idempotency_key": "ledger-2"},
        with_human_approval=True,
        with_secondary_authorization=True,
    )
    result = runtime.engine.evaluate(approved)
    assert result.decision == Decision.ALLOW_WITH_OBLIGATIONS
    assert result.policy_id == "policy.ledger.eod_approved_update"


def test_weak_authentication_requires_reauthentication(runtime):
    weak = signed_request(
        runtime,
        subject_canonical_id="agent.front_office.customer_service",
        subject_runtime_id="customer_service_agent",
        resource_canonical_id="resource.front_office.customer_profile",
        resource_runtime_id="customer_profile",
        action="read",
        auth_factors={"workload_identity": True},
    )
    assert runtime.engine.evaluate(weak).decision == Decision.REAUTHENTICATE

    strong = signed_request(
        runtime,
        subject_canonical_id="agent.front_office.customer_service",
        subject_runtime_id="customer_service_agent",
        resource_canonical_id="resource.front_office.customer_profile",
        resource_runtime_id="customer_profile",
        action="read",
        auth_factors={"workload_identity": True, "user_session": True},
    )
    assert runtime.engine.evaluate(strong).decision == Decision.ALLOW_WITH_OBLIGATIONS


def test_undefined_action_is_denied(runtime):
    request = signed_request(
        runtime,
        subject_canonical_id="agent.front_office.fraud",
        subject_runtime_id="fraud_agent",
        resource_canonical_id="resource.front_office.transaction_history",
        resource_runtime_id="transaction_history",
        action="delete",
        workflow_id="workflow.front_office.fraud_review",
        workflow_instance_id="wf-x",
    )
    result = runtime.engine.evaluate(request)
    assert result.decision == Decision.DENY
    assert result.reason == "undefined_action_for_resource"
