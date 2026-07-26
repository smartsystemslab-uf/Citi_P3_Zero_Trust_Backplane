from datetime import datetime, timezone

from zt_backplane.models import Decision, PDPRequest


def request(subject: str, resource: str, action: str, **context):
    return PDPRequest(subject=subject, resource=resource, action=action, context=context)


def test_fraud_agent_may_read_transaction_history(engine):
    result = engine.evaluate(
        request("fraud_agent", "transaction_history", "read", workflow="fraud_review", risk="medium")
    )
    assert result.decision == Decision.ALLOW_WITH_OBLIGATIONS
    assert result.policy_id == "FO-FRAUD-READ-TRANSACTION-HISTORY"
    assert {item.type for item in result.obligations} == {"enhanced_logging", "data_masking"}


def test_fraud_agent_may_not_execute_transfers(engine):
    result = engine.evaluate(
        request("fraud_agent", "banking_transfer", "execute", workflow="customer_transaction")
    )
    assert result.decision == Decision.DENY
    assert result.policy_id == "FO-FRAUD-DENY-TRANSFER"


def test_report_agent_may_read_reconciliation_results(engine):
    result = engine.evaluate(
        request("report_agent", "reconciliation_results", "read", workflow="report_generation")
    )
    assert result.decision == Decision.ALLOW_WITH_OBLIGATIONS
    assert result.policy_id == "BO-REPORT-READ-RECONCILIATION"


def test_report_agent_may_not_update_ledger(engine):
    result = engine.evaluate(request("report_agent", "ledger", "update", workflow="eod_processing"))
    assert result.decision == Decision.DENY
    assert result.policy_id == "LEDGER-REPORT-DENY-UPDATE"


def test_unknown_agents_are_denied(engine):
    result = engine.evaluate(request("unknown_agent", "transaction_history", "read"))
    assert result.decision == Decision.DENY
    assert result.reason == "unknown_subject"


def test_undefined_actions_are_denied(engine):
    result = engine.evaluate(request("fraud_agent", "transaction_history", "delete"))
    assert result.decision == Decision.DENY
    assert result.reason == "undefined_action_for_resource"


def test_critical_operations_require_manual_approval(engine):
    result = engine.evaluate(
        request("eod_agent", "ledger", "update", workflow="eod_processing", human_approved=False)
    )
    assert result.decision == Decision.MANUAL_REVIEW
    approved = engine.evaluate(
        request("eod_agent", "ledger", "update", workflow="eod_processing", human_approved=True)
    )
    assert approved.decision == Decision.ALLOW_WITH_OBLIGATIONS


def test_high_risk_transfer_requires_manual_review(engine):
    pending = engine.evaluate(
        request(
            "transaction_processing_agent",
            "banking_transfer",
            "execute",
            workflow="customer_transaction",
            risk="high",
            human_approved=False,
        )
    )
    assert pending.decision == Decision.MANUAL_REVIEW


def test_weak_authentication_requires_reauthentication(engine):
    weak = engine.evaluate(
        request("customer_service_agent", "customer_profile", "read", auth_strength=1)
    )
    assert weak.decision == Decision.REAUTHENTICATE
    strong = engine.evaluate(
        request("customer_service_agent", "customer_profile", "read", auth_strength=2)
    )
    assert strong.decision == Decision.ALLOW_WITH_OBLIGATIONS


def test_default_deny_for_valid_but_unpermitted_identity(engine):
    result = engine.evaluate(
        request("chatbot_agent", "ledger_snapshot", "read", workflow="customer_transaction")
    )
    assert result.decision == Decision.DENY
    assert result.reason == "default_deny_no_matching_policy"


def test_request_timestamp_is_accepted_for_future_time_policies(engine):
    # This confirms the context contract accepts an explicit aware timestamp.
    result = engine.evaluate(
        PDPRequest(
            subject="fraud_agent",
            resource="transaction_history",
            action="read",
            context={
                "workflow": "fraud_review",
                "risk": "medium",
                "timestamp": datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc),
            },
        )
    )
    assert result.decision == Decision.ALLOW_WITH_OBLIGATIONS


def test_time_based_policy(engine):
    during_business_hours = engine.evaluate(
        PDPRequest(
            subject="support_guidance_agent",
            resource="internal_operations_data",
            action="read",
            context={
                "workflow": "operations_planning",
                "timestamp": datetime(2026, 7, 27, 14, 0, tzinfo=timezone.utc),
            },
        )
    )
    assert during_business_hours.decision == Decision.ALLOW

    outside_business_hours = engine.evaluate(
        PDPRequest(
            subject="support_guidance_agent",
            resource="internal_operations_data",
            action="read",
            context={
                "workflow": "operations_planning",
                "timestamp": datetime(2026, 7, 27, 3, 0, tzinfo=timezone.utc),
            },
        )
    )
    assert outside_business_hours.decision == Decision.DENY
    assert outside_business_hours.reason == "default_deny_no_matching_policy"
