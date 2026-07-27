from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from zt_backplane.canonical import assertion_payload
from zt_backplane.crypto import TrustedKeyStore, load_private_key, sign_mapping
from zt_backplane.evidence import FixedClock
from zt_backplane.models import Decision, RiskLevel
from zt_backplane.policy import PolicyBundle, PolicyRollbackStore

from .conftest import make_runtime
from .helpers import ROOT, resign_request, signed_request


def test_exact_copied_request_is_rejected_as_replay(runtime):
    request = signed_request(
        runtime,
        subject_canonical_id="agent.front_office.fraud",
        subject_runtime_id="fraud_agent",
        resource_canonical_id="resource.front_office.transaction_history",
        resource_runtime_id="transaction_history",
        action="read",
        workflow_id="workflow.front_office.fraud_review",
        workflow_instance_id="wf-replay",
    )
    first = runtime.engine.evaluate(request)
    second = runtime.engine.evaluate(request)
    assert first.decision == Decision.ALLOW_WITH_OBLIGATIONS
    assert second.decision == Decision.DENY
    assert "request_replay_detected" in second.reason


def test_modified_parameters_after_authorization_are_rejected(runtime):
    request = signed_request(
        runtime,
        subject_canonical_id="agent.front_office.transaction_processing",
        subject_runtime_id="transaction_processing_agent",
        resource_canonical_id="resource.front_office.banking_transfer",
        resource_runtime_id="banking_transfer",
        action="execute",
        workflow_id="workflow.front_office.customer_transaction",
        workflow_instance_id="wf-modified",
        parameters={"amount_minor_units": 10000, "destination": "B"},
        with_human_approval=True,
        with_secondary_authorization=True,
    )
    request.parameters["amount_minor_units"] = 900000
    result = runtime.engine.evaluate(request)
    assert result.decision == Decision.DENY
    assert "request_hash_mismatch" in result.reason


def test_context_change_breaks_signed_request(runtime):
    request = signed_request(
        runtime,
        subject_canonical_id="agent.front_office.fraud",
        subject_runtime_id="fraud_agent",
        resource_canonical_id="resource.front_office.transaction_history",
        resource_runtime_id="transaction_history",
        action="read",
        workflow_id="workflow.front_office.fraud_review",
        workflow_instance_id="wf-context",
        risk_score=300,
    )
    request.context.risk = RiskLevel.HIGH
    result = runtime.engine.evaluate(request)
    assert result.decision == Decision.DENY
    assert "invalid_request_signature" in result.reason or "context_risk_assertion_mismatch" in result.reason


def test_forged_approval_is_rejected_even_when_pep_resigns_request(runtime):
    request = signed_request(
        runtime,
        subject_canonical_id="agent.back_office.eod",
        subject_runtime_id="eod_agent",
        resource_canonical_id="resource.back_office.ledger",
        resource_runtime_id="ledger",
        action="update",
        workflow_id="workflow.back_office.eod_processing",
        workflow_instance_id="wf-forged-approval",
        parameters={"idempotency_key": "x"},
        with_human_approval=True,
        with_secondary_authorization=True,
    )
    request.context.human_approval["signature"] = "forged"
    resign_request(request)
    result = runtime.engine.evaluate(request)
    assert result.decision == Decision.DENY
    assert "invalid_human_approval_signature" in result.reason


def test_auth_strength_is_recomputed_from_signed_factors(runtime):
    request = signed_request(
        runtime,
        subject_canonical_id="agent.front_office.customer_service",
        subject_runtime_id="customer_service_agent",
        resource_canonical_id="resource.front_office.customer_profile",
        resource_runtime_id="customer_profile",
        action="read",
        auth_factors={"workload_identity": True},
    )
    auth = request.context.model_extra["auth_evidence"]
    auth["strength"] = 10
    auth.pop("signature")
    auth["signature"] = sign_mapping(
        load_private_key(ROOT / "security" / "dev_keys" / "idp_private.pem"),
        assertion_payload(auth),
    )
    request.context.auth_strength = 10
    resign_request(request)
    result = runtime.engine.evaluate(request)
    assert result.decision == Decision.DENY
    assert "auth_strength_calculation_mismatch" in result.reason


def test_risk_level_is_recomputed_from_signed_score(runtime):
    request = signed_request(
        runtime,
        subject_canonical_id="agent.front_office.fraud",
        subject_runtime_id="fraud_agent",
        resource_canonical_id="resource.front_office.transaction_history",
        resource_runtime_id="transaction_history",
        action="read",
        workflow_id="workflow.front_office.fraud_review",
        workflow_instance_id="wf-risk",
        risk_score=300,
    )
    risk = request.context.model_extra["risk_evidence"]
    risk["level"] = "critical"
    risk.pop("signature")
    risk["signature"] = sign_mapping(
        load_private_key(ROOT / "security" / "dev_keys" / "risk_private.pem"),
        assertion_payload(risk),
    )
    request.context.risk = RiskLevel.CRITICAL
    resign_request(request)
    result = runtime.engine.evaluate(request)
    assert result.decision == Decision.DENY
    assert "risk_score_level_mismatch" in result.reason


def test_request_timestamp_cannot_override_pdp_server_time(tmp_path):
    outside = datetime(2026, 7, 27, 3, 0, tzinfo=timezone.utc)
    runtime = make_runtime(tmp_path, now=outside)
    request = signed_request(
        runtime,
        subject_canonical_id="agent.mid_office.support_guidance",
        subject_runtime_id="support_guidance_agent",
        resource_canonical_id="resource.mid_office.internal_operations_data",
        resource_runtime_id="internal_operations_data",
        action="read",
        now=outside,
    )
    request.context.timestamp = datetime(2026, 7, 27, 14, 0, tzinfo=timezone.utc)
    resign_request(request)
    result = runtime.engine.evaluate(request)
    assert result.decision == Decision.DENY
    assert result.reason == "default_deny_no_matching_policy"


def test_unknown_subject_binding_is_denied(runtime):
    request = signed_request(
        runtime,
        subject_canonical_id="agent.front_office.unknown",
        subject_runtime_id="unknown_agent",
        resource_canonical_id="resource.front_office.transaction_history",
        resource_runtime_id="transaction_history",
        action="read",
        workflow_id="workflow.front_office.fraud_review",
        workflow_instance_id="wf-unknown",
    )
    result = runtime.engine.evaluate(request)
    assert result.decision == Decision.DENY
    assert "unknown_or_mismatched_subject" in result.reason


def test_tampered_policy_bundle_is_rejected(tmp_path):
    copied = tmp_path / "policies"
    shutil.copytree(ROOT / "policy_store", copied)
    path = copied / "front_office.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["policies"][0]["effect"] = "ALLOW"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    keys = TrustedKeyStore(ROOT / "config" / "trusted_issuers.yaml")
    with pytest.raises(ValueError, match="digest mismatch"):
        PolicyBundle.load(
            copied,
            schema_path=ROOT / "interface_contract" / "schemas" / "policy_bundle.schema.json",
            keys=keys,
        )


def test_policy_rollback_is_rejected(tmp_path):
    store = tmp_path / "versions.json"
    store.write_text(json.dumps({"bundle.front_office": "2.0.0"}), encoding="utf-8")
    keys = TrustedKeyStore(ROOT / "config" / "trusted_issuers.yaml")
    with pytest.raises(ValueError, match="policy rollback rejected"):
        PolicyBundle.load(
            ROOT / "policy_store",
            schema_path=ROOT / "interface_contract" / "schemas" / "policy_bundle.schema.json",
            keys=keys,
            rollback_store=PolicyRollbackStore(store),
        )
