from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator, FormatChecker

from zt_backplane.decision_signing import verify_decision_headers
from zt_backplane.pdp_service import create_app

from .helpers import ROOT, signed_request


def test_challenge_authorize_and_signed_decision(runtime):
    client = TestClient(create_app(runtime))
    challenge = client.post(
        "/v1/challenge",
        json={
            "subject_canonical_id": "agent.front_office.fraud",
            "subject_runtime_id": "fraud_agent",
        },
    )
    assert challenge.status_code == 200
    request = signed_request(
        runtime,
        subject_canonical_id="agent.front_office.fraud",
        subject_runtime_id="fraud_agent",
        resource_canonical_id="resource.front_office.transaction_history",
        resource_runtime_id="transaction_history",
        action="read",
        workflow_id="workflow.front_office.fraud_review",
        workflow_instance_id="wf-api",
    )
    response = client.post("/v1/authorize", json=request.model_dump(mode="json"))
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "ALLOW_WITH_OBLIGATIONS"
    assert verify_decision_headers(
        body,
        response.headers,
        ROOT / "security" / "dev_keys" / "pdp_signing_public.pem",
        expected_request_hash=request.request_hash,
    )
    schema = json.loads(
        (ROOT / "interface_contract" / "schemas" / "pdp_response.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(body)


def test_health_reports_security_controls(runtime):
    client = TestClient(create_app(runtime))
    body = client.get("/health").json()
    assert body["interface_schema_version"] == "1.0"
    assert body["security"]["signed_policy_bundles"] is True
    assert body["security"]["signed_decisions"] is True
    assert body["security"]["permit_cache"] is False


def test_hot_reload_disabled_by_default(runtime, monkeypatch):
    monkeypatch.delenv("ZT_ENABLE_ADMIN_RELOAD", raising=False)
    client = TestClient(create_app(runtime))
    response = client.post("/v1/admin/reload")
    assert response.status_code == 503


def test_audit_hash_chain_is_valid(runtime):
    for index in range(2):
        request = signed_request(
            runtime,
            subject_canonical_id="agent.front_office.fraud",
            subject_runtime_id="fraud_agent",
            resource_canonical_id="resource.front_office.transaction_history",
            resource_runtime_id="transaction_history",
            action="read",
            workflow_id="workflow.front_office.fraud_review",
            workflow_instance_id=f"wf-audit-{index}",
        )
        runtime.engine.evaluate(request)
    assert runtime.engine.audit_logger.verify_chain()
