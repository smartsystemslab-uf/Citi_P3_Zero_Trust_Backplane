from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from zt_backplane.models import Decision

from .helpers import signed_request


ROOT = Path(__file__).resolve().parents[1]


def test_interface_schema_files_match_recorded_original_hashes():
    expected = json.loads((ROOT / "interface_contract" / "SCHEMA_SHA256.json").read_text(encoding="utf-8"))
    for name, digest in expected.items():
        actual = hashlib.sha256((ROOT / "interface_contract" / "schemas" / name).read_bytes()).hexdigest()
        assert actual == digest


def test_request_and_response_validate_against_unchanged_schemas(runtime):
    request = signed_request(
        runtime,
        subject_canonical_id="agent.front_office.fraud",
        subject_runtime_id="fraud_agent",
        resource_canonical_id="resource.front_office.transaction_history",
        resource_runtime_id="transaction_history",
        action="read",
        workflow_id="workflow.front_office.fraud_review",
        workflow_instance_id="wf-1",
    )
    request_schema = json.loads(
        (ROOT / "interface_contract" / "schemas" / "pdp_request.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(request_schema, format_checker=FormatChecker()).validate(request.model_dump(mode="json"))

    response = runtime.engine.evaluate(request)
    assert response.decision == Decision.ALLOW_WITH_OBLIGATIONS
    response_schema = json.loads(
        (ROOT / "interface_contract" / "schemas" / "pdp_response.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(response_schema, format_checker=FormatChecker()).validate(response.model_dump(mode="json"))
