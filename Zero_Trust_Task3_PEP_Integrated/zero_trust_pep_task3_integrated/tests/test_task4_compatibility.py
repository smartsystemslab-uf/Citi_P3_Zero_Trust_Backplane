from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from zt_pep.compatibility import check_task4_compatibility
from zt_pep.placement import build_pep_plan
from zt_pep.runtime import PEPDenied, PEPEnforcer, Task4PDPClient


ROOT = Path(__file__).resolve().parents[1]


def _task4_root() -> Path:
    raw = os.getenv("TASK4_ROOT")
    if not raw:
        pytest.skip("TASK4_ROOT not set")
    path = Path(raw).resolve()
    if not (path / "src" / "zt_backplane").exists():
        pytest.skip(f"invalid TASK4_ROOT: {path}")
    return path


def test_registry_and_schema_compatibility(manifest):
    task4 = _task4_root()
    plan, _ = build_pep_plan(manifest)
    report = check_task4_compatibility(plan, task4, ROOT / "interface_contract")
    assert report["summary"]["interface_schemas_match"] is True
    assert report["summary"]["all_pep_requests_resolve_in_task4_registry"] is True
    assert report["summary"]["compatible"] is True


def test_real_task4_pdp_end_to_end(manifest):
    task4 = _task4_root()
    sys.path.insert(0, str(task4 / "src"))
    try:
        from fastapi.testclient import TestClient
        from zt_backplane.pdp_service import build_runtime, create_app

        runtime = build_runtime()
        http_client = TestClient(create_app(runtime))
        client = Task4PDPClient(
            pdp_url="http://testserver",
            pdp_public_key=task4 / "security" / "dev_keys" / "pdp_signing_public.pem",
            http_client=http_client,
        )
        plan, _ = build_pep_plan(manifest)
        enforcer = PEPEnforcer(plan.model_dump(mode="json"), pdp_client=client)

        masked = enforcer.enforce(
            "pep.fraud_review.read_history",
            lambda: {"transaction": "t-1", "full_account_number": "9999", "ssn": "111"},
            parameters={"transaction_id": "t-1"},
        )
        assert masked["full_account_number"] == "***MASKED***"
        assert masked["ssn"] == "***MASKED***"

        with pytest.raises(PEPDenied):
            enforcer.enforce(
                "pep.eod_processing.ledger_update",
                lambda: "must not update",
                parameters={"batch_id": "b-1"},
            )

        result = enforcer.enforce(
            "pep.eod_processing.ledger_update",
            lambda: "ledger updated",
            parameters={
                "batch_id": "b-1",
                "idempotency_key": "idem-1",
                "change_ticket": "CHG-1",
            },
            with_human_approval=True,
            with_secondary_authorization=True,
        )
        assert result == "ledger updated"
    finally:
        if sys.path and sys.path[0] == str(task4 / "src"):
            sys.path.pop(0)
