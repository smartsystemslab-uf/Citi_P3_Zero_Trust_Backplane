from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
for path in (
    ROOT / "zero_trust_task5" / "src",
    ROOT / "integrated_demo",
):
    sys.path.insert(0, str(path))

from zt_task5.models import UnifiedAuthorizationRequest


def test_task5_operation_hash_ignores_freshness_fields_but_binds_parameters():
    request = UnifiedAuthorizationRequest(
        subject="agent.front_office.fraud",
        resource="resource.front_office.transaction_history",
        action="read",
        workflow_id="workflow.front_office.fraud_review",
        parameters={"transaction_id": "tx-1"},
        audience="data-plane",
        endpoint="transaction-history",
    )
    retry = request.model_copy(update={"request_id": "retry", "evidence": {"risk": {"id": "new"}}})
    modified = request.model_copy(update={"parameters": {"transaction_id": "tx-2"}})
    assert request.request_hash() == retry.request_hash()
    assert request.request_hash() != modified.request_hash()
