from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zt_task5.key_rotation import Ed25519KeyRing
from zt_task5.models import UnifiedAuthorizationRequest
from zt_task5.service import build_task5_components, register_generated_pep
from zt_task5.task3_adapter import Task3PEPAdapter
from zt_task5.task4_adapter import (
    HeaderEd25519DecisionVerifier,
    build_demo_allow_decision,
    sign_demo_task4_decision,
)


def main() -> None:
    task4_private = Ed25519PrivateKey.generate()
    task4_key_id = "task4-decision-key-v1"
    task4_trust = Ed25519KeyRing()
    task4_trust.add_public_key(task4_key_id, task4_private.public_key())
    verifier = HeaderEd25519DecisionVerifier(task4_trust)

    components = build_task5_components(
        verifier,
        current_policy_version="policy-v1",
        normal_max_uses=3,
    )
    pep_private = Ed25519PrivateKey.generate()
    pep_identity = "pep://task3/generated/tool-pep-transfer"
    register_generated_pep(components, pep_identity, pep_private)

    def task4_pdp(request: UnifiedAuthorizationRequest):
        decision = build_demo_allow_decision(
            request,
            key_id=task4_key_id,
            policy_version="policy-v1",
            identity_version="identity-v1",
            risk_version="risk-v1",
            obligations=[{"type": "enhanced_logging"}],
        )
        return sign_demo_task4_decision(decision, task4_private)

    request = UnifiedAuthorizationRequest.from_mapping(
        {
            "subject_id": "fraud_agent",
            "resource_id": "transaction_history",
            "operation": "read",
            "params": {"customer_id": "customer-100"},
            "context": {
                "workflow_id": "fraud-review-001",
                "audience": "banking-backend",
                "endpoint": "/v1/transactions/history",
                "risk": "medium"
            },
            "evidence": {
                "risk": {
                    "assertion_id": "risk-001",
                    "issuer": "risk-service",
                    "issuer_version": "model-v1",
                    "score": 310
                }
            }
        }
    )

    pep = Task3PEPAdapter(
        components.state_machine,
        task4_pdp,
        pep_identity=pep_identity,
        pep_private_key=pep_private,
        idempotency_guard=components.idempotency_guard,
    )

    print("1. Task 3 PEP -> Task 4 PDP -> Task 5 Permit Lease")
    value = pep.execute(request, lambda: {"transactions": 4})
    print("   ALLOW:", value)

    print("2. PDP timeout with an exact, valid cached Permit Lease")
    pep.task4_call = lambda _request: (_ for _ in ()).throw(TimeoutError("PDP down"))
    retry = request.model_copy(update={"request_id": "retry-request-002"})
    cached = pep.authorize(retry)
    print("   ", cached.state.value, cached.source, cached.reason)

    print("3. Modified request cannot reuse the cached Permit Lease")
    modified = request.model_copy(
        update={"parameters": {"customer_id": "customer-999"}, "request_id": "modified-003"}
    )
    denied = pep.authorize(modified)
    print("   ", denied.state.value, denied.reason)

    print("4. PEP restart clears local authorization cache")
    components.lease_cache.restart()
    after_restart = pep.authorize(retry)
    print("   ", after_restart.state.value, after_restart.reason)

    print("5. Audit chain valid:", components.audit_log.verify())
    print("   Audit records:", len(components.audit_log.events()))


if __name__ == "__main__":
    main()
