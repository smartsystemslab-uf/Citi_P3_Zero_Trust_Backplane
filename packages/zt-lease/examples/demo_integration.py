from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zt_lease.key_rotation import Ed25519KeyRing
from zt_lease.models import UnifiedAuthorizationRequest
from zt_lease.service import build_lease_components, register_generated_pep
from zt_lease.pep_adapter import GeneratedPepAdapter
from zt_lease.pdp_adapter import (
    HeaderEd25519DecisionVerifier,
    build_demo_allow_decision,
    sign_demo_pdp_decision,
)


def main() -> None:
    pdp_private = Ed25519PrivateKey.generate()
    pdp_key_id = "pdp-decision-key-v1"
    pdp_trust = Ed25519KeyRing()
    pdp_trust.add_public_key(pdp_key_id, pdp_private.public_key())
    verifier = HeaderEd25519DecisionVerifier(pdp_trust)

    components = build_lease_components(
        verifier,
        current_policy_version="policy-v1",
        normal_max_uses=3,
    )
    pep_private = Ed25519PrivateKey.generate()
    pep_identity = "pep://pep/generated/tool-pep-transfer"
    register_generated_pep(components, pep_identity, pep_private)

    def pdp_service(request: UnifiedAuthorizationRequest):
        decision = build_demo_allow_decision(
            request,
            key_id=pdp_key_id,
            policy_version="policy-v1",
            identity_version="identity-v1",
            risk_version="risk-v1",
            obligations=[{"type": "enhanced_logging"}],
        )
        return sign_demo_pdp_decision(decision, pdp_private)

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

    pep = GeneratedPepAdapter(
        components.state_machine,
        pdp_service,
        pep_identity=pep_identity,
        pep_private_key=pep_private,
        idempotency_guard=components.idempotency_guard,
    )

    print("1. PEP -> PDP -> Permit Lease")
    value = pep.execute(request, lambda: {"transactions": 4})
    print("   ALLOW:", value)

    print("2. PDP timeout with an exact, valid cached Permit Lease")
    pep.pdp_call = lambda _request: (_ for _ in ()).throw(TimeoutError("PDP down"))
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
