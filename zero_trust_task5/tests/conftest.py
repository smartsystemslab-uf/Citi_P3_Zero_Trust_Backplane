from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zt_task5.key_rotation import Ed25519KeyRing
from zt_task5.models import UnifiedAuthorizationRequest
from zt_task5.service import build_task5_components, register_generated_pep
from zt_task5.task4_adapter import (
    HeaderEd25519DecisionVerifier,
    build_demo_allow_decision,
    sign_demo_task4_decision,
)


@pytest.fixture
def environment():
    task4_private = Ed25519PrivateKey.generate()
    task4_key_id = "task4-decision-key-v1"
    trust = Ed25519KeyRing()
    trust.add_public_key(task4_key_id, task4_private.public_key())
    verifier = HeaderEd25519DecisionVerifier(trust)
    components = build_task5_components(
        verifier,
        current_policy_version="policy-v1",
        normal_ttl_seconds=30,
        critical_ttl_seconds=5,
        normal_max_uses=3,
    )
    pep_private = Ed25519PrivateKey.generate()
    pep_identity = "pep://task3/generated/tool-pep-001"
    thumbprint = register_generated_pep(components, pep_identity, pep_private)

    def pdp_allow(request: UnifiedAuthorizationRequest):
        decision = build_demo_allow_decision(
            request,
            key_id=task4_key_id,
            policy_version="policy-v1",
            identity_version="identity-v1",
            risk_version="risk-v1",
            obligations=[{"type": "enhanced_logging"}],
        )
        return sign_demo_task4_decision(decision, task4_private)

    def make_request(*, critical=False, amount=100, workflow="wf-transfer-001", evidence=None):
        return UnifiedAuthorizationRequest.from_mapping(
            {
                "interface_version": "1.0",
                "subject_id": "transaction_agent",
                "resource_id": "banking_api.transfer",
                "operation": "execute",
                "params": {
                    "from_account": "A",
                    "to_account": "B",
                    "amount": amount,
                    "currency": "USD",
                },
                "context": {
                    "workflow_id": workflow,
                    "audience": "banking-api",
                    "endpoint": "/v1/transfers",
                    "risk": "high" if critical else "medium",
                    "critical": critical,
                    "idempotency_key": "idem-transfer-001" if critical else None,
                },
                "evidence": evidence
                or {
                    "risk": {
                        "assertion_id": "risk-001",
                        "issuer": "risk-service",
                        "issuer_version": "model-v1",
                        "score": 410,
                    },
                    "workflow": {
                        "assertion_id": "workflow-001",
                        "issuer": "workflow-orchestrator",
                        "issuer_version": "rules-v1",
                        "step": "execute_transfer",
                    },
                },
            }
        )

    return {
        "components": components,
        "task4_private": task4_private,
        "task4_key_id": task4_key_id,
        "pep_private": pep_private,
        "pep_identity": pep_identity,
        "thumbprint": thumbprint,
        "pdp_allow": pdp_allow,
        "make_request": make_request,
    }
