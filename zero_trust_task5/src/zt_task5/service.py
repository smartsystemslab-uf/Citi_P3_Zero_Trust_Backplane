from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .audit import HashChainedAuditLog
from .idempotency_guard import IdempotencyGuard
from .key_rotation import Ed25519KeyRing
from .lease_cache import LeaseCache
from .nonce_service import NonceService
from .pdp_timeout_state_machine import PDPTimeoutStateMachine
from .permit_lease import PermitLeaseIssuer, PermitLeaseValidator
from .replay_cache import ReplayCache
from .revocation_service import RevocationService
from .sender_constraint import SenderConstraintRegistry
from .task4_adapter import DecisionVerifier, Task4DecisionAdapter


@dataclass
class Task5Components:
    permit_keys: Ed25519KeyRing
    revocations: RevocationService
    sender_registry: SenderConstraintRegistry
    lease_cache: LeaseCache
    issuer: PermitLeaseIssuer
    validator: PermitLeaseValidator
    state_machine: PDPTimeoutStateMachine
    idempotency_guard: IdempotencyGuard
    audit_log: HashChainedAuditLog


def build_task5_components(
    task4_verifier: DecisionVerifier,
    *,
    current_policy_version: str = "1",
    permit_key_id: str = "task5-permit-key-v1",
    normal_ttl_seconds: int = 60,
    critical_ttl_seconds: int = 15,
    normal_max_uses: int = 3,
) -> Task5Components:
    permit_keys = Ed25519KeyRing.with_generated_key(permit_key_id)
    revocations = RevocationService(current_policy_version=current_policy_version)
    sender_registry = SenderConstraintRegistry()
    lease_cache = LeaseCache()
    audit_log = HashChainedAuditLog()
    issuer = PermitLeaseIssuer(
        permit_keys,
        revocations,
        decision_replay_cache=ReplayCache(),
        nonce_service=NonceService(),
        normal_ttl_seconds=normal_ttl_seconds,
        critical_ttl_seconds=critical_ttl_seconds,
        normal_max_uses=normal_max_uses,
    )
    validator = PermitLeaseValidator(
        permit_keys,
        revocations,
        sender_registry,
        lease_use_cache=ReplayCache(),
    )
    state_machine = PDPTimeoutStateMachine(
        Task4DecisionAdapter(),
        task4_verifier,
        issuer,
        validator,
        lease_cache,
        audit_log=audit_log,
    )
    return Task5Components(
        permit_keys=permit_keys,
        revocations=revocations,
        sender_registry=sender_registry,
        lease_cache=lease_cache,
        issuer=issuer,
        validator=validator,
        state_machine=state_machine,
        idempotency_guard=IdempotencyGuard(),
        audit_log=audit_log,
    )


def register_generated_pep(
    components: Task5Components,
    pep_identity: str,
    private_key: Ed25519PrivateKey,
) -> str:
    return components.sender_registry.register(pep_identity, private_key.public_key())
