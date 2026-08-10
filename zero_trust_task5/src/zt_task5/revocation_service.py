from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock

from .errors import RevocationError
from .models import PermitLeaseClaims


@dataclass
class RevocationSnapshot:
    epoch: int = 0
    current_policy_version: str = "1"
    identity_versions: dict[str, str] = field(default_factory=dict)
    risk_versions: dict[str, str] = field(default_factory=dict)


class RevocationService:
    """In-memory prototype of scoped revocation plus version/epoch validation."""

    def __init__(self, *, current_policy_version: str = "1") -> None:
        self._lock = RLock()
        self.snapshot = RevocationSnapshot(current_policy_version=current_policy_version)
        self.revoked_permits: set[str] = set()
        self.revoked_decisions: set[str] = set()
        self.revoked_subjects: set[str] = set()
        self.revoked_sessions: set[str] = set()
        self.revoked_workflows: set[str] = set()
        self.revoked_policy_versions: set[str] = set()
        self.revoked_signing_keys: set[str] = set()
        self.revoked_context_issuers: set[str] = set()
        self.revoked_context_assertions: set[str] = set()
        self.revoked_pep_keys: set[str] = set()
        self.revoked_idempotency_keys: set[str] = set()

    @property
    def epoch(self) -> int:
        return self.snapshot.epoch

    def _bump_epoch(self) -> int:
        self.snapshot.epoch += 1
        return self.snapshot.epoch

    def set_policy_version(self, version: str) -> int:
        with self._lock:
            if version != self.snapshot.current_policy_version:
                self.snapshot.current_policy_version = version
                return self._bump_epoch()
            return self.snapshot.epoch

    def set_identity_version(self, subject: str, version: str) -> int:
        with self._lock:
            if self.snapshot.identity_versions.get(subject) != version:
                self.snapshot.identity_versions[subject] = version
                return self._bump_epoch()
            return self.snapshot.epoch

    def set_risk_version(self, subject: str, version: str) -> int:
        with self._lock:
            if self.snapshot.risk_versions.get(subject) != version:
                self.snapshot.risk_versions[subject] = version
                return self._bump_epoch()
            return self.snapshot.epoch

    def revoke_permit(self, permit_id: str) -> int:
        with self._lock:
            self.revoked_permits.add(permit_id)
            return self._bump_epoch()

    def revoke_decision(self, decision_id: str) -> int:
        with self._lock:
            self.revoked_decisions.add(decision_id)
            return self._bump_epoch()

    def revoke_subject(self, subject: str) -> int:
        with self._lock:
            self.revoked_subjects.add(subject)
            return self._bump_epoch()

    def revoke_session(self, session_id: str) -> int:
        with self._lock:
            self.revoked_sessions.add(session_id)
            return self._bump_epoch()

    def revoke_workflow(self, workflow_id: str) -> int:
        with self._lock:
            self.revoked_workflows.add(workflow_id)
            return self._bump_epoch()

    def revoke_policy_version(self, policy_version: str) -> int:
        with self._lock:
            self.revoked_policy_versions.add(policy_version)
            return self._bump_epoch()

    def revoke_signing_key(self, key_id: str) -> int:
        with self._lock:
            self.revoked_signing_keys.add(key_id)
            return self._bump_epoch()

    def revoke_context_issuer(self, issuer: str) -> int:
        with self._lock:
            self.revoked_context_issuers.add(issuer)
            return self._bump_epoch()

    def revoke_context_assertion(self, assertion_id: str) -> int:
        with self._lock:
            self.revoked_context_assertions.add(assertion_id)
            return self._bump_epoch()

    def revoke_pep_key(self, thumbprint: str) -> int:
        with self._lock:
            self.revoked_pep_keys.add(thumbprint)
            return self._bump_epoch()

    def revoke_idempotency_key(self, idempotency_key: str) -> int:
        with self._lock:
            self.revoked_idempotency_keys.add(idempotency_key)
            return self._bump_epoch()

    def validate_versions_for_issuance(
        self,
        *,
        subject: str,
        policy_version: str,
        identity_version: str,
        risk_version: str,
    ) -> None:
        if policy_version != self.snapshot.current_policy_version:
            raise RevocationError("Task 4 decision uses a stale policy version")
        current_identity = self.snapshot.identity_versions.get(subject, identity_version)
        current_risk = self.snapshot.risk_versions.get(subject, risk_version)
        if identity_version != current_identity:
            raise RevocationError("Task 4 decision uses a stale identity version")
        if risk_version != current_risk:
            raise RevocationError("Task 4 decision uses a stale risk version")

    def validate_lease(self, claims: PermitLeaseClaims) -> None:
        # Strict epoch matching is deliberately conservative: any missed revocation
        # makes an old local cache unusable until a fresh PDP decision is obtained.
        if claims.revocation_epoch != self.snapshot.epoch:
            raise RevocationError("Permit Lease revocation epoch is stale")
        if claims.permit_id in self.revoked_permits:
            raise RevocationError("Permit Lease is revoked")
        if claims.decision_id in self.revoked_decisions:
            raise RevocationError("Source PDP decision is revoked")
        if claims.subject in self.revoked_subjects:
            raise RevocationError("Subject identity is revoked")
        if claims.session_id and claims.session_id in self.revoked_sessions:
            raise RevocationError("User session is revoked")
        if claims.workflow_id in self.revoked_workflows:
            raise RevocationError("Workflow is revoked")
        if claims.policy_version in self.revoked_policy_versions:
            raise RevocationError("Policy version is revoked")
        if claims.policy_version != self.snapshot.current_policy_version:
            raise RevocationError("Permit Lease uses an old policy version")
        if claims.permit_signing_key_id in self.revoked_signing_keys:
            raise RevocationError("Permit signing key is revoked")
        if claims.decision_signing_key_id in self.revoked_signing_keys:
            raise RevocationError("Decision signing key is revoked")
        if claims.pep_key_thumbprint in self.revoked_pep_keys:
            raise RevocationError("PEP sender key is revoked")
        if claims.idempotency_key and claims.idempotency_key in self.revoked_idempotency_keys:
            raise RevocationError("Idempotency authorization is revoked")

        current_identity = self.snapshot.identity_versions.get(
            claims.subject, claims.identity_version
        )
        current_risk = self.snapshot.risk_versions.get(claims.subject, claims.risk_version)
        if claims.identity_version != current_identity:
            raise RevocationError("Permit Lease identity version is stale")
        if claims.risk_version != current_risk:
            raise RevocationError("Permit Lease risk version is stale")

        for binding in claims.context_bindings:
            if binding.assertion_id in self.revoked_context_assertions:
                raise RevocationError(f"Context assertion is revoked: {binding.kind}")
            if binding.issuer and binding.issuer in self.revoked_context_issuers:
                raise RevocationError(f"Context issuer is revoked: {binding.kind}")
