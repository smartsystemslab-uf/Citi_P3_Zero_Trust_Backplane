from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .audit import HashChainedAuditLog
from .errors import Task5Error
from .key_rotation import public_key_thumbprint
from .lease_cache import LeaseCache
from .models import LeaseValidationResult, RuntimeState, Task4Decision, UnifiedAuthorizationRequest
from .permit_lease import PermitLeaseIssuer, PermitLeaseValidator
from .proof_of_possession import create_proof_of_possession
from .task4_adapter import DecisionVerifier, Task4DecisionAdapter, Task4DecisionEnvelope


@dataclass
class RuntimeAuthorization:
    allowed: bool
    state: RuntimeState
    source: str
    reason: str
    token: str | None = None
    decision: Task4Decision | None = None
    validation: LeaseValidationResult | None = None


class PDPTimeoutStateMachine:
    """NO_DECISION -> WAITING_FOR_PDP -> ACTIVE_LEASE or DENIED.

    A PDP timeout may use only a still-valid, exactly matching, sender-constrained
    cached Permit Lease. No plain Boolean authorization is ever cached.
    """

    def __init__(
        self,
        adapter: Task4DecisionAdapter,
        verifier: DecisionVerifier,
        issuer: PermitLeaseIssuer,
        validator: PermitLeaseValidator,
        lease_cache: LeaseCache,
        *,
        audit_log: HashChainedAuditLog | None = None,
    ) -> None:
        self.adapter = adapter
        self.verifier = verifier
        self.issuer = issuer
        self.validator = validator
        self.lease_cache = lease_cache
        self.audit_log = audit_log or HashChainedAuditLog()

    def authorize(
        self,
        request: UnifiedAuthorizationRequest,
        task4_call: Callable[[UnifiedAuthorizationRequest], Task4DecisionEnvelope],
        *,
        pep_identity: str,
        pep_private_key: Ed25519PrivateKey,
        session_id: str | None = None,
    ) -> RuntimeAuthorization:
        state = RuntimeState.WAITING_FOR_PDP
        thumbprint = public_key_thumbprint(pep_private_key.public_key())
        try:
            envelope = task4_call(request)
            decision = self.adapter.normalize(envelope, request)
            self.verifier.verify(envelope, decision, request)
            if not decision.allows_execution:
                return self._deny(request, f"TASK4_{decision.decision.value}", "PDP", decision)
            signed = self.issuer.issue(
                request,
                decision,
                pep_identity=pep_identity,
                pep_key_thumbprint=thumbprint,
                session_id=session_id,
            )
            # A fresh, verified PDP response re-establishes cache synchronization
            # after a PEP restart. Old cache entries were already cleared.
            self.lease_cache.mark_synchronized()
            self.lease_cache.put(signed.token, signed.claims)
            proof = create_proof_of_possession(signed.claims, pep_private_key)
            validation = self.validator.validate(signed.token, request, proof, consume=True)
            result = RuntimeAuthorization(
                allowed=True,
                state=RuntimeState.ACTIVE_LEASE,
                source="PDP",
                reason=validation.reason,
                token=signed.token,
                decision=decision,
                validation=validation,
            )
            self._audit(request, result, signed.claims.policy_version)
            return result
        except (TimeoutError, ConnectionError):
            return self._timeout_fallback(request, pep_identity, pep_private_key)
        except Task5Error as exc:
            return self._deny(request, str(exc), "PDP")
        except Exception as exc:
            # Unknown integration failures are fail-closed.
            return self._deny(request, f"PDP_INTEGRATION_ERROR:{type(exc).__name__}", "PDP")

    def _timeout_fallback(
        self,
        request: UnifiedAuthorizationRequest,
        pep_identity: str,
        pep_private_key: Ed25519PrivateKey,
    ) -> RuntimeAuthorization:
        thumbprint = public_key_thumbprint(pep_private_key.public_key())
        cached = self.lease_cache.get_matching(
            request_hash=request.request_hash(),
            pep_key_thumbprint=thumbprint,
            audience=request.audience,
            endpoint=request.endpoint,
        )
        if cached is None:
            return self._deny(request, "PDP_TIMEOUT_NO_VALID_LEASE", "CACHE")
        if cached.claims.pep_identity != pep_identity:
            return self._deny(request, "PDP_TIMEOUT_SENDER_MISMATCH", "CACHE")
        try:
            proof = create_proof_of_possession(cached.claims, pep_private_key)
            validation = self.validator.validate(cached.token, request, proof, consume=True)
            result = RuntimeAuthorization(
                allowed=True,
                state=RuntimeState.ACTIVE_LEASE,
                source="CACHE",
                reason="PDP_TIMEOUT_VALID_CACHED_LEASE",
                token=cached.token,
                validation=validation,
            )
            self._audit(request, result, cached.claims.policy_version)
            return result
        except Task5Error as exc:
            self.lease_cache.remove(cached.claims.permit_id)
            return self._deny(request, f"PDP_TIMEOUT_INVALID_LEASE:{exc}", "CACHE")

    def _deny(
        self,
        request: UnifiedAuthorizationRequest,
        reason: str,
        source: str,
        decision: Task4Decision | None = None,
    ) -> RuntimeAuthorization:
        result = RuntimeAuthorization(
            allowed=False,
            state=RuntimeState.DENIED,
            source=source,
            reason=reason,
            decision=decision,
        )
        self._audit(request, result, decision.policy_version if decision else None)
        return result

    def _audit(
        self,
        request: UnifiedAuthorizationRequest,
        result: RuntimeAuthorization,
        policy_version: str | None,
    ) -> None:
        self.audit_log.append(
            event_type="RUNTIME_AUTHORIZATION",
            request_id=request.request_id,
            subject=request.subject,
            resource=request.resource,
            action=request.action,
            workflow_id=request.workflow_id,
            decision="ALLOW" if result.allowed else "DENY",
            source=result.source,
            permit_id=(result.validation.permit_id if result.validation else None),
            policy_version=policy_version,
            reason=result.reason,
            details={"state": result.state.value},
        )
