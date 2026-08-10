from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from .context_binding import build_context_bindings, validate_context_bindings
from .errors import LeaseIssuanceError, LeaseValidationError, ReplayError
from .key_rotation import Ed25519KeyRing, b64url_decode, b64url_encode
from .models import (
    LeaseValidationResult,
    PermitLeaseClaims,
    ProofOfPossession,
    SignedPermitLease,
    Task4Decision,
    UnifiedAuthorizationRequest,
)
from .nonce_service import NonceService
from .proof_of_possession import validate_proof_of_possession
from .replay_cache import ReplayCache
from .request_hash import canonical_json_bytes
from .revocation_service import RevocationService
from .sender_constraint import SenderConstraintRegistry
from .trusted_clock import TrustedClock


_TOKEN_TYPE = "ZT-PERMIT-LEASE"
_TOKEN_VERSION = "1"


def _token_signing_input(header: dict[str, Any], payload: dict[str, Any]) -> bytes:
    return (
        b64url_encode(canonical_json_bytes(header))
        + "."
        + b64url_encode(canonical_json_bytes(payload))
    ).encode("ascii")


class PermitLeaseIssuer:
    def __init__(
        self,
        key_ring: Ed25519KeyRing,
        revocation_service: RevocationService,
        *,
        decision_replay_cache: ReplayCache | None = None,
        nonce_service: NonceService | None = None,
        critical_ttl_seconds: int = 15,
        normal_ttl_seconds: int = 60,
        normal_max_uses: int = 3,
    ) -> None:
        self.key_ring = key_ring
        self.revocation_service = revocation_service
        self.decision_replay_cache = decision_replay_cache or ReplayCache()
        self.nonce_service = nonce_service or NonceService()
        self.critical_ttl_seconds = critical_ttl_seconds
        self.normal_ttl_seconds = normal_ttl_seconds
        self.normal_max_uses = normal_max_uses

    def issue(
        self,
        request: UnifiedAuthorizationRequest,
        decision: Task4Decision,
        *,
        pep_identity: str,
        pep_key_thumbprint: str,
        session_id: str | None = None,
    ) -> SignedPermitLease:
        if not decision.allows_execution:
            raise LeaseIssuanceError(f"Task 4 decision does not allow execution: {decision.decision}")
        if decision.request_hash != request.request_hash():
            raise LeaseIssuanceError("Task 4 decision request_hash does not match the request")
        expected = (
            (decision.subject, request.subject, "subject"),
            (decision.resource, request.resource, "resource"),
            (decision.action, request.action, "action"),
            (decision.workflow_id, request.workflow_id, "workflow_id"),
        )
        for decision_value, request_value, field in expected:
            if str(decision_value or "") != str(request_value or ""):
                raise LeaseIssuanceError(f"Task 4 decision {field} does not match the request")

        self.revocation_service.validate_versions_for_issuance(
            subject=request.subject,
            policy_version=decision.policy_version,
            identity_version=decision.identity_version,
            risk_version=decision.risk_version,
        )

        now = datetime.now(timezone.utc)
        replay_expiration = decision.expires_at or (now + timedelta(seconds=120))
        try:
            self.decision_replay_cache.consume_once("task4-decision-jti", decision.jti, replay_expiration)
            self.decision_replay_cache.consume_once("task4-decision-nonce", decision.nonce, replay_expiration)
            self.decision_replay_cache.consume_once(
                "task4-decision-id", decision.decision_id, replay_expiration
            )
        except ReplayError as exc:
            raise LeaseIssuanceError("Task 4 decision was already converted into a Permit Lease") from exc

        ttl = self.critical_ttl_seconds if request.critical else self.normal_ttl_seconds
        expires_at = now + timedelta(seconds=ttl)
        if decision.expires_at is not None:
            expires_at = min(expires_at, decision.expires_at)
        if expires_at <= now:
            raise LeaseIssuanceError("Task 4 decision is already expired")

        max_uses = 1 if request.critical else self.normal_max_uses
        key_id = self.key_ring.active_key_id
        claims = PermitLeaseClaims(
            interface_version=request.interface_version,
            subject=request.subject,
            resource=request.resource,
            action=request.action,
            request_hash=request.request_hash(),
            workflow_id=request.workflow_id,
            audience=request.audience,
            endpoint=request.endpoint,
            issued_at=now,
            expires_at=expires_at,
            policy_version=decision.policy_version,
            identity_version=decision.identity_version,
            risk_version=decision.risk_version,
            max_uses=max_uses,
            obligations=decision.obligations,
            pep_identity=pep_identity,
            pep_key_thumbprint=pep_key_thumbprint,
            context_bindings=decision.context_bindings
            or build_context_bindings(request.evidence),
            decision_id=decision.decision_id,
            decision_signing_key_id=decision.decision_key_id,
            permit_signing_key_id=key_id,
            revocation_epoch=self.revocation_service.epoch,
            nonce=self.nonce_service.issue(),
            jti=str(uuid4()),
            session_id=session_id,
            critical=request.critical,
            idempotency_key=request.idempotency_key,
        )
        token = self._encode(claims)
        return SignedPermitLease(token=token, claims=claims)

    def _encode(self, claims: PermitLeaseClaims) -> str:
        header = {
            "alg": "EdDSA",
            "typ": _TOKEN_TYPE,
            "ver": _TOKEN_VERSION,
            "kid": claims.permit_signing_key_id,
        }
        payload = claims.model_dump(mode="json")
        signing_input = _token_signing_input(header, payload)
        key_id, signature = self.key_ring.sign(signing_input)
        if key_id != claims.permit_signing_key_id:
            raise LeaseIssuanceError("Permit signing key changed during issuance")
        return signing_input.decode("ascii") + "." + signature


class PermitLeaseValidator:
    def __init__(
        self,
        key_ring: Ed25519KeyRing,
        revocation_service: RevocationService,
        sender_registry: SenderConstraintRegistry,
        *,
        lease_use_cache: ReplayCache | None = None,
        trusted_clock: TrustedClock | None = None,
        maximum_clock_skew_seconds: int = 2,
    ) -> None:
        self.key_ring = key_ring
        self.revocation_service = revocation_service
        self.sender_registry = sender_registry
        self.lease_use_cache = lease_use_cache or ReplayCache()
        self.trusted_clock = trusted_clock or TrustedClock()
        self.maximum_clock_skew_seconds = maximum_clock_skew_seconds

    def decode_and_verify(self, token: str) -> SignedPermitLease:
        parts = token.split(".")
        if len(parts) != 3:
            raise LeaseValidationError("Malformed Permit Lease token")
        try:
            header = json.loads(b64url_decode(parts[0]))
            payload = json.loads(b64url_decode(parts[1]))
        except Exception as exc:
            raise LeaseValidationError("Permit Lease token is not valid JSON") from exc
        if header.get("alg") != "EdDSA" or header.get("typ") != _TOKEN_TYPE:
            raise LeaseValidationError("Unsupported Permit Lease header")
        key_id = str(header.get("kid") or "")
        signing_input = (parts[0] + "." + parts[1]).encode("ascii")
        self.key_ring.verify(key_id, signing_input, parts[2])
        claims = PermitLeaseClaims.model_validate(payload)
        if claims.permit_signing_key_id != key_id:
            raise LeaseValidationError("Permit Lease key ID mismatch")
        return SignedPermitLease(token=token, claims=claims)

    def validate(
        self,
        token: str,
        request: UnifiedAuthorizationRequest,
        proof_of_possession: ProofOfPossession,
        *,
        consume: bool = True,
        now: datetime | None = None,
    ) -> LeaseValidationResult:
        signed = self.decode_and_verify(token)
        claims = signed.claims
        now = now or self.trusted_clock.now()
        self.trusted_clock.observe(now)

        if now < claims.issued_at - timedelta(seconds=self.maximum_clock_skew_seconds):
            raise LeaseValidationError("Permit Lease is not yet valid")
        if now >= claims.expires_at:
            raise LeaseValidationError("Permit Lease is expired")
        if claims.request_hash != request.request_hash():
            raise LeaseValidationError("Request parameters were modified after authorization")

        comparisons = (
            (claims.subject, request.subject, "subject"),
            (claims.resource, request.resource, "resource"),
            (claims.action, request.action, "action"),
            (claims.workflow_id, request.workflow_id, "workflow_id"),
            (claims.audience, request.audience, "audience"),
            (claims.endpoint, request.endpoint, "endpoint"),
            (claims.idempotency_key or "", request.idempotency_key or "", "idempotency_key"),
        )
        for lease_value, request_value, field in comparisons:
            if str(lease_value) != str(request_value):
                raise LeaseValidationError(f"Permit Lease {field} does not match the request")
        if claims.critical != request.critical:
            raise LeaseValidationError("Permit Lease criticality does not match the request")

        self.revocation_service.validate_lease(claims)
        validate_context_bindings(claims, request)
        validate_proof_of_possession(
            proof_of_possession,
            claims,
            self.sender_registry,
            now=now,
        )

        remaining = claims.max_uses
        if consume:
            try:
                remaining = self.lease_use_cache.consume_use(
                    claims.permit_id,
                    claims.max_uses,
                    claims.expires_at,
                )
            except ReplayError as exc:
                raise LeaseValidationError("Single-use or bounded-use Permit Lease was replayed") from exc

        return LeaseValidationResult(
            allowed=True,
            reason="VALID_PERMIT_LEASE",
            permit_id=claims.permit_id,
            remaining_uses=remaining,
            obligations=claims.obligations,
        )
