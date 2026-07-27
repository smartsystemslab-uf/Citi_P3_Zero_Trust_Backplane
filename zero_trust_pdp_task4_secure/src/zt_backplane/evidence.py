from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

import yaml

from .canonical import assertion_payload, compute_request_hash, request_proof_payload
from .crypto import TrustedKeyStore, verify_mapping
from .models import PDPRequest, RiskLevel, VerifiedSecurityContext
from .registry import IdentityRegistry
from .replay import InMemoryReplayGuard


class SecurityError(ValueError):
    pass


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


@dataclass(frozen=True)
class FixedClock:
    value: datetime

    def now(self) -> datetime:
        return self.value


class SecurityConfig:
    def __init__(self, path: str | Path):
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        self.clock_skew_seconds = int(raw.get("clock_skew_seconds", 5))
        self.max_assertion_lifetime_seconds = int(raw.get("max_assertion_lifetime_seconds", 300))
        self.risk_threshold_version = str(raw.get("risk_threshold_version", ""))
        self.auth_factor_mapping_version = str(raw.get("auth_factor_mapping_version", ""))
        if not self.risk_threshold_version or not self.auth_factor_mapping_version:
            raise ValueError("security context mappings must have explicit versions")
        self.risk_thresholds: dict[str, list[int]] = {
            str(k): [int(v[0]), int(v[1])] for k, v in raw.get("risk_thresholds", {}).items()
        }
        self.auth_factor_weights: dict[str, int] = {
            str(k): int(v) for k, v in raw.get("auth_factor_weights", {}).items()
        }
        required = {level.value for level in RiskLevel}
        if set(self.risk_thresholds) != required:
            raise ValueError(f"risk_thresholds must define exactly {sorted(required)}")

    def classify_risk(self, score: int) -> RiskLevel:
        for level in RiskLevel:
            low, high = self.risk_thresholds[level.value]
            if low <= score <= high:
                return level
        raise SecurityError("risk_score_out_of_range")

    def calculate_auth_strength(self, factors: dict[str, Any]) -> int:
        unknown = set(factors) - set(self.auth_factor_weights)
        if unknown:
            raise SecurityError(f"unknown_auth_factors:{','.join(sorted(unknown))}")
        total = sum(self.auth_factor_weights[name] for name, enabled in factors.items() if bool(enabled))
        return max(0, min(10, total))


class EvidenceVerifier:
    def __init__(
        self,
        *,
        identities: IdentityRegistry,
        keys: TrustedKeyStore,
        replay_guard: InMemoryReplayGuard,
        security_config: SecurityConfig,
        clock: Clock | None = None,
    ):
        self.identities = identities
        self.keys = keys
        self.replay_guard = replay_guard
        self.security_config = security_config
        self.clock = clock or SystemClock()

    def verify(self, request: PDPRequest) -> VerifiedSecurityContext:
        now = self.clock.now()
        identity = self.identities.resolve(request.subject.canonical_id, request.subject.runtime_id)
        if identity is None:
            raise SecurityError("unknown_or_mismatched_subject")
        if not identity.enabled:
            raise SecurityError("subject_disabled")

        computed_hash = compute_request_hash(request)
        if not request.request_hash:
            raise SecurityError("missing_request_hash")
        if request.request_hash != computed_hash:
            raise SecurityError("request_hash_mismatch")

        identity_evidence = request.subject.identity_evidence
        self._verify_freshness(identity_evidence, "request_proof", now)
        self._require_equal(identity_evidence, "subject_canonical_id", request.subject.canonical_id)
        self._require_equal(identity_evidence, "subject_runtime_id", request.subject.runtime_id)
        self._require_equal(identity_evidence, "request_hash", request.request_hash)
        signature = self._required_string(identity_evidence, "signature")
        key = self.keys.get(
            self._required_string(identity_evidence, "issuer"),
            self._required_string(identity_evidence, "key_id"),
            "request_proof",
        )
        if not verify_mapping(key, request_proof_payload(request), signature):
            raise SecurityError("invalid_request_signature")

        jti = self._required_string(identity_evidence, "jti")
        nonce = self._required_string(identity_evidence, "nonce")
        self.replay_guard.consume(
            nonce=nonce,
            jti=jti,
            subject_canonical_id=request.subject.canonical_id,
            subject_runtime_id=request.subject.runtime_id,
            now=now,
        )

        risk = self._verify_risk(request, now)
        auth = self._verify_auth(request, now)
        workflow = self._verify_workflow(request, now)
        approval = self._verify_optional_bound_assertion(
            request.context.human_approval,
            purpose="human_approval",
            request=request,
            now=now,
        )
        secondary_raw = self._context_extra(request, "secondary_authorization") or {}
        secondary = self._verify_optional_bound_assertion(
            secondary_raw,
            purpose="secondary_authorization",
            request=request,
            now=now,
        )

        evidence_ids = [
            self._required_string(identity_evidence, "jti"),
            self._required_string(risk, "evidence_id"),
            self._required_string(auth, "evidence_id"),
        ]
        if workflow:
            evidence_ids.append(self._required_string(workflow, "evidence_id"))
        if approval:
            evidence_ids.append(self._required_string(approval, "evidence_id"))
        if secondary:
            evidence_ids.append(self._required_string(secondary, "evidence_id"))

        return VerifiedSecurityContext(
            decision_time=now,
            identity_verified=True,
            identity_issuer=self._required_string(identity_evidence, "issuer"),
            request_jti=jti,
            request_nonce=nonce,
            identity_version=self._required_string(auth, "identity_version"),
            risk_verified=True,
            risk_issuer=self._required_string(risk, "issuer"),
            risk_score=int(risk["score"]),
            risk_level=RiskLevel(str(risk["level"])),
            risk_version=self._required_string(risk, "risk_version"),
            auth_verified=True,
            auth_issuer=self._required_string(auth, "issuer"),
            auth_strength=int(auth["strength"]),
            workflow_verified=workflow is not None or request.context.workflow_id is None,
            workflow_issuer=self._required_string(workflow, "issuer") if workflow else None,
            approval_valid=approval is not None,
            approval_issuer=self._required_string(approval, "issuer") if approval else None,
            secondary_authorization_valid=secondary is not None,
            secondary_authorization_issuer=self._required_string(secondary, "issuer") if secondary else None,
            evidence_ids=evidence_ids,
        )

    def _verify_risk(self, request: PDPRequest, now: datetime) -> dict[str, Any]:
        raw = self._required_context_mapping(request, "risk_evidence")
        self._verify_assertion(raw, "risk_assertion", now)
        score = int(raw.get("score", -1))
        self._require_equal(raw, "threshold_version", self.security_config.risk_threshold_version)
        claimed_level = self._required_string(raw, "level")
        calculated_level = self.security_config.classify_risk(score).value
        if claimed_level != calculated_level:
            raise SecurityError("risk_score_level_mismatch")
        if request.context.risk.value != claimed_level:
            raise SecurityError("context_risk_assertion_mismatch")
        return raw

    def _verify_auth(self, request: PDPRequest, now: datetime) -> dict[str, Any]:
        raw = self._required_context_mapping(request, "auth_evidence")
        self._verify_assertion(raw, "auth_assertion", now)
        self._require_equal(raw, "subject_canonical_id", request.subject.canonical_id)
        self._require_equal(raw, "mapping_version", self.security_config.auth_factor_mapping_version)
        factors = raw.get("factors")
        if not isinstance(factors, dict):
            raise SecurityError("auth_factors_must_be_mapping")
        calculated = self.security_config.calculate_auth_strength(factors)
        claimed = int(raw.get("strength", -1))
        if calculated != claimed:
            raise SecurityError("auth_strength_calculation_mismatch")
        if request.context.auth_strength != claimed:
            raise SecurityError("context_auth_assertion_mismatch")
        return raw

    def _verify_workflow(self, request: PDPRequest, now: datetime) -> dict[str, Any] | None:
        if request.context.workflow_id is None:
            return None
        raw = self._required_context_mapping(request, "workflow_evidence")
        self._verify_assertion(raw, "workflow_assertion", now)
        self._require_equal(raw, "workflow_id", request.context.workflow_id)
        self._require_equal(raw, "workflow_instance_id", request.context.workflow_instance_id)
        return raw

    def _verify_optional_bound_assertion(
        self,
        raw: dict[str, Any],
        *,
        purpose: str,
        request: PDPRequest,
        now: datetime,
    ) -> dict[str, Any] | None:
        if not raw:
            return None
        if not isinstance(raw, dict):
            raise SecurityError(f"{purpose}_must_be_mapping")
        self._verify_assertion(raw, purpose, now)
        self._require_equal(raw, "request_hash", request.request_hash)
        self._require_equal(raw, "subject_canonical_id", request.subject.canonical_id)
        self._require_equal(raw, "resource_canonical_id", request.resource.canonical_id)
        self._require_equal(raw, "action", request.action)
        self._require_equal(raw, "workflow_instance_id", request.context.workflow_instance_id)
        if raw.get("decision", "ALLOW") != "ALLOW":
            raise SecurityError(f"{purpose}_did_not_allow")
        return raw

    def _verify_assertion(self, raw: dict[str, Any], purpose: str, now: datetime) -> None:
        self._verify_freshness(raw, purpose, now)
        issuer = self._required_string(raw, "issuer")
        key_id = self._required_string(raw, "key_id")
        signature = self._required_string(raw, "signature")
        key = self.keys.get(issuer, key_id, purpose)
        if not verify_mapping(key, assertion_payload(raw), signature):
            raise SecurityError(f"invalid_{purpose}_signature")

    def _verify_freshness(self, raw: dict[str, Any], purpose: str, now: datetime) -> None:
        if not isinstance(raw, dict):
            raise SecurityError(f"{purpose}_must_be_mapping")
        self._required_string(raw, "issuer")
        self._required_string(raw, "key_id")
        self._required_string(raw, "signature")
        issued_at = self._parse_time(raw, "issued_at")
        expires_at = self._parse_time(raw, "expires_at")
        skew = timedelta(seconds=self.security_config.clock_skew_seconds)
        if issued_at > now + skew:
            raise SecurityError(f"{purpose}_issued_in_future")
        if expires_at < now - skew:
            raise SecurityError(f"{purpose}_expired")
        if expires_at - issued_at > timedelta(seconds=self.security_config.max_assertion_lifetime_seconds):
            raise SecurityError(f"{purpose}_lifetime_too_long")

    @staticmethod
    def _context_extra(request: PDPRequest, key: str) -> Any:
        return (request.context.model_extra or {}).get(key)

    def _required_context_mapping(self, request: PDPRequest, key: str) -> dict[str, Any]:
        value = self._context_extra(request, key)
        if not isinstance(value, dict) or not value:
            raise SecurityError(f"missing_{key}")
        return value

    @staticmethod
    def _required_string(raw: dict[str, Any] | None, key: str) -> str:
        if raw is None:
            raise SecurityError(f"missing_{key}")
        value = raw.get(key)
        if not isinstance(value, str) or not value:
            raise SecurityError(f"missing_{key}")
        return value

    @staticmethod
    def _require_equal(raw: dict[str, Any], key: str, expected: Any) -> None:
        if raw.get(key) != expected:
            raise SecurityError(f"{key}_binding_mismatch")

    @staticmethod
    def _parse_time(raw: dict[str, Any], key: str) -> datetime:
        value = raw.get(key)
        if not isinstance(value, str):
            raise SecurityError(f"missing_{key}")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise SecurityError(f"invalid_{key}") from exc
        if parsed.tzinfo is None:
            raise SecurityError(f"{key}_must_include_timezone")
        return parsed
