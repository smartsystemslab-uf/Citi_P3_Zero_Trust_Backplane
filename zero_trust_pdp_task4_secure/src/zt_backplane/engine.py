from __future__ import annotations

import time as perf_time
from dataclasses import dataclass
from datetime import time
from decimal import Decimal, InvalidOperation
from typing import Any
from zoneinfo import ZoneInfo

from .audit import ChainedAuditLogger
from .evidence import EvidenceVerifier, SecurityError
from .models import Decision, IdentityRecord, PDPRequest, PDPResponse, ResourceRecord, RiskLevel, VerifiedSecurityContext
from .policy import Policy, PolicyBundle
from .registry import IdentityRegistry, ResourceCatalog


RISK_ORDER = {
    RiskLevel.LOW.value: 0,
    RiskLevel.MEDIUM.value: 1,
    RiskLevel.HIGH.value: 2,
    RiskLevel.CRITICAL.value: 3,
}

EFFECT_PRECEDENCE = {
    Decision.DENY: 5,
    Decision.REAUTHENTICATE: 4,
    Decision.MANUAL_REVIEW: 3,
    Decision.ALLOW_WITH_OBLIGATIONS: 2,
    Decision.ALLOW: 1,
}

CRITICAL_WRITE_ACTIONS = {"execute", "update", "approve", "reject", "submit", "cancel", "store", "create"}


@dataclass(frozen=True)
class MatchContext:
    identity: IdentityRecord
    resource: ResourceRecord
    security: VerifiedSecurityContext


class PolicyEngine:
    def __init__(
        self,
        *,
        bundle: PolicyBundle,
        identities: IdentityRegistry,
        resources: ResourceCatalog,
        evidence_verifier: EvidenceVerifier,
        audit_logger: ChainedAuditLogger | None = None,
    ):
        self.bundle = bundle
        self.identities = identities
        self.resources = resources
        self.evidence_verifier = evidence_verifier
        self.audit_logger = audit_logger

    def evaluate(self, request: PDPRequest) -> PDPResponse:
        started_ns = perf_time.perf_counter_ns()
        security: VerifiedSecurityContext | None = None
        try:
            security = self.evidence_verifier.verify(request)
        except (SecurityError, ValueError) as exc:
            return self._finish(
                request,
                Decision.DENY,
                f"security_verification_failed:{exc}",
                security=None,
                started_ns=started_ns,
            )

        identity = self.identities.resolve(request.subject.canonical_id, request.subject.runtime_id)
        if identity is None:
            return self._finish(request, Decision.DENY, "unknown_or_mismatched_subject", security=security, started_ns=started_ns)
        resource = self.resources.resolve(request.resource.canonical_id, request.resource.runtime_id)
        if resource is None:
            return self._finish(request, Decision.DENY, "unknown_or_mismatched_resource", security=security, started_ns=started_ns)
        if request.action not in resource.actions:
            return self._finish(request, Decision.DENY, "undefined_action_for_resource", security=security, started_ns=started_ns)

        ctx = MatchContext(identity=identity, resource=resource, security=security)
        matches = [policy for policy in self.bundle.policies if policy.enabled and self._matches(policy, request, ctx)]
        if not matches:
            return self._finish(
                request,
                Decision.DENY,
                "default_deny_no_matching_policy",
                security=security,
                started_ns=started_ns,
            )

        highest_priority = max(policy.priority for policy in matches)
        finalists = [policy for policy in matches if policy.priority == highest_priority]
        selected = max(finalists, key=lambda policy: EFFECT_PRECEDENCE[policy.effect])
        matched_ids = [policy.id for policy in sorted(matches, key=lambda item: (-item.priority, item.id))]

        decision = selected.effect
        reason = f"matched_policy:{selected.id}"
        if (
            decision in {Decision.ALLOW, Decision.ALLOW_WITH_OBLIGATIONS}
            and resource.critical
            and request.action in CRITICAL_WRITE_ACTIONS
            and not (security.approval_valid and security.secondary_authorization_valid)
        ):
            decision = Decision.MANUAL_REVIEW
            reason = "critical_write_requires_signed_approval_and_secondary_authorization"

        return self._finish(
            request,
            decision,
            reason,
            policy=selected,
            matched_policy_ids=matched_ids,
            security=security,
            started_ns=started_ns,
        )

    def _finish(
        self,
        request: PDPRequest,
        decision: Decision,
        reason: str,
        *,
        security: VerifiedSecurityContext | None,
        started_ns: int,
        policy: Policy | None = None,
        matched_policy_ids: list[str] | None = None,
    ) -> PDPResponse:
        response = PDPResponse(
            request_id=request.request_id,
            trace_id=request.trace_id,
            decision=decision,
            reason=reason,
            policy_id=policy.id if policy else None,
            matched_policy_ids=matched_policy_ids or [],
            policy_version=self.bundle.version,
            obligations=policy.obligations if policy else [],
            decided_at=security.decision_time if security else self.evidence_verifier.clock.now(),
            cache_control="NO_STORE",
            permit_lease=None,
        )
        if self.audit_logger is not None:
            self.audit_logger.write(request, response, security, started_ns=started_ns)
        return response

    def _matches(self, policy: Policy, request: PDPRequest, ctx: MatchContext) -> bool:
        match = policy.match
        checks = [
            _list_match(request.subject.canonical_id, match.get("subjects")),
            _intersection_match(ctx.identity.roles, match.get("subject_roles")),
            _list_match(ctx.identity.domain, match.get("subject_domains")),
            _list_match(request.resource.canonical_id, match.get("resources")),
            _list_match(ctx.resource.domain, match.get("resource_domains")),
            _list_match(ctx.resource.classification, match.get("resource_classifications")),
            _list_match(request.action, match.get("actions")),
            _list_match(request.context.workflow_id, match.get("workflows")),
            _list_match(request.context.environment, match.get("environments")),
            _list_match(ctx.security.risk_level.value, match.get("risk_levels")),
        ]
        if not all(checks):
            return False

        risk_value = RISK_ORDER[ctx.security.risk_level.value]
        if "min_risk" in match and risk_value < RISK_ORDER[str(match["min_risk"]).lower()]:
            return False
        if "max_risk" in match and risk_value > RISK_ORDER[str(match["max_risk"]).lower()]:
            return False
        if "min_risk_score" in match and ctx.security.risk_score < int(match["min_risk_score"]):
            return False
        if "max_risk_score" in match and ctx.security.risk_score > int(match["max_risk_score"]):
            return False
        if "auth_strength_gte" in match and ctx.security.auth_strength < int(match["auth_strength_gte"]):
            return False
        if "auth_strength_lte" in match and ctx.security.auth_strength > int(match["auth_strength_lte"]):
            return False
        if "approval_valid" in match and ctx.security.approval_valid is not bool(match["approval_valid"]):
            return False
        if (
            "secondary_authorization_valid" in match
            and ctx.security.secondary_authorization_valid is not bool(match["secondary_authorization_valid"])
        ):
            return False
        if not _parameter_conditions(request.parameters, match.get("parameter_conditions")):
            return False
        if not _time_windows(ctx.security.decision_time, match.get("time_windows")):
            return False
        return True


def _list_match(value: str | None, accepted: Any) -> bool:
    if accepted is None:
        return True
    if not isinstance(accepted, list):
        raise ValueError("list-based policy matcher must be a list")
    return "*" in accepted or value in accepted


def _intersection_match(values: list[str], accepted: Any) -> bool:
    if accepted is None:
        return True
    if not isinstance(accepted, list):
        raise ValueError("role matcher must be a list")
    return "*" in accepted or bool(set(values).intersection(accepted))


def _parameter_conditions(parameters: dict[str, Any], conditions: Any) -> bool:
    if conditions is None:
        return True
    if not isinstance(conditions, list):
        raise ValueError("parameter_conditions must be a list")
    for condition in conditions:
        if not isinstance(condition, dict):
            raise ValueError("each parameter condition must be a mapping")
        actual = _get_path(parameters, str(condition.get("path", "")))
        op = str(condition.get("op", "eq"))
        expected = condition.get("value")
        if not _compare(actual, op, expected):
            return False
    return True


def _get_path(value: Any, path: str) -> Any:
    current = value
    for segment in path.split(".") if path else []:
        if not isinstance(current, dict) or segment not in current:
            return None
        current = current[segment]
    return current


def _compare(actual: Any, op: str, expected: Any) -> bool:
    if op == "exists":
        return actual is not None
    if op == "not_exists":
        return actual is None
    if op == "eq":
        return actual == expected
    if op == "ne":
        return actual != expected
    if op == "in":
        return isinstance(expected, list) and actual in expected
    if op == "not_in":
        return isinstance(expected, list) and actual not in expected
    if op in {"gt", "gte", "lt", "lte"}:
        try:
            left = Decimal(str(actual))
            right = Decimal(str(expected))
        except (InvalidOperation, TypeError):
            return False
        return {
            "gt": left > right,
            "gte": left >= right,
            "lt": left < right,
            "lte": left <= right,
        }[op]
    raise ValueError(f"unsupported parameter operator: {op}")


def _time_windows(decision_time, windows: Any) -> bool:
    if windows is None:
        return True
    if not isinstance(windows, list):
        raise ValueError("time_windows must be a list")
    for window in windows:
        if not isinstance(window, dict):
            raise ValueError("each time window must be a mapping")
        timezone_name = str(window.get("timezone", "UTC"))
        local = decision_time.astimezone(ZoneInfo(timezone_name))
        days = window.get("days")
        if days and local.strftime("%a").upper()[:3] not in {str(item).upper() for item in days}:
            continue
        start = time.fromisoformat(str(window["start"]))
        end = time.fromisoformat(str(window["end"]))
        current = local.timetz().replace(tzinfo=None)
        within = start <= current <= end if start <= end else current >= start or current <= end
        if within:
            return True
    return False
