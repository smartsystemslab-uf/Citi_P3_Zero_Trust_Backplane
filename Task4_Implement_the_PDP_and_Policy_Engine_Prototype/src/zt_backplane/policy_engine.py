from __future__ import annotations

from dataclasses import dataclass
from datetime import time
from decimal import Decimal, InvalidOperation
from typing import Any
from zoneinfo import ZoneInfo

from .audit import DecisionAuditLogger
from .identity import IdentityRegistry, ResourceCatalog
from .models import Decision, IdentityRecord, PDPRequest, PDPResponse, ResourceRecord, RiskLevel
from .policy_store import Policy, PolicyBundle


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


@dataclass(frozen=True)
class MatchContext:
    identity: IdentityRecord
    resource: ResourceRecord


class PolicyEngine:
    def __init__(
        self,
        bundle: PolicyBundle,
        identities: IdentityRegistry,
        resources: ResourceCatalog,
        audit_logger: DecisionAuditLogger | None = None,
    ):
        self.bundle = bundle
        self.identities = identities
        self.resources = resources
        self.audit_logger = audit_logger

    def evaluate(self, request: PDPRequest) -> PDPResponse:
        identity = self.identities.get(request.subject)
        if identity is None:
            return self._finish(request, Decision.DENY, "unknown_subject")
        if not identity.enabled:
            return self._finish(request, Decision.DENY, "subject_disabled")

        resource = self.resources.get(request.resource)
        if resource is None:
            return self._finish(request, Decision.DENY, "unknown_resource")
        if request.action not in resource.actions:
            return self._finish(request, Decision.DENY, "undefined_action_for_resource")

        ctx = MatchContext(identity=identity, resource=resource)
        matches = [p for p in self.bundle.policies if p.enabled and self._matches(p, request, ctx)]
        if not matches:
            return self._finish(request, Decision.DENY, "default_deny_no_matching_policy")

        highest_priority = max(policy.priority for policy in matches)
        finalists = [policy for policy in matches if policy.priority == highest_priority]
        selected = max(finalists, key=lambda policy: EFFECT_PRECEDENCE[policy.effect])
        matched_ids = [policy.id for policy in sorted(matches, key=lambda p: (-p.priority, p.id))]

        reason = f"matched_policy:{selected.id}"
        return self._finish(
            request,
            selected.effect,
            reason,
            policy=selected,
            matched_policy_ids=matched_ids,
        )

    def _finish(
        self,
        request: PDPRequest,
        decision: Decision,
        reason: str,
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
        )
        if self.audit_logger is not None:
            self.audit_logger.write(request, response)
        return response

    def _matches(self, policy: Policy, request: PDPRequest, ctx: MatchContext) -> bool:
        match = policy.match

        checks = [
            _list_match(request.subject, match.get("subjects")),
            _intersection_match(ctx.identity.roles, match.get("subject_roles")),
            _list_match(ctx.identity.domain, match.get("subject_domains")),
            _list_match(request.resource, match.get("resources")),
            _list_match(ctx.resource.domain, match.get("resource_domains")),
            _list_match(ctx.resource.classification, match.get("resource_classifications")),
            _list_match(request.action, match.get("actions")),
            _list_match(request.context.workflow, match.get("workflows")),
            _list_match(request.context.risk.value, match.get("risk_levels")),
        ]
        if not all(checks):
            return False

        risk_value = RISK_ORDER[request.context.risk.value]
        if "min_risk" in match and risk_value < RISK_ORDER[str(match["min_risk"]).lower()]:
            return False
        if "max_risk" in match and risk_value > RISK_ORDER[str(match["max_risk"]).lower()]:
            return False

        auth_strength = request.context.auth_strength
        if "auth_strength_gte" in match and auth_strength < int(match["auth_strength_gte"]):
            return False
        if "auth_strength_lte" in match and auth_strength > int(match["auth_strength_lte"]):
            return False

        if "human_approved" in match and request.context.human_approved is not bool(match["human_approved"]):
            return False

        if not _context_equals(request, match.get("context_equals")):
            return False
        if not _parameter_conditions(request.parameters, match.get("parameter_conditions")):
            return False
        if not _time_windows(request, match.get("time_windows")):
            return False

        return True


def _list_match(value: str | None, accepted: Any) -> bool:
    if accepted is None:
        return True
    if not isinstance(accepted, list):
        raise ValueError("list-based policy matcher must be a list")
    if "*" in accepted:
        return True
    return value in accepted


def _intersection_match(values: list[str], accepted: Any) -> bool:
    if accepted is None:
        return True
    if not isinstance(accepted, list):
        raise ValueError("role matcher must be a list")
    if "*" in accepted:
        return True
    return bool(set(values).intersection(accepted))


def _context_equals(request: PDPRequest, expected: Any) -> bool:
    if expected is None:
        return True
    if not isinstance(expected, dict):
        raise ValueError("context_equals must be a mapping")
    context = request.context.model_dump(mode="python")
    context.update(request.context.model_extra or {})
    for key, expected_value in expected.items():
        actual = _get_path(context, str(key))
        if actual != expected_value:
            return False
    return True


def _parameter_conditions(parameters: dict[str, Any], conditions: Any) -> bool:
    if conditions is None:
        return True
    if not isinstance(conditions, list):
        raise ValueError("parameter_conditions must be a list")
    for item in conditions:
        if not isinstance(item, dict):
            return False
        path = str(item.get("path", ""))
        op = str(item.get("op", "eq"))
        expected = item.get("value")
        actual = _get_path(parameters, path)
        if not _compare(actual, op, expected):
            return False
    return True


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
        except (InvalidOperation, ValueError, TypeError):
            return False
        return {
            "gt": left > right,
            "gte": left >= right,
            "lt": left < right,
            "lte": left <= right,
        }[op]
    raise ValueError(f"unsupported parameter condition operator: {op}")


def _get_path(data: Any, path: str) -> Any:
    current = data
    for part in path.split(".") if path else []:
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _time_windows(request: PDPRequest, windows: Any) -> bool:
    if windows is None:
        return True
    if not isinstance(windows, list):
        raise ValueError("time_windows must be a list")

    source_ts = request.context.effective_timestamp()
    for window in windows:
        if not isinstance(window, dict):
            continue
        tz = ZoneInfo(str(window.get("timezone", "UTC")))
        local_ts = source_ts.astimezone(tz)
        days = window.get("days", ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"])
        if local_ts.strftime("%a").upper()[:3] not in days:
            continue
        start = _parse_time(str(window.get("start", "00:00")))
        end = _parse_time(str(window.get("end", "23:59:59")))
        now = local_ts.time().replace(tzinfo=None)
        if start <= end:
            if start <= now <= end:
                return True
        else:  # overnight window, e.g. 22:00-06:00
            if now >= start or now <= end:
                return True
    return False


def _parse_time(value: str) -> time:
    parts = [int(item) for item in value.split(":")]
    if len(parts) == 2:
        return time(parts[0], parts[1])
    if len(parts) == 3:
        return time(parts[0], parts[1], parts[2])
    raise ValueError(f"invalid time: {value}")
