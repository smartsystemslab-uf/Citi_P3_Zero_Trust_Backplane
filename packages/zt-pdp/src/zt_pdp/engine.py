"""PDP decision engine -- PSL policies, deny-overrides.

Order of evaluation for one request:

1. evidence verification (PEP request proof, replay, signed risk / authentication /
   workflow / approval assertions) -- failure: DENY;
2. structural checks against the registries (unknown subject, unknown resource,
   action not defined for the resource) -- failure: DENY;
3. PSL policies (``policy_store/*.psl``, ``zt_psl``): the request's verified facts
   are bound to the fields of the signed field catalogue; every rule must hold
   (deny-overrides); the outcome is the strictest violated rule's @on_violation, else
   ALLOW / ALLOW_WITH_OBLIGATIONS with the obligations of the permissions that hold.

A field a rule needs but that is not available fails closed (DENY). The former
hard-coded critical-write rule is the PSL rule core.critical_write_requires_dual_approval.
The previous priority-based engine is kept in legacy_engine.py for the differential test.
"""
from __future__ import annotations

import time as perf_time

from zt_psl import UnboundField

from .audit import ChainedAuditLogger
from .evidence import EvidenceVerifier, SecurityError
from .models import Decision, Obligation, PDPRequest, PDPResponse, VerifiedSecurityContext
from .psl_fields import request_fields
from .psl_policy import PslPolicyStore
from .registry import IdentityRegistry, ResourceCatalog

OUTCOME = {
    "ALLOW": Decision.ALLOW,
    "ALLOW_WITH_OBLIGATIONS": Decision.ALLOW_WITH_OBLIGATIONS,
    "DENY": Decision.DENY,
    "REAUTHENTICATE": Decision.REAUTHENTICATE,
    "MANUAL_REVIEW": Decision.MANUAL_REVIEW,
}
STRICTNESS = {"DENY": 3, "REAUTHENTICATE": 2, "MANUAL_REVIEW": 1}


class PolicyEngine:
    def __init__(
        self,
        *,
        bundle: PslPolicyStore,
        identities: IdentityRegistry,
        resources: ResourceCatalog,
        evidence_verifier: EvidenceVerifier,
        audit_logger: ChainedAuditLogger | None = None,
    ):
        if not isinstance(bundle, PslPolicyStore):
            raise TypeError("PolicyEngine needs a signed PSL policy store (PslPolicyStore.load)")
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
            return self._finish(request, Decision.DENY, f"security_verification_failed:{exc}",
                                security=None, started_ns=started_ns)

        identity = self.identities.resolve(request.subject.canonical_id, request.subject.runtime_id)
        if identity is None:
            return self._finish(request, Decision.DENY, "unknown_or_mismatched_subject", security=security,
                                started_ns=started_ns)
        resource = self.resources.resolve(request.resource.canonical_id, request.resource.runtime_id)
        if resource is None:
            return self._finish(request, Decision.DENY, "unknown_or_mismatched_resource", security=security,
                                started_ns=started_ns)
        if request.action not in resource.actions:
            return self._finish(request, Decision.DENY, "undefined_action_for_resource", security=security,
                                started_ns=started_ns)

        try:
            decision = self.bundle.engine.decide(request_fields(request, identity, resource, security, self.bundle))
        except UnboundField as exc:
            return self._finish(request, Decision.DENY, f"psl_unbound_field:{exc.name}", security=security,
                                started_ns=started_ns)
        except TypeError as exc:
            return self._finish(request, Decision.DENY, f"psl_field_type_error:{exc}", security=security,
                                started_ns=started_ns)

        if decision.allowed:
            deciding = decision.permits[0].rule_id
        else:
            # report the rule that set the outcome; an explicit rule is more informative than the
            # generated default deny when both are violated (all violated rules are in matched_policy_ids)
            strictest = max(STRICTNESS[v.on_violation] for v in decision.violated)
            candidates = [v for v in decision.violated if STRICTNESS[v.on_violation] == strictest]
            explicit = [v for v in candidates if v.kind != "default_deny"]
            deciding = (explicit or candidates)[0].rule_id
        matched = [p.rule_id for p in decision.permits] + [v.rule_id for v in decision.violated]
        obligations = [Obligation(type=o.type, parameters=o.as_dict()["parameters"]) for o in decision.obligations]
        return self._finish(request, OUTCOME[decision.outcome], decision.reason(), security=security,
                            started_ns=started_ns, policy_id=deciding, matched_policy_ids=matched,
                            obligations=obligations)

    def _finish(
        self,
        request: PDPRequest,
        decision: Decision,
        reason: str,
        *,
        security: VerifiedSecurityContext | None,
        started_ns: int,
        policy_id: str | None = None,
        matched_policy_ids: list[str] | None = None,
        obligations: list[Obligation] | None = None,
    ) -> PDPResponse:
        response = PDPResponse(
            request_id=request.request_id,
            trace_id=request.trace_id,
            decision=decision,
            reason=reason,
            policy_id=policy_id,
            matched_policy_ids=matched_policy_ids or [],
            policy_version=self.bundle.version,
            obligations=obligations or [],
            decided_at=security.decision_time if security else self.evidence_verifier.clock.now(),
            cache_control="NO_STORE",
            permit_lease=None,
        )
        if self.audit_logger is not None:
            self.audit_logger.write(request, response, security, started_ns=started_ns)
        return response
