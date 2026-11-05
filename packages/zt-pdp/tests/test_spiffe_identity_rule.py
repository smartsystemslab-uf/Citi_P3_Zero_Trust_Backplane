"""identity.psl: the PDP re-checks the gateway's SPIFFE scheme B authentication result
carried in the IdP-signed authentication assertion (auth.scheme, auth.factor.*,
auth.agent_bound). Requests without an authentication block are unaffected."""
from __future__ import annotations

from zt_pdp.crypto import load_private_key, sign_mapping
from zt_pdp.models import Decision

from .helpers import ROOT, resign_request, signed_request

FACTORS_B = {"workload_identity": True, "agent_credential": True}


def fraud_read(runtime, *, factors=None, authentication=None):
    request = signed_request(
        runtime,
        subject_canonical_id="agent.front_office.fraud",
        subject_runtime_id="fraud_agent",
        resource_canonical_id="resource.front_office.transaction_history",
        resource_runtime_id="transaction_history",
        action="read",
        workflow_id="workflow.front_office.fraud_review",
        workflow_instance_id="fraud-wf-1",
        auth_factors=factors,
    )
    if authentication is not None:              # what the gateway's backplane adapter adds
        extra = request.context.__pydantic_extra__
        auth = {k: v for k, v in dict(extra["auth_evidence"]).items() if k != "signature"}
        auth["authentication"] = authentication
        auth["signature"] = sign_mapping(load_private_key(ROOT / "security" / "dev_keys" / "idp_private.pem"), auth)
        extra["auth_evidence"] = auth
        resign_request(request)
    return runtime.engine.evaluate(request)


def scheme_b(agent_id="fraud_agent", subject_kind="agent"):
    return {"auth_mode": "B", "subject_kind": subject_kind, "method": "spiffe-x509svid-mtls+agent-cert+rfc9421",
            "workload_spiffe_id": "spiffe://citi-p3.test/ztbp/wl/fraud_agent", "agent_id": agent_id,
            "agent_credential_id": "abc123", "credential_expiry": None}


def test_fully_verified_scheme_b_agent_is_decided_by_the_business_policies(runtime):
    result = fraud_read(runtime, factors=FACTORS_B, authentication=scheme_b())
    assert result.decision == Decision.ALLOW_WITH_OBLIGATIONS
    assert result.policy_id == "policy.front_office.fraud_read_transaction_history"


def test_scheme_b_without_agent_credential_factor_is_denied(runtime):
    result = fraud_read(runtime, factors={"workload_identity": True}, authentication=scheme_b())
    assert result.decision == Decision.DENY
    assert result.policy_id == "identity.spiffe-b-agent-verified"


def test_scheme_b_assertion_for_another_agent_is_denied(runtime):
    result = fraud_read(runtime, factors=FACTORS_B, authentication=scheme_b(agent_id="transaction_processing_agent"))
    assert result.decision == Decision.DENY
    assert result.policy_id == "identity.spiffe-b-agent-verified"


def test_requests_without_authentication_block_are_unaffected(runtime):
    result = fraud_read(runtime)          # in-process native runtime: original factor claim, no scheme
    assert result.decision == Decision.ALLOW_WITH_OBLIGATIONS


def test_service_identity_cannot_obtain_tool_decisions(runtime):
    """identity.spiffe-b-service-io-only: the ingress service's SVID authorizes only the MAS
    input/output channels, never a tool or route on behalf of an agent subject."""
    svc = {**scheme_b(agent_id="cli_user", subject_kind="service"), "agent_credential_id": None}
    result = fraud_read(runtime, factors={"workload_identity": True}, authentication=svc)
    assert result.decision == Decision.DENY
    assert result.policy_id == "identity.spiffe-b-service-io-only"


def test_unknown_subject_kind_is_denied(runtime):
    result = fraud_read(runtime, factors=FACTORS_B, authentication=scheme_b(subject_kind="robot"))
    assert result.decision == Decision.DENY
    assert result.policy_id == "identity.spiffe-b-known-subject-kind"


def test_non_text_authentication_values_are_ignored(runtime):
    bad = {**scheme_b(), "auth_mode": ["B"]}        # not a string: no scheme, rule does not apply
    assert fraud_read(runtime, factors=FACTORS_B, authentication=bad).decision == Decision.ALLOW_WITH_OBLIGATIONS
