from __future__ import annotations

from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zt_task5.errors import IdempotencyError, LeaseValidationError
from zt_task5.models import RuntimeState
from zt_task5.proof_of_possession import create_proof_of_possession
from zt_task5.task3_adapter import Task3PEPAdapter, augment_generated_pep_plan


def authorize(env, request):
    return env["components"].state_machine.authorize(
        request,
        env["pdp_allow"],
        pep_identity=env["pep_identity"],
        pep_private_key=env["pep_private"],
    )


def timeout(_request):
    raise TimeoutError("PDP unavailable")


def test_task4_task5_happy_path(environment):
    request = environment["make_request"]()
    result = authorize(environment, request)
    assert result.allowed is True
    assert result.state == RuntimeState.ACTIVE_LEASE
    assert result.source == "PDP"
    assert result.validation.obligations == [{"type": "enhanced_logging"}]


def test_expired_permit_is_rejected(environment):
    request = environment["make_request"]()
    result = authorize(environment, request)
    signed = environment["components"].validator.decode_and_verify(result.token)
    future = signed.claims.expires_at + timedelta(seconds=1)
    pop = create_proof_of_possession(
        signed.claims, environment["pep_private"], issued_at=future
    )
    with pytest.raises(LeaseValidationError, match="expired"):
        environment["components"].validator.validate(
            result.token, request, pop, now=future
        )


def test_single_use_critical_permit_replay_is_rejected(environment):
    request = environment["make_request"](critical=True)
    result = authorize(environment, request)
    signed = environment["components"].validator.decode_and_verify(result.token)
    pop = create_proof_of_possession(signed.claims, environment["pep_private"])
    with pytest.raises(LeaseValidationError, match="replayed"):
        environment["components"].validator.validate(result.token, request, pop)


def test_modified_request_parameters_are_rejected(environment):
    original = environment["make_request"](amount=100)
    result = authorize(environment, original)
    signed = environment["components"].validator.decode_and_verify(result.token)
    modified = environment["make_request"](amount=1000)
    pop = create_proof_of_possession(signed.claims, environment["pep_private"])
    with pytest.raises(LeaseValidationError, match="modified"):
        environment["components"].validator.validate(result.token, modified, pop)


def test_old_policy_version_is_rejected(environment):
    request = environment["make_request"]()
    result = authorize(environment, request)
    signed = environment["components"].validator.decode_and_verify(result.token)
    environment["components"].revocations.set_policy_version("policy-v2")
    pop = create_proof_of_possession(signed.claims, environment["pep_private"])
    with pytest.raises(Exception, match="stale|old policy"):
        environment["components"].validator.validate(result.token, request, pop)


def test_revoked_identity_is_rejected(environment):
    request = environment["make_request"]()
    result = authorize(environment, request)
    signed = environment["components"].validator.decode_and_verify(result.token)
    environment["components"].revocations.revoke_subject(request.subject)
    pop = create_proof_of_possession(signed.claims, environment["pep_private"])
    with pytest.raises(Exception, match="stale|revoked"):
        environment["components"].validator.validate(result.token, request, pop)


def test_different_workflow_is_rejected(environment):
    request = environment["make_request"](workflow="wf-a")
    result = authorize(environment, request)
    signed = environment["components"].validator.decode_and_verify(result.token)
    other = environment["make_request"](workflow="wf-b")
    pop = create_proof_of_possession(signed.claims, environment["pep_private"])
    with pytest.raises(LeaseValidationError):
        environment["components"].validator.validate(result.token, other, pop)


def test_pdp_timeout_without_valid_lease_fails_closed(environment):
    request = environment["make_request"]()
    result = environment["components"].state_machine.authorize(
        request,
        timeout,
        pep_identity=environment["pep_identity"],
        pep_private_key=environment["pep_private"],
    )
    assert result.allowed is False
    assert result.state == RuntimeState.DENIED
    assert result.reason == "PDP_TIMEOUT_NO_VALID_LEASE"


def test_pdp_timeout_with_valid_matching_lease_succeeds(environment):
    request = environment["make_request"]()
    first = authorize(environment, request)
    assert first.allowed
    retry = environment["make_request"]()  # new request_id, same protected operation
    result = environment["components"].state_machine.authorize(
        retry,
        timeout,
        pep_identity=environment["pep_identity"],
        pep_private_key=environment["pep_private"],
    )
    assert result.allowed is True
    assert result.source == "CACHE"


def test_pep_restart_clears_cache_and_disables_fallback(environment):
    request = environment["make_request"]()
    assert authorize(environment, request).allowed
    environment["components"].lease_cache.restart()
    result = environment["components"].state_machine.authorize(
        request,
        timeout,
        pep_identity=environment["pep_identity"],
        pep_private_key=environment["pep_private"],
    )
    assert result.allowed is False
    assert result.reason == "PDP_TIMEOUT_NO_VALID_LEASE"


def test_stolen_permit_from_different_sender_key_is_rejected(environment):
    request = environment["make_request"]()
    result = authorize(environment, request)
    signed = environment["components"].validator.decode_and_verify(result.token)
    attacker = Ed25519PrivateKey.generate()
    environment["components"].sender_registry.register("pep://attacker", attacker.public_key())
    pop = create_proof_of_possession(signed.claims, attacker)
    with pytest.raises(Exception, match="mismatch|wrong sender"):
        environment["components"].validator.validate(result.token, request, pop)


def test_context_assertion_substitution_is_rejected(environment):
    request = environment["make_request"]()
    result = authorize(environment, request)
    signed = environment["components"].validator.decode_and_verify(result.token)
    changed_evidence = dict(request.evidence)
    changed_evidence["risk"] = dict(changed_evidence["risk"], score=900)
    substituted = environment["make_request"](evidence=changed_evidence)
    pop = create_proof_of_possession(signed.claims, environment["pep_private"])
    with pytest.raises(LeaseValidationError, match="Context assertion changed"):
        environment["components"].validator.validate(result.token, substituted, pop)


def test_task3_adapter_blocks_duplicate_financial_execution(environment):
    request = environment["make_request"](critical=True)
    adapter = Task3PEPAdapter(
        environment["components"].state_machine,
        environment["pdp_allow"],
        pep_identity=environment["pep_identity"],
        pep_private_key=environment["pep_private"],
        idempotency_guard=environment["components"].idempotency_guard,
    )
    calls = []
    assert adapter.execute(request, lambda: calls.append("executed") or "ok") == "ok"
    with pytest.raises(IdempotencyError, match="Duplicate"):
        adapter.execute(request, lambda: calls.append("executed-again"))
    assert calls == ["executed"]


def test_task3_plan_is_augmented_without_changing_stable_ids():
    plan = {
        "interface_version": "1.0",
        "peps": [
            {
                "pep_id": "tool-pep-transfer",
                "resource_id": "banking_api.transfer",
                "action_id": "execute",
                "critical": True,
            }
        ],
    }
    augmented = augment_generated_pep_plan(plan)
    pep = augmented["peps"][0]
    assert pep["pep_id"] == "tool-pep-transfer"
    assert pep["task5"]["max_uses"] == 1
    assert pep["task5"]["pdp_timeout_mode"] == "VALID_MATCHING_LEASE_ONLY"


def test_audit_chain_is_complete(environment):
    request = environment["make_request"]()
    authorize(environment, request)
    environment["components"].state_machine.authorize(
        environment["make_request"](),
        timeout,
        pep_identity=environment["pep_identity"],
        pep_private_key=environment["pep_private"],
    )
    assert environment["components"].audit_log.verify() is True
    assert len(environment["components"].audit_log.events()) == 2
