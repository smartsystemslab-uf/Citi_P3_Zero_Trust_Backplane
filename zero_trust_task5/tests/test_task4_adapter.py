from __future__ import annotations

import pytest

from zt_task5.errors import DecisionVerificationError
from zt_task5.task4_adapter import Task4DecisionAdapter


def test_task4_signed_decision_tampering_is_rejected(environment):
    request = environment["make_request"]()
    envelope = environment["pdp_allow"](request)
    envelope.body["policy_version"] = "attacker-policy"
    decision = Task4DecisionAdapter().normalize(envelope, request)
    with pytest.raises(DecisionVerificationError, match="signature"):
        environment["components"].state_machine.verifier.verify(
            envelope, decision, request
        )
