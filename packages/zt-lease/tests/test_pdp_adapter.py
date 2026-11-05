from __future__ import annotations

import pytest

from zt_lease.errors import DecisionVerificationError
from zt_lease.pdp_adapter import PdpDecisionAdapter


def test_pdp_signed_decision_tampering_is_rejected(environment):
    request = environment["make_request"]()
    envelope = environment["pdp_allow"](request)
    envelope.body["policy_version"] = "attacker-policy"
    decision = PdpDecisionAdapter().normalize(envelope, request)
    with pytest.raises(DecisionVerificationError, match="signature"):
        environment["components"].state_machine.verifier.verify(
            envelope, decision, request
        )
