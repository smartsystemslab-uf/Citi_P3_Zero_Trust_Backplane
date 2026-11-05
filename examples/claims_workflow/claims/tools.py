"""Tools of the claims desk: an in-memory policy register and payment ledger."""
from __future__ import annotations

POLICIES = {"P-100": {"holder": "alice", "limit": 5000, "state": "active"},
            "P-200": {"holder": "bob", "limit": 800, "state": "active"}}
HISTORY = {"C-1": ["2026-03-02 windshield", "2026-07-19 towing"]}
PAYMENTS: list[dict] = []


def lookup_policy(policy_id: str) -> dict:
    """Look up an insurance policy."""
    policy = POLICIES.get(policy_id)
    if policy is None:
        return {"status": "not_found", "policy_id": policy_id}
    return {"status": "ok", "policy_id": policy_id, **policy}


def read_claim_history(claim_id: str) -> dict:
    """Read the earlier claims of a claim's policy holder."""
    return {"status": "ok", "claim_id": claim_id, "history": HISTORY.get(claim_id, [])}


def pay_claim(claim_id: str, amount: int) -> dict:
    """Pay out an approved claim to the policy holder."""
    PAYMENTS.append({"claim_id": claim_id, "amount": amount})
    return {"status": "paid", "claim_id": claim_id, "amount": amount}
