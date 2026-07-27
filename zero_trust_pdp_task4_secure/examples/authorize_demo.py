#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

import httpx

from zt_backplane.decision_signing import verify_decision_headers
from zt_backplane.dev_evidence import build_signed_request


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pdp", default="http://127.0.0.1:8080")
    args = parser.parse_args()
    challenge = httpx.post(
        f"{args.pdp}/v1/challenge",
        json={
            "subject_canonical_id": "agent.front_office.fraud",
            "subject_runtime_id": "fraud_agent",
        },
        timeout=2.0,
    )
    challenge.raise_for_status()
    nonce = challenge.json()["nonce"]
    request = build_signed_request(
        nonce=nonce,
        subject_canonical_id="agent.front_office.fraud",
        subject_runtime_id="fraud_agent",
        resource_canonical_id="resource.front_office.transaction_history",
        resource_runtime_id="transaction_history",
        action="read",
        workflow_id="workflow.front_office.fraud_review",
        workflow_instance_id="demo-fraud-review-1",
        risk_score=300,
        auth_factors={"workload_identity": True, "user_session": True},
    )
    response = httpx.post(
        f"{args.pdp}/v1/authorize",
        json=request.model_dump(mode="json"),
        timeout=2.0,
    )
    response.raise_for_status()
    body = response.json()
    valid = verify_decision_headers(
        body,
        response.headers,
        ROOT / "security" / "dev_keys" / "pdp_signing_public.pem",
        expected_request_hash=request.request_hash,
    )
    print(body)
    print(f"decision_signature_valid={valid}")


if __name__ == "__main__":
    main()
