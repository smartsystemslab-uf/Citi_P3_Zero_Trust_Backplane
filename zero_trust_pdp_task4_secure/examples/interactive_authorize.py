#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import httpx

from zt_backplane.decision_signing import verify_decision_headers
from zt_backplane.dev_evidence import build_signed_request


ROOT = Path(__file__).resolve().parents[1]

AGENTS = {
    "1": ("Fraud Agent", "agent.front_office.fraud", "fraud_agent"),
    "2": ("Customer Service Agent", "agent.front_office.customer_service", "customer_service_agent"),
    "3": ("Transaction Processing Agent", "agent.front_office.transaction_processing", "transaction_processing_agent"),
    "4": ("Report Agent", "agent.back_office.report", "report_agent"),
    "5": ("EOD Agent", "agent.back_office.eod", "eod_agent"),
    "6": ("Financial Data Agent", "agent.mid_office.financial_data", "financial_data_agent"),
}

RESOURCES = {
    "1": ("Transaction History", "resource.front_office.transaction_history", "transaction_history"),
    "2": ("Banking Transfer", "resource.front_office.banking_transfer", "banking_transfer"),
    "3": ("Customer Profile", "resource.front_office.customer_profile", "customer_profile"),
    "4": ("Reconciliation Results", "resource.back_office.reconciliation_results", "reconciliation_results"),
    "5": ("Ledger", "resource.back_office.ledger", "ledger"),
    "6": ("Financial Customer Data", "resource.mid_office.financial_customer_data", "financial_customer_data"),
}

WORKFLOWS = {
    "0": ("No workflow", None),
    "1": ("Fraud Review", "workflow.front_office.fraud_review"),
    "2": ("Customer Transaction", "workflow.front_office.customer_transaction"),
    "3": ("EOD Processing", "workflow.back_office.eod_processing"),
}


def choose(title: str, options: dict[str, tuple[Any, ...]]) -> tuple[Any, ...]:
    print(f"\n{title}")
    for key, value in options.items():
        print(f"  {key}. {value[0]}")
    while True:
        selected = input("Select: ").strip()
        if selected in options:
            return options[selected]
        print("Invalid selection. Try again.")


def yes_no(prompt: str, default: bool = False) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    value = input(prompt + suffix).strip().lower()
    if not value:
        return default
    return value in {"y", "yes"}


def read_int(prompt: str, default: int, minimum: int, maximum: int) -> int:
    while True:
        value = input(f"{prompt} [{default}]: ").strip()
        if not value:
            return default
        try:
            number = int(value)
        except ValueError:
            print("Please enter an integer.")
            continue
        if minimum <= number <= maximum:
            return number
        print(f"Enter a value between {minimum} and {maximum}.")


def read_parameters() -> dict[str, Any]:
    raw = input('Business parameters as JSON, or press Enter for {}: ').strip()
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit("Parameters must be a JSON object.")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description="Interactive Task 4 PDP demonstration")
    parser.add_argument("--pdp", default="http://127.0.0.1:8080")
    parser.add_argument("--show-request", action="store_true")
    args = parser.parse_args()

    print("\n=== Zero Trust Task 4 Interactive PDP Demo ===")
    print("Enter a simulated request. The client will create trusted prototype evidence, sign the request, and ask the PDP for a decision.")

    while True:
        agent_name, subject_canonical_id, subject_runtime_id = choose("Choose an agent", AGENTS)
        resource_name, resource_canonical_id, resource_runtime_id = choose("Choose a resource", RESOURCES)
        action = input("\nAction, for example read, execute, or update: ").strip().lower()
        if not action:
            print("Action cannot be empty.")
            continue

        workflow_name, workflow_id = choose("Choose a workflow", WORKFLOWS)
        risk_score = read_int("Risk score from 0 to 1000", 300, 0, 1000)

        user_session = yes_no("Include a verified user session?", default=True)
        mfa = yes_no("Include MFA?", default=False)
        approval = yes_no("Include signed human approval?", default=False)
        secondary = yes_no("Include signed secondary authorization?", default=False)
        parameters = read_parameters()

        challenge_response = httpx.post(
            f"{args.pdp}/v1/challenge",
            json={
                "subject_canonical_id": subject_canonical_id,
                "subject_runtime_id": subject_runtime_id,
            },
            timeout=5.0,
        )
        challenge_response.raise_for_status()
        nonce = challenge_response.json()["nonce"]

        request = build_signed_request(
            nonce=nonce,
            subject_canonical_id=subject_canonical_id,
            subject_runtime_id=subject_runtime_id,
            resource_canonical_id=resource_canonical_id,
            resource_runtime_id=resource_runtime_id,
            action=action,
            workflow_id=workflow_id,
            workflow_instance_id=(f"demo-{workflow_id.split('.')[-1]}-1" if workflow_id else None),
            risk_score=risk_score,
            auth_factors={
                "workload_identity": True,
                "user_session": user_session,
                "mfa": mfa,
            },
            parameters=parameters,
            with_human_approval=approval,
            with_secondary_authorization=secondary,
        )

        print("\n--- Simulated Input ---")
        print(f"Agent:      {agent_name} ({subject_canonical_id})")
        print(f"Resource:   {resource_name} ({resource_canonical_id})")
        print(f"Action:     {action}")
        print(f"Workflow:   {workflow_name}")
        print(f"Risk score: {risk_score}")
        print(f"Approval:   {approval}")
        print(f"Secondary:  {secondary}")
        print(f"Parameters: {json.dumps(parameters, ensure_ascii=False)}")

        if args.show_request:
            print("\n--- Full Signed PDP Request ---")
            print(json.dumps(request.model_dump(mode="json"), indent=2, ensure_ascii=False))

        response = httpx.post(
            f"{args.pdp}/v1/authorize",
            json=request.model_dump(mode="json"),
            timeout=5.0,
        )
        body = response.json()

        print("\n--- PDP Output ---")
        if response.status_code >= 400:
            print(f"HTTP status: {response.status_code}")
            print(json.dumps(body, indent=2, ensure_ascii=False))
        else:
            signature_valid = verify_decision_headers(
                body,
                response.headers,
                ROOT / "security" / "dev_keys" / "pdp_signing_public.pem",
                expected_request_hash=request.request_hash,
            )
            print(f"Decision:         {body['decision']}")
            print(f"Reason:           {body['reason']}")
            print(f"Matched policy:   {body.get('policy_id')}")
            print(f"Policy version:   {body.get('policy_version')}")
            print(f"Request hash:     {request.request_hash}")
            print(f"Decision signed:  {signature_valid}")
            obligations = body.get("obligations", [])
            if obligations:
                print("Obligations:")
                for obligation in obligations:
                    print(f"  - {obligation['type']}: {obligation.get('parameters', {})}")
            else:
                print("Obligations:      none")

        if not yes_no("\nSubmit another request?", default=False):
            break


if __name__ == "__main__":
    main()
