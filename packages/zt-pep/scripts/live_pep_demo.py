#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from zt_pep.runtime import PEPDenied, PEPEnforcer, PdpClient


def main() -> None:
    parser = argparse.ArgumentParser(description="Run generated PEPs against the live PDP")
    parser.add_argument("--plan", type=Path, default=Path(__file__).resolve().parents[1] / "generated" / "generated_pep_plan.json")
    parser.add_argument("--pdp-root", type=Path, required=True)
    parser.add_argument("--pdp", default="http://127.0.0.1:8080")
    args = parser.parse_args()
    sys.path.insert(0, str(args.pdp_root / "src"))
    from zt_pdp.dev_material import dev_key_path

    client = PdpClient(
        pdp_url=args.pdp,
        pdp_public_key=dev_key_path("pdp_signing_public.pem", args.pdp_root),
    )
    enforcer = PEPEnforcer(
        args.plan,
        pdp_client=client,
        audit_path=Path(__file__).resolve().parents[1] / "runtime" / "pep_audit.jsonl",
    )

    print("\n1) Authorized fraud read; PDP returns masking obligations")
    value = enforcer.enforce(
        "pep.fraud_review.read_history",
        lambda: {"transaction_id": "t-100", "full_account_number": "123456", "ssn": "111-22-3333"},
        parameters={"transaction_id": "t-100"},
    )
    print(json.dumps(value, indent=2))

    print("\n2) Critical ledger update without approvals; PEP generator blocks MANUAL_REVIEW")
    try:
        enforcer.enforce(
            "pep.eod_processing.ledger_update",
            lambda: "should not execute",
            parameters={"batch_id": "eod-1"},
        )
    except PEPDenied as exc:
        print(f"BLOCKED: {exc}")

    print("\n3) Same ledger update with signed approvals and required obligations")
    value = enforcer.enforce(
        "pep.eod_processing.ledger_update",
        lambda: "ledger update executed",
        parameters={
            "batch_id": "eod-1",
            "idempotency_key": "idem-eod-1",
            "change_ticket": "CHG-1001",
        },
        with_human_approval=True,
        with_secondary_authorization=True,
    )
    print(value)


if __name__ == "__main__":
    main()
