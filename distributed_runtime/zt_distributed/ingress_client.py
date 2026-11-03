"""Ingress client: the trusted front end of the distributed runtime.

Runs in the `ingress-client` container with its own SPIFFE service identity (cli-ingress,
X.509-SVID over mTLS). It has authenticated the end user (out of scope here) and asserts
the session (session id, user role) and the approvals of the request; the gateway accepts
the role only if the controlled service map lists it for this service.

    python -m zt_distributed.ingress_client --scenario read --count 3
    python -m zt_distributed.ingress_client --scenario custom --entry transaction_monitoring_agent \
        --message "..." --user-role customer

Prints one JSON object: per-request outcome (ok / error class, boundary, reason, rules,
workflow run id, policy flags) and a summary.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time
import uuid
from typing import Any

from zt_identity.events import EventLog
from zt_identity.workload_identity.spiffe_tls import WorkloadIdentity

from . import catalog
from .transport import ServiceClient

N_CUSTOMERS = 20000
N_DEST = 1000


def _jl(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    try:
        out = json.loads(value)
        return out if isinstance(out, dict) else {}
    except (TypeError, ValueError):
        return {}


def build_request(scenario: str, k: int, *, run_tag: str, approvals: bool, entry: str | None,
                  message: str | None) -> dict[str, Any]:
    appr = {"human_approval": True, "secondary_authorization": True,
            "change_ticket": f"CHG-ZTBP-{run_tag}"} if approvals else {}
    c = k % N_CUSTOMERS
    if scenario == "read":
        return {"entry_agent": entry or "transaction_monitoring_agent", "initial_state": {},
                "message": message or f"Review transaction TXN-B{c:05d}-A for customer CUST-B{c:05d} and run "
                                      f"the front-office transaction monitoring checks."}
    if scenario == "write":
        # the legitimate path: chatbot workflow -> intent -> customer service -> transaction processing
        return {"entry_agent": entry or "customer_service_chatbot_workflow", "approvals": appr, "initial_state": {},
                "message": message or f"Please transfer 1.25 USD from ACC-B{c:05d} to ACC-D{c % N_DEST:05d} for "
                                      f"customer CUST-B{c:05d}, memo ztbp {run_tag} #{k}."}
    if scenario == "write_direct":
        # the transaction agent entered directly with a ready-made plan: no customer-service step
        plan = {"service_type": "transaction_execution", "execution_required": True,
                "customer_id": f"CUST-B{c:05d}", "source_account": f"ACC-B{c:05d}",
                "destination_account": f"ACC-D{c % N_DEST:05d}", "amount": 1.25,
                "memo": f"ztbp {run_tag} #{k}", "customer_message": "Transfer requested."}
        return {"entry_agent": entry or "transaction_processing_agent", "approvals": appr,
                "message": message or f"Please transfer 1.25 USD from ACC-B{c:05d} to ACC-D{c % N_DEST:05d}.",
                "initial_state": {"fo_service_result": json.dumps(plan)}}
    if scenario in ("workflow", "workflow_mismatch", "workflow_not_ready"):
        batch = {"workflow": f"EOD-B-{k:06d}", "workflow_mismatch": f"EOD-M-{k:05d}",
                 "workflow_not_ready": f"EOD-N-{k:05d}"}[scenario]
        return {"entry_agent": entry or "back_office_eod_workflow", "approvals": appr, "initial_state": {},
                "message": message or f"Please run the scheduled end-of-day batch processing for batch {batch}, "
                                      f"including posting the ledger update."}
    if scenario == "ledger_direct":
        # the ledger agent entered directly, with a plausible processing report in its
        # state: authenticated and PDP-permitted, but no trusted pipeline in this run
        batch = f"EOD-B-{k:06d}"
        proc = {"processing_status": "prepared", "posting_instructions": f"POST 1000.00 USD to GL for {batch}"}
        return {"entry_agent": entry or "ledger_update_agent", "approvals": appr,
                "initial_state": {"bo_processing_report": json.dumps(proc)},
                "message": message or f"Post the ledger update for batch {batch}."}
    if scenario == "knowledge":
        return {"entry_agent": entry or "customer_service_chatbot_workflow", "initial_state": {},
                "message": message or "What are the cut-off times for same-day payments?"}
    if scenario == "custom":
        if not entry or message is None:
            raise SystemExit("--scenario custom needs --entry and --message")
        return {"entry_agent": entry, "approvals": appr, "initial_state": {}, "message": message}
    raise SystemExit(f"unknown scenario {scenario}")


def classify(scenario: str, status: int, body: dict[str, Any]) -> tuple[bool, str]:
    if status != 200 or body.get("status") != "ok":
        return False, f"http_{status}:{body.get('boundary', '')}:{str(body.get('reason') or body.get('status'))[:120]}"
    delta = (body.get("result") or {}).get("state_delta") or {}
    if scenario == "read":
        rep = _jl(delta.get("fo_monitoring_report"))
        return (True, "") if rep.get("evidence_ok") is True else (False, "business:read_evidence_incomplete")
    if scenario in ("write", "write_direct"):
        rep = _jl(delta.get("fo_transaction_execution"))
        if rep.get("execution_performed") is True and rep.get("transaction_id"):
            return True, ""
        return False, f"business:write_not_executed:{str(rep.get('outcome'))[:100]}"
    if scenario == "workflow":
        rep = _jl(delta.get("bo_report_output"))
        return (True, "") if rep.get("report_id") else (False, "business:eod_report_missing")
    if scenario == "workflow_mismatch":
        rep = _jl(delta.get("bo_exception_output"))
        return (True, "") if rep.get("exception_case_id") else (False, "business:exception_missing")
    if scenario == "knowledge":
        rep = _jl(delta.get("fo_knowledge_answer"))
        return (True, "") if rep.get("answer") else (False, "business:no_answer")
    if scenario == "ledger_direct":
        rep = _jl(delta.get("bo_ledger_update_report"))
        notes = str(rep.get("notes", ""))
        return (notes == "posted"), ("" if notes == "posted" else f"business:ledger_{notes or 'unknown'}")
    return True, ""


async def run(ns: argparse.Namespace) -> dict[str, Any]:
    events = EventLog(None, component="ingress-client")
    ident = WorkloadIdentity(trust_domain=catalog.TRUST_DOMAIN, events=events)
    ident.bind_loop(asyncio.get_running_loop())
    client = ServiceClient(identity=ident, trust_domain=catalog.TRUST_DOMAIN,
                           expected_servers={catalog.GATEWAY_HOST: catalog.SERVICES["zt-gateway"].spiffe_id})
    url = f"{catalog.gateway_url()}/v1/ingress/run"
    run_tag = ns.run_tag or uuid.uuid4().hex[:10]
    results = []
    deadline = time.monotonic() + ns.duration if ns.duration else None
    i = 0
    while (i < ns.count) if deadline is None else (time.monotonic() < deadline):
        k = ns.offset + i
        i += 1
        req = build_request(ns.scenario, k, run_tag=run_tag, approvals=not ns.no_approvals, entry=ns.entry,
                            message=ns.message)
        req["request_id"] = f"ing-{uuid.uuid4()}"
        if not ns.no_session:
            req["session"] = {"session_id": ns.session_id or f"sess-{uuid.uuid4().hex[:12]}",
                              "user_role": ns.user_role}
        t0 = time.perf_counter()
        status, body, _ = await client.post(url, req)
        ok, err = classify(ns.scenario, status, body)
        delta = ((body.get("result") or {}).get("state_delta") or {}) if isinstance(body, dict) else {}
        results.append({"i": k, "status": status, "ok": ok, "err": err, "ms": round((time.perf_counter() - t0) * 1000, 2),
                        "boundary": body.get("boundary"), "reason": body.get("reason"), "rules": body.get("rules"),
                        "workflow_run_id": body.get("workflow_run_id"), "policy_flags": body.get("policy_flags"),
                        "state_keys": sorted(delta), "state": {k2: _jl(v) or v for k2, v in delta.items()}
                        if ns.include_state else None})
    await client.close()
    return {"scenario": ns.scenario, "count": len(results), "ok": sum(r["ok"] for r in results),
            "results": results}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True,
                    choices=["read", "write", "write_direct", "workflow", "workflow_mismatch",
                             "workflow_not_ready", "ledger_direct", "knowledge", "custom"])
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--duration", type=float, default=0.0, help="send sequentially for this many seconds instead")
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--entry", default=None)
    ap.add_argument("--message", default=None)
    ap.add_argument("--user-role", default="internal_rep")
    ap.add_argument("--session-id", default=None)
    ap.add_argument("--no-session", action="store_true")
    ap.add_argument("--no-approvals", action="store_true")
    ap.add_argument("--include-state", action="store_true")
    ap.add_argument("--run-tag", default=None)
    print(json.dumps(asyncio.run(run(ap.parse_args())), default=str))


if __name__ == "__main__":
    main()
