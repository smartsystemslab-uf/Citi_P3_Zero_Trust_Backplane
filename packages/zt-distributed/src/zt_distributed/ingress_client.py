"""Ingress client: the trusted front end of the distributed runtime.

Runs in the ``ingress-client`` container with its own SPIFFE service identity (X.509-SVID over
mTLS). It stands for the application's authenticated front end: it asserts the conversation's
session id and the end user's role; the gateway accepts the role only if the controlled service
map lists it for this service.

    python -m zt_distributed.ingress_client --message "Please look up user alice" \
        [--message "next turn" ...] [--session-id S] [--role employee] [--repeat N]
    python -m zt_distributed.ingress_client --function-response '{"id": "...", "name": "...", "response": {...}}'

Prints one JSON object with one record per message: status, entry agent, final text, the tool
calls and their results as the user would see them, withheld outputs, workflow run id.
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

from . import deployment as D
from .transport import ServiceClient


def summarize(body: dict[str, Any]) -> dict[str, Any]:
    calls, results = [], {}
    for raw in body.get("events") or []:
        for part in ((raw.get("content") or {}).get("parts") or []):
            if part.get("function_call"):
                calls.append(f"{raw.get('author')}:{part['function_call'].get('name')}")
            if part.get("function_response"):
                fr = part["function_response"]
                results[fr.get("name")] = fr.get("response")
    return {"calls": calls, "results": results}


async def run(ns: argparse.Namespace) -> dict[str, Any]:
    dep = D.load()
    ident = WorkloadIdentity(trust_domain=dep.trust_domain, events=EventLog(None, component="ingress-client"))
    ident.bind_loop(asyncio.get_running_loop())
    client = ServiceClient(identity=ident, trust_domain=dep.trust_domain,
                           expected_servers={"zt-gateway": dep.gateway.spiffe_id}, timeout_s=ns.timeout)
    url = f"{dep.gateway_url()}/v1/ingress/run"
    out = []
    session_id = ns.session_id or f"sess-{uuid.uuid4().hex[:12]}"
    turns: list[dict[str, Any]] = [{"message": m} for m in (ns.message or [])]
    if ns.function_response:
        turns.append({"function_response": json.loads(ns.function_response)})
    deadline = time.monotonic() + ns.duration if ns.duration else None
    rep = -1
    while True:
        rep += 1
        if deadline is None and rep >= max(1, ns.repeat):
            break
        if deadline is not None and time.monotonic() >= deadline:
            break
        sid = session_id if (ns.repeat <= 1 and deadline is None) else f"{session_id}-{rep}"
        for turn in turns:
            req: dict[str, Any] = {"request_id": f"ing-{uuid.uuid4()}", **turn}
            if not ns.no_session:
                req["session"] = {"session_id": sid, "user_role": ns.role}
            t0 = time.perf_counter()
            status, body, _ = await client.post(url, req)
            rec = {"turn": turn.get("message") or "function_response", "session_id": sid, "http": status,
                   "status": body.get("status"), "ms": round((time.perf_counter() - t0) * 1000, 2),
                   "entry_agent": body.get("entry_agent"), "final_text": body.get("final_text"),
                   "workflow_run_id": body.get("workflow_run_id"), "withheld": body.get("withheld"),
                   "tainted": body.get("tainted"), "boundary": body.get("boundary"), "reason": body.get("reason"),
                   "rules": body.get("rules")}
            rec.update(summarize(body))
            out.append(rec)
    await client.close()
    return {"turns": len(out), "ok": sum(1 for r in out if r["status"] == "ok"), "results": out}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--message", action="append", help="one user message (repeat for a multi-turn conversation)")
    ap.add_argument("--function-response", help="JSON {id, name, response}: resume a long-running tool call")
    ap.add_argument("--session-id")
    ap.add_argument("--role", default="")
    ap.add_argument("--no-session", action="store_true")
    ap.add_argument("--repeat", type=int, default=1, help="run the conversation N times (separate sessions)")
    ap.add_argument("--duration", type=float, default=0.0,
                    help="repeat the conversation (separate sessions) for this many seconds")
    ap.add_argument("--timeout", type=float, default=900.0)
    ns = ap.parse_args()
    if not ns.message and not ns.function_response:
        ap.error("--message or --function-response is required")
    print(json.dumps(asyncio.run(run(ns)), default=str))


if __name__ == "__main__":
    main()
