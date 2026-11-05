"""Probe: act as a (compromised) agent workload with its OWN valid credentials and try what the
agent's code would never do. Used by the functional tests to show that a valid identity is not
enough -- every request must also fit the generated placements, an active dispatched run and the
signed policies.

Runs inside an agent workload container as that workload's UID:

    python -m zt_distributed.probe tool --tool account_agent__reset_password --args '{"username": "x"}'
    python -m zt_distributed.probe route --target diagnostic_agent

Prints one JSON object with the gateway's answer.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import uuid
from typing import Any

from zt_identity.agent_identity.client import AgentCredentialManager
from zt_identity.events import EventLog
from zt_identity.workload_identity.spiffe_tls import WorkloadIdentity

from . import deployment as D
from .mcp_client import AgentSigningAuth, McpToolSession, SpiffeHTTPTransport, call_meta
from .mcp_compat import result_parts
from .transport import ServiceClient


async def run(ns: argparse.Namespace) -> dict[str, Any]:
    dep = D.load()
    agent_id = os.environ["AGENT_ID"]
    events = EventLog(None, component="probe")
    ident = WorkloadIdentity(trust_domain=dep.trust_domain, events=events)
    ident.bind_loop(asyncio.get_running_loop())
    expected = {"zt-gateway": dep.gateway.spiffe_id, "agent-issuer": dep.issuer.spiffe_id}
    issuer = ServiceClient(identity=ident, trust_domain=dep.trust_domain, expected_servers=expected)

    async def post_json(url: str, payload: dict) -> tuple[int, dict]:
        status, body, _ = await issuer.post(url, payload)
        return status, body

    creds = AgentCredentialManager(agent_id=agent_id, workload_spiffe_id=lambda: ident.spiffe_id,
                                   issuer_url=dep.issuer_url(), post_json=post_json,
                                   enrollment_key_path="/run/secrets/agent-enroll/enroll.key", events=events)
    await creds.start()
    run_id = ns.workflow_run_id or f"wfr-forged-{uuid.uuid4()}"
    if ns.kind == "tool":
        stats: dict[str, Any] = {}
        auth = AgentSigningAuth(agent_id, stats, creds, lambda: ident.spiffe_id, {})
        trans = SpiffeHTTPTransport(identity=ident, trust_domain=dep.trust_domain, expected_servers=expected)
        mcp = McpToolSession(url=f"{dep.gateway_url()}/mcp", agent_id=agent_id, transport=trans, auth=auth,
                             events=events, protocol_stats=stats, read_timeout_s=60)
        await mcp.connect("probe")
        meta = call_meta(request_id=str(uuid.uuid4()), workflow_run_id=run_id, trace_id="probe",
                         idempotency_key=f"probe:{uuid.uuid4()}", call_id="probe", state={})
        try:
            res = await mcp.call(ns.tool, json.loads(ns.args or "{}"), meta)
            is_error, structured, _content = result_parts(res)
            out = {"is_error": is_error, "body": structured}
        except Exception as exc:
            out = {"exception": f"{type(exc).__name__}: {exc}"[:300]}
        return {"agent": agent_id, "kind": "tool", "tool": ns.tool, **out}
    gw = ServiceClient(identity=ident, trust_domain=dep.trust_domain, expected_servers=expected, agent_creds=creds)
    body = {"request_id": str(uuid.uuid4()), "workflow_run_id": run_id, "trace_id": "probe", "mode": "run",
            "history": [], "state": {}}
    status, data, _ = await gw.post(f"{dep.gateway_url()}/v1/agents/{ns.target}/invoke", body,
                                    sign_for=(body["request_id"], run_id))
    return {"agent": agent_id, "kind": "route", "target": ns.target, "http": status, "body": data}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("kind", choices=["tool", "route"])
    ap.add_argument("--tool")
    ap.add_argument("--args")
    ap.add_argument("--target")
    ap.add_argument("--workflow-run-id")
    print(json.dumps(asyncio.run(run(ap.parse_args())), default=str))


if __name__ == "__main__":
    main()
