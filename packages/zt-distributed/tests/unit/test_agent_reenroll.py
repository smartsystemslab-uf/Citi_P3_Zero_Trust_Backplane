"""An agent whose certificate was revoked (admin disable -> enable) re-enrolls and sends the refused
request once more; nothing else is retried."""
from __future__ import annotations

import asyncio
import json
import time
import types

from zt_distributed import agent_service as A

REVOKED = {"status": 401, "reason": "agent_cert_revoked"}


class Creds:
    def __init__(self, enroll_ok: bool = True) -> None:
        self.cred = types.SimpleNamespace(serial="old")
        self.enroll_ok = enroll_ok
        self.reenrolled: list[str | None] = []

    async def reenroll(self, reason: str, *, stale_serial: str | None = None) -> bool:
        self.reenrolled.append(stale_serial)
        if self.enroll_ok:
            self.cred = types.SimpleNamespace(serial="new")
        return self.enroll_ok


class Mcp:
    """Refuses the first ``refusals`` calls at the PEP with ``reject``; then answers."""

    def __init__(self, auth, refusals: int, reject: dict) -> None:
        self.auth, self.refusals, self.reject, self.metas = auth, refusals, reject, []

    async def call(self, name, args, meta):
        self.metas.append(meta)
        if len(self.metas) <= self.refusals:
            self.auth.last_reject = {**self.reject, "t": time.monotonic()}
            raise RuntimeError("session terminated")
        return types.SimpleNamespace(is_error=False, isError=False, structured_content=None, structuredContent=None,
                                     content=[types.SimpleNamespace(type="text", text='{"status": "ok"}')])


def service(creds: Creds, refusals: int = 0, reject: dict = REVOKED) -> A.AgentService:
    svc = A.AgentService.__new__(A.AgentService)
    svc.agent_id, svc.creds, svc.counters, svc.sign_times = "pharmacy_desk", creds, {}, {}
    svc.mcp_auth = types.SimpleNamespace(last_reject=None)
    svc.mcp = Mcp(svc.mcp_auth, refusals, reject)
    svc.spans = types.SimpleNamespace(add=lambda record: None)
    return svc


def call_tool(svc: A.AgentService) -> dict:
    async def go():
        A.RUN.set(A.RunInfo("wfr-1", "trace-1"))
        return await svc._call_tool("pharmacy_desk", "check_formulary", {"drug": "carprofen"}, "call-1", {})
    return asyncio.run(go())


def test_tool_call_refused_for_a_revoked_certificate_is_sent_again_after_reenrollment():
    creds = Creds()
    svc = service(creds, refusals=1)
    assert call_tool(svc) == {"status": "ok"}
    assert creds.reenrolled == ["old"] and len(svc.mcp.metas) == 2
    first, second = (json.dumps(m, sort_keys=True) for m in svc.mcp.metas)
    assert first != second                                     # a new request (fresh request id / nonce) ...
    assert "adk:wfr-1:pharmacy_desk:call-1" in first and "adk:wfr-1:pharmacy_desk:call-1" in second  # ... same call


def test_no_retry_while_the_agent_is_still_disabled():
    creds = Creds(enroll_ok=False)
    svc = service(creds, refusals=1)
    out = call_tool(svc)
    assert out["status"] == "zero_trust_denied" and "agent_cert_revoked" in out["reason"]
    assert len(svc.mcp.metas) == 1


def test_retried_at_most_once():
    creds = Creds()
    svc = service(creds, refusals=2)
    assert call_tool(svc)["status"] == "zero_trust_denied" and len(svc.mcp.metas) == 2


def test_other_refusals_are_not_retried():
    creds = Creds()
    svc = service(creds, refusals=1, reject={"status": 401, "reason": "signature_invalid"})
    assert call_tool(svc)["status"] == "zero_trust_denied"
    assert creds.reenrolled == [] and len(svc.mcp.metas) == 1


def test_agent_route_refused_for_a_revoked_certificate_is_sent_again():
    creds = Creds()
    svc = service(creds)
    sent = []

    async def post(url, body, headers=None, sign_for=None):
        sent.append(body["request_id"])
        info = {"sign_ms": 0.0, "rtt_ms": 0.0}
        if len(sent) == 1:
            return 401, dict(REVOKED), info
        return 200, {"status": "ok", "events": []}, info

    svc.gateway = types.SimpleNamespace(post=post)
    svc.gw_url = "https://zt-gateway"

    async def go():
        A.RUN.set(A.RunInfo("wfr-1", "trace-1"))
        return await svc._call_agent("billing_desk", {"mode": "run"})
    assert asyncio.run(go())["status"] == "ok"
    assert len(sent) == 2 and sent[0] != sent[1] and creds.reenrolled == ["old"]
