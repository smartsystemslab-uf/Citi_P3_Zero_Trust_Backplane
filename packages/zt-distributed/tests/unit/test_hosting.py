"""One agent per workload reproduces ADK's in-process behaviour.

The loopback wires every agent's HostedAgentRunner (its own copy of the agent tree) and the
gateway's ToolHost together without network or PEP; the same conversation is run in one
process with a plain ADK Runner. Tool calls (agent, tool, arguments), tool results and the
answers must be identical -- transfers, workflows (sequential / parallel / loop with
escalate), state written by tools and read by later instructions, AgentTool with a fresh
session and a model-side built-in, multi-turn resumption at the active agent.
"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

import pytest
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from zt_adk.testing.playback import install_playback
from zt_distributed import deployment as D
from zt_distributed.loopback import Loopback
from zt_distributed.workload_runtime import ConversationStore

EXAMPLE = Path(__file__).resolve().parents[4] / "examples" / "helpdesk_mas"
CONVERSATION = ["Please look up user alice", "Unlock the account of bob", "The printer of carol is broken",
                "How do I fix the vpn?", "Ask the vendor about the vpn client"]
FRESH_IDS = re.compile(r"(INC|MSG|HW)-[0-9A-F]{8}")       # identifiers created per run
PARALLEL = {"asset_agent", "history_agent"}                 # ParallelAgent children interleave nondeterministically


def _prepare(root):
    install_playback(root, EXAMPLE / "playback.yaml")


def _trace(events) -> list[tuple]:
    out = []
    for ev in events:
        for p in (ev.content.parts if ev.content else []) or []:
            if p.function_call:
                out.append(("call", ev.author, p.function_call.name, json.dumps(p.function_call.args, sort_keys=True)))
            elif p.function_response:
                out.append(("result", ev.author, p.function_response.name,
                            json.dumps(p.function_response.response, sort_keys=True, default=str)))
            elif p.text:
                out.append(("text", ev.author, p.text))
    return out


def _mask(value: str) -> str:
    return FRESH_IDS.sub(lambda m: m.group(1) + "-ID", value)


def _normalize(trace: list[tuple]) -> tuple[list[tuple], list[tuple]]:
    """(order of every non-parallel step, multiset of the parallel steps)."""
    masked = [tuple(_mask(x) for x in t) for t in trace]
    return [t for t in masked if t[1] not in PARALLEL], sorted(t for t in masked if t[1] in PARALLEL)


@pytest.fixture()
def db(tmp_path, monkeypatch):
    def use(name: str) -> None:
        monkeypatch.setenv("HELPDESK_DB", str(tmp_path / name))
    return use


def test_loopback_equals_in_process(db):
    import helpdesk.agent as hd

    async def in_process() -> list:
        root = hd.build_root_agent()
        _prepare(root)
        sessions = InMemorySessionService()
        runner = Runner(app_name="helpdesk", agent=root, session_service=sessions)
        s = await sessions.create_session(app_name="helpdesk", user_id="u")
        out = []
        for msg in CONVERSATION:
            evs = [e async for e in runner.run_async(user_id="u", session_id=s.id, new_message=types.Content(
                role="user", parts=[types.Part(text=msg)]))]
            out.append(_normalize(_trace([e for e in evs if not e.partial])))
        return out

    async def distributed() -> tuple[list, Loopback]:
        lb = Loopback(hd.build_root_agent, app_name="helpdesk", prepare=_prepare)
        out = []
        for msg in CONVERSATION:
            out.append(_normalize(_trace(await lb.say("s1", msg))))
        return out, lb

    db("one_process.db")
    expected = asyncio.run(in_process())
    db("distributed.db")
    got, lb = asyncio.run(distributed())
    for turn, (g, e) in enumerate(zip(got, expected)):
        assert g == e, f"turn {turn}: {CONVERSATION[turn]}"
    assert len(got) == len(expected)
    assert ("agent_tool", "web_research_agent") in lb.agent_calls
    assert {a for _, a in lb.agent_calls} >= {"account_agent", "incident_workflow", "intake_agent", "context_gatherer",
                                             "asset_agent", "history_agent", "diagnosis_loop", "diagnostic_agent",
                                             "escalation_checker", "resolution_agent", "triage_agent"}
    assert ("resolution_agent", "notify_user") in lb.tool_calls


def test_conversation_store_follows_adks_resume_rule():
    import helpdesk.agent as hd
    from zt_adk.discovery import discover

    root = hd.build_root_agent()
    _model, agents, _tools = discover(root)
    store = ConversationStore(agents=agents, root=root.name)
    conv = store.get("s")
    assert store.entry_agent(conv) == "service_desk"                      # new conversation: root
    store.append(conv, [{"author": "user", "content": {"role": "user", "parts": [{"text": "hi"}]}},
                        {"author": "account_agent", "content": {"role": "model", "parts": [{"text": "ok"}]},
                         "actions": {"state_delta": {"k": 1}}}])
    assert store.entry_agent(conv) == "account_agent"                     # resumable LLM agent replied last
    assert conv.state == {"k": 1}
    store.append(conv, [{"author": "intake_agent", "content": {"role": "model", "parts": [{"text": "x"}]}}])
    assert store.entry_agent(conv) == "account_agent"                     # inside a workflow: not resumable
    store.append(conv, [{"author": "service_desk", "content": {"role": "model", "parts": [{"text": "y"}]}}])
    assert store.entry_agent(conv) == "service_desk"


def test_deployment_descriptor():
    import helpdesk.agent as hd
    from zt_adk.discovery import discover
    from zt_adk.profile import profile_from_dict

    model, _a, _t = discover(hd.build_root_agent(), app_name="helpdesk")
    prof = profile_from_dict({"app": "helpdesk.agent:app", "identity": {"trust_domain": "hd.test"},
                              "session": {"roles": ["employee"]}}, base_dir=EXAMPLE)
    dep = D.describe(model, prof)
    assert len(dep.agents) == 13 and dep.fingerprint == model.fingerprint()
    w = dep.agents["account_agent"]
    assert w.name == "wl-account-agent" and w.spiffe_id == "spiffe://hd.test/ztbp/wl/account_agent"
    assert len({a.uid for a in dep.agents.values()} | {s.uid for s in dep.services.values()}) == 16
    assert dep.ingress.user_roles == ("employee",)
    assert dep.entry_agents == ["account_agent", "service_desk", "triage_agent"]
    assert dep.selectors(w) == [f"docker:label:{D.LABEL_KEY}:wl-account-agent",
                                "docker:label:com.docker.compose.project:citi_p3_ztbp", f"unix:uid:{w.uid}"]
    assert D.Deployment.from_dict(json.loads(json.dumps(dep.to_dict()))) == dep
    assert D.dns_name("Some_Agent__X", "wl-") == "wl-some-agent-x"


def test_workload_refuses_undeclared_function_and_runs_app_plugins(db):
    """A workload's model calling a function its agent does not have gets a denial (counted and
    reported) instead of failing the invocation; the application's own plugins run around the
    hosted agent."""
    import helpdesk.agent as hd
    from google.adk.plugins.base_plugin import BasePlugin

    from zt_adk.discovery import discover
    from zt_distributed.workload_runtime import HostedAgentRunner

    class Recorder(BasePlugin):
        def __init__(self) -> None:
            super().__init__(name="recorder")
            self.models: list[str] = []

        async def before_model_callback(self, *, callback_context, llm_request):
            self.models.append(callback_context.agent_name)
            return None

    root = hd.build_root_agent()
    install_playback(root, {"account_agent": [
        {"when": {"after": "drop_database"}, "text": "refused: {result[status]} {result[reason]}"},
        {"call": "drop_database", "args": {}}]})
    _model, agents, _tools = discover(root, resolve_toolsets=False)
    refusals: list[tuple[str, str]] = []
    rec = Recorder()
    hosted = HostedAgentRunner(agents=agents, agent_name="account_agent", app_name="helpdesk", plugins=[rec],
                               on_refusal=lambda agent, fn: refusals.append((agent, fn)))
    out = asyncio.run(hosted.run({"mode": "agent_tool", "request": "wipe everything"}))
    assert out["status"] == "ok"
    assert out["result_text"] == "refused: zero_trust_denied UNDECLARED_FUNCTION: account_agent may not call drop_database"
    assert refusals == [("account_agent", "drop_database")] and hosted.guard.refused == 1
    assert rec.models == ["account_agent", "account_agent"]


# ------------------------------------------------------------------ toolsets in the distributed runtime
def _ledger_toolset_app():
    """An application whose agent gets its tools from a toolset (here a custom BaseToolset; MCP and
    OpenAPI toolsets are hosted the same way: the gateway resolves them, workloads get proxies)."""
    from typing import Optional

    from google.adk.agents import LlmAgent
    from google.adk.tools.base_toolset import BaseToolset
    from google.adk.tools.function_tool import FunctionTool

    def get_balance(account: str) -> dict:
        """Read the balance of an account."""
        return {"status": "ok", "account": account, "balance": 120}

    def credit_points(account: str, points: int) -> dict:
        """Credit loyalty points to an account."""
        return {"status": "ok", "account": account, "points": points, "type": type(points).__name__}

    class LedgerToolset(BaseToolset):
        async def get_tools(self, readonly_context: Optional[object] = None):
            return [FunctionTool(get_balance), FunctionTool(credit_points)]

        async def close(self) -> None:
            return None

    def build():
        ledger = LlmAgent(name="ledger_agent", model="gemini-2.5-flash", instruction="Ledger.", tools=[LedgerToolset()])
        return LlmAgent(name="front_desk", model="gemini-2.5-flash", instruction="Route.", sub_agents=[ledger])

    script = {
        "front_desk": [{"when": {"user": "(?i)balance|points"}, "transfer": "ledger_agent"}, {"text": "Hello."}],
        "ledger_agent": [
            {"when": {"after": "get_balance"}, "text": "Balance {result[balance]}"},
            {"when": {"after": "credit_points"}, "text": "Credited {result[points]} ({result[type]})"},
            {"when": {"user": "(?i)balance of (?P<a>\w+)"}, "call": "get_balance", "args": {"account": "{a}"}},
            {"when": {"user": "(?i)(?P<n>\d+) points to (?P<a>\w+)"}, "call": "credit_points",
             "args": {"account": "{a}", "points": "{n}"}},
            {"text": "Ledger here."},
        ],
    }
    return build, script


def test_agent_with_a_toolset_runs_distributed_exactly_as_in_process():
    build, script = _ledger_toolset_app()
    conversation = ["What is the balance of acme", "Add 40 points to acme"]

    async def in_process() -> list:
        root = build()
        install_playback(root, script)
        sessions = InMemorySessionService()
        runner = Runner(app_name="ledger", agent=root, session_service=sessions)
        s = await sessions.create_session(app_name="ledger", user_id="u")
        out = []
        for msg in conversation:
            evs = [e async for e in runner.run_async(user_id="u", session_id=s.id, new_message=types.Content(
                role="user", parts=[types.Part(text=msg)]))]
            out.append(_trace([e for e in evs if not e.partial]))
        return out

    async def distributed() -> tuple[list, Loopback]:
        lb = Loopback(build, app_name="ledger", prepare=lambda root: install_playback(root, script))
        return [_trace(await lb.say("s1", msg)) for msg in conversation], lb

    expected = asyncio.run(in_process())
    got, lb = asyncio.run(distributed())
    assert got == expected
    assert ("ledger_agent", "get_balance") in lb.tool_calls and ("ledger_agent", "credit_points") in lb.tool_calls
    hosted = lb.runners["ledger_agent"].agent
    assert sorted(t.name for t in hosted.tools) == ["credit_points", "get_balance"]      # proxies, no toolset
    assert lb.listed["ledger_agent__credit_points"]["parameters"]["properties"]["points"]["type"] == "integer"
    # the argument reaches the toolset's tool as the model produced it ("40": a string), as in one process
    assert any("Credited 40 (str)" in t[2] for t in got[1] if t[0] == "text")


def test_hosting_an_agent_with_a_toolset_needs_the_gateways_declarations():
    from zt_adk.discovery import discover
    from zt_distributed.remote import host_agent

    build, _script = _ledger_toolset_app()
    _model, agents, _tools = discover(build(), resolve_toolsets=False)
    with pytest.raises(RuntimeError, match="needs the declarations"):
        host_agent(agents, "ledger_agent")


# ------------------------------------------------------------------ graph workflows (ADK 2.x)
CLAIMS = Path(__file__).resolve().parents[4] / "examples" / "claims_workflow"


@pytest.mark.parametrize("message", ["Claim on policy P-100 for 120 usd", "Claim on policy P-100 for 4200 usd"])
def test_graph_workflow_runs_distributed_exactly_as_in_process(message, monkeypatch):
    """A graph workflow in its own workload: its agent nodes, nested workflow and the agent a
    function node starts run in their own workloads (through the gateway hooks), its tool node in
    the tool host -- calls, results and answers are identical to one process."""
    pytest.importorskip("google.adk.workflow", reason="graph workflows exist in ADK 2.x only")
    import sys

    if str(CLAIMS) not in sys.path:
        sys.path.insert(0, str(CLAIMS))
    import claims.agent as ca

    monkeypatch.setattr(ca, "notifier_agent", ca.notifier_agent)        # restored after the test
    script = CLAIMS / "playback.yaml"

    async def in_process() -> list:
        root = ca.build_root()
        install_playback(root, script)
        sessions = InMemorySessionService()
        runner = Runner(app_name="claims", node=root, session_service=sessions)
        s = await sessions.create_session(app_name="claims", user_id="u")
        evs = [e async for e in runner.run_async(user_id="u", session_id=s.id, new_message=types.Content(
            role="user", parts=[types.Part(text=message)]))]
        return _trace([e for e in evs if not e.partial and e.author != "user"])

    async def distributed() -> tuple[list, Loopback]:
        lb = Loopback(ca.build_root, app_name="claims", prepare=lambda root: install_playback(root, script))
        return _trace(await lb.say("s1", message)), lb

    expected = asyncio.run(in_process())
    got, lb = asyncio.run(distributed())
    assert got == expected
    called = {t for _m, t in lb.agent_calls}
    assert {"intake_agent", "writer_agent"} <= called
    if "4200" in message:
        assert {"review_flow", "adjuster_agent"} <= called and ("adjuster_agent", "read_claim_history") in lb.tool_calls
    else:
        assert "notifier_agent" in called and ("claims_desk", "pay_claim") in lb.tool_calls
