"""Discovery of the live ADK object graph, with ADK's own transfer rules."""
from __future__ import annotations

from typing import AsyncGenerator

import pytest
from google.adk.agents import BaseAgent, LlmAgent, LoopAgent, ParallelAgent, SequentialAgent
from google.adk.events import Event
from google.adk.tools import google_search
from google.adk.tools.agent_tool import AgentTool
from google.adk.tools.function_tool import FunctionTool

from zt_adk import model as M
from zt_adk.discovery import discover, discover_app


def _tool_read(user_id: str) -> dict:
    """Read a record."""
    return {"user": user_id}


def _tool_write(record_id: str) -> dict:
    """Update a record."""
    import sqlite3

    with sqlite3.connect(":memory:") as c:
        c.execute("UPDATE t SET x = 1 WHERE id = ?", (record_id,))
    return {"status": "ok"}


def edges(model: M.SystemModel, kind: str) -> set[tuple[str, str]]:
    return {(e.caller, e.target) for e in model.edges if e.kind == kind}


def test_example_service_desk():
    model, root, agents, tools = discover_app("helpdesk.agent:app")
    assert model.errors == [] and len(model.agents) == 13 and len(model.tools) == 13
    assert model.root_agent == "service_desk"
    # entry points: root + resumable LLM agents (all ancestors LlmAgents allowing transfer)
    assert edges(model, M.EDGE_ENTRY) == {("ingress", "service_desk"), ("ingress", "account_agent"),
                                          ("ingress", "triage_agent")}
    # transfer: sub-agents, parent, peers (ADK rules)
    assert ("service_desk", "incident_workflow") in edges(model, M.EDGE_TRANSFER)
    assert ("account_agent", "service_desk") in edges(model, M.EDGE_TRANSFER)
    assert ("account_agent", "triage_agent") in edges(model, M.EDGE_TRANSFER)
    # agents inside workflows are orchestrated, not transfer targets of each other
    assert ("incident_workflow", "intake_agent") in edges(model, M.EDGE_ORCHESTRATE)
    assert ("diagnosis_loop", "escalation_checker") in edges(model, M.EDGE_ORCHESTRATE)
    assert ("intake_agent", "context_gatherer") not in edges(model, M.EDGE_TRANSFER)
    # AgentTool and model-side built-in
    assert ("triage_agent", "web_research_agent") in edges(model, M.EDGE_AGENT_TOOL)
    assert model.tools["web_research_agent/google_search"].kind == M.BUILTIN
    assert model.tools["web_research_agent/google_search"].analysis["model_fields"] == ["google_search"]
    assert model.agents["web_research_agent"].reached_via == "agent_tool"
    assert model.tools["account_agent/request_hardware"].kind == M.LONG_RUNNING
    assert model.agents["escalation_checker"].kind == M.CUSTOM
    # workflows and the nearest enclosing workflow of each agent
    assert model.workflows["incident_workflow"] == ["intake_agent", "context_gatherer", "diagnosis_loop",
                                                    "resolution_agent"]
    assert model.workflow_of["asset_agent"] == "context_gatherer"
    assert model.workflow_of["resolution_agent"] == "incident_workflow"
    assert model.workflow_of["account_agent"] is None


def test_fingerprint_ignores_prompts_but_not_structure():
    import helpdesk.agent as hd

    a, _, _ = discover(hd.build_root_agent())
    r2 = hd.build_root_agent()
    r2.instruction = "a completely different prompt"
    b, _, _ = discover(r2)
    assert a.fingerprint() == b.fingerprint()
    r3 = hd.build_root_agent()
    r3.sub_agents[0].tools.append(_tool_write)
    c, _, _ = discover(r3)
    assert c.fingerprint() != a.fingerprint()


def test_transfer_flags_are_respected():
    child = LlmAgent(name="child", model="gemini-2.5-flash", disallow_transfer_to_parent=True,
                     disallow_transfer_to_peers=True)
    peer = LlmAgent(name="peer", model="gemini-2.5-flash")
    root = LlmAgent(name="root", model="gemini-2.5-flash", sub_agents=[child, peer])
    model, _, _ = discover(root)
    t = edges(model, M.EDGE_TRANSFER)
    assert ("root", "child") in t and ("root", "peer") in t
    assert ("child", "root") not in t and ("child", "peer") not in t       # disallowed
    assert ("peer", "root") in t and ("peer", "child") in t                # default: allowed
    # child cannot be resumed (it does not allow transfer to its parent)
    assert ("ingress", "child") not in edges(model, M.EDGE_ENTRY)
    assert ("ingress", "peer") in edges(model, M.EDGE_ENTRY)


class Orchestrator(BaseAgent):
    """Custom agent that runs a child held in an attribute (not in sub_agents)."""
    worker: BaseAgent

    async def _run_async_impl(self, ctx) -> AsyncGenerator[Event, None]:
        async for ev in self.worker.run_async(ctx):
            yield ev


def test_custom_agent_children_in_attributes():
    worker = LlmAgent(name="worker", model="gemini-2.5-flash", tools=[_tool_read])
    orch = Orchestrator(name="orch", worker=worker)
    root = SequentialAgent(name="pipeline", sub_agents=[orch])
    model, _, _ = discover(root)
    assert model.agents["orch"].child_fields == {"worker": ["worker"]}
    assert ("orch", "worker") in edges(model, M.EDGE_ORCHESTRATE)
    assert any("attribute" in w for w in model.warnings)


def test_agent_tool_without_plugins_is_an_error():
    helper = LlmAgent(name="helper", model="gemini-2.5-flash")
    root = LlmAgent(name="root", model="gemini-2.5-flash", tools=[AgentTool(agent=helper, include_plugins=False)])
    model, _, _ = discover(root)
    assert any("include_plugins=False" in e for e in model.errors)


def test_duplicate_agent_names_are_an_error():
    a1 = LlmAgent(name="dup", model="gemini-2.5-flash")
    a2 = LlmAgent(name="dup", model="gemini-2.5-flash")
    root = LlmAgent(name="root", model="gemini-2.5-flash", sub_agents=[a1],
                    tools=[AgentTool(agent=a2)])
    model, _, _ = discover(root)
    assert any("two different agents are named 'dup'" in e for e in model.errors)


def test_tool_forms_and_parameters():
    root = LlmAgent(name="root", model="gemini-2.5-flash",
                    tools=[_tool_read, FunctionTool(func=_tool_write), google_search])
    model, _, _ = discover(root)
    assert model.tools["root/_tool_read"].kind == M.FUNCTION
    assert set(model.tools["root/_tool_write"].parameters["properties"]) == {"record_id"}
    assert model.tools["root/_tool_write"].analysis["sql"] == ["UPDATE"]
    assert model.tools["root/google_search"].kind == M.BUILTIN


def test_loop_and_parallel_are_workflows():
    a = LlmAgent(name="a", model="gemini-2.5-flash")
    b = LlmAgent(name="b", model="gemini-2.5-flash")
    loop = LoopAgent(name="loop", sub_agents=[a], max_iterations=2)
    par = ParallelAgent(name="par", sub_agents=[b])
    root = SequentialAgent(name="seq", sub_agents=[loop, par])
    model, _, _ = discover(root)
    assert model.agents["loop"].kind == M.LOOP and model.agents["par"].kind == M.PARALLEL
    assert model.workflow_of["a"] == "loop" and model.workflow_of["b"] == "par"
    assert edges(model, M.EDGE_ENTRY) == {("ingress", "seq")}     # no LLM agent can be resumed here


@pytest.mark.parametrize("declared", [[], ["remote_search"]])
def test_unresolvable_toolset(declared):
    from google.adk.tools.base_toolset import BaseToolset

    class BrokenToolset(BaseToolset):
        async def get_tools(self, readonly_context=None):
            raise ConnectionError("server down")

        async def close(self):
            pass

    root = LlmAgent(name="root", model="gemini-2.5-flash", tools=[BrokenToolset()])
    model, _, _ = discover(root, declared_toolset_tools={"BrokenToolset": declared})
    ts = model.toolsets["root/BrokenToolset"]
    assert ts["resolved"] is False and "server down" in ts["error"]
    if declared:
        assert model.tools["root/remote_search"].kind == M.TOOLSET_TOOL
    else:
        assert any("every tool it offers at run time is denied" in w for w in model.warnings)


def test_strict_build_refuses_unknown_toolset_tools(tmp_path):
    """strict: an unresolved toolset without declared tools fails the build until the profile lists it."""
    from google.adk.tools.base_toolset import BaseToolset

    from zt_adk.build import BuildError, build
    from zt_adk.keys import init_keys
    from zt_adk.profile import profile_from_dict

    class BrokenToolset(BaseToolset):
        async def get_tools(self, readonly_context=None):
            raise ConnectionError("server down")

        async def close(self):
            pass

    def root():
        return LlmAgent(name="root", model="gemini-2.5-flash", tools=[BrokenToolset()])

    init_keys(tmp_path / "keys", tmp_path / "approver-keys", approvers=["alice"], secondaries=[])
    base = {"app": "unused:root", "keys_dir": str(tmp_path / "keys"), "bundle_dir": str(tmp_path / "bundle"),
            "approver_keys_dir": str(tmp_path / "approver-keys"), "state_dir": str(tmp_path / "state")}
    with pytest.raises(BuildError, match="strict: the tools of these toolsets are unknown"):
        build(profile_from_dict(base, tmp_path), root_agent=root(), skip_static=True)
    res = build(profile_from_dict({**base, "toolsets": {"BrokenToolset": {"resolve": False}}}, tmp_path),
                root_agent=root(), skip_static=True)
    assert any("every tool it offers at run time is denied" in w for w in res.warnings)
    build(profile_from_dict({**base, "strict": False}, tmp_path), root_agent=root(), skip_static=True)
