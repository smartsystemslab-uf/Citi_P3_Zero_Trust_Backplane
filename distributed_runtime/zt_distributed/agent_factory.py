"""Build the ORIGINAL ADK agent tree and host one agent per workload.

The agent objects come from the original factories in
bank_adk/agents/{root,front_office,back_office}.py (instructions, output keys,
callbacks, tool lists and the BackOfficeEodWorkflowAgent orchestration logic
are unchanged). Per workload only three things are rebound:
  * model  -> ScriptedLlm (model-output fixture),
  * tools  -> network proxies to the Backplane PEP with the same name,
              signature and docstring (the real tool body runs behind the PEP),
  * orchestrator children -> RemoteAgentProxy (the child runs in its own
              workload and is reached through the PEP's route check).
"""
from __future__ import annotations

import inspect
import json
from types import SimpleNamespace
from typing import Any, AsyncGenerator, Callable

from google.adk.agents import BaseAgent, LlmAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event, EventActions
from google.adk.tools.tool_context import ToolContext
from google.genai import types

from . import catalog
from .scripted_model import ScriptedLlm, install_fixture_llm_module


def build_original_tree():
    install_fixture_llm_module()
    from bank_adk.agents.root import build_root_agent

    return build_root_agent()


def find_agent(root: Any, name: str) -> Any:
    stack = [root]
    while stack:
        a = stack.pop()
        if getattr(a, "name", None) == name:
            return a
        stack.extend(list(getattr(a, "sub_agents", None) or []))
    raise KeyError(name)


def index_topology(root: Any) -> SimpleNamespace:
    """Same topology index the original ZeroTrustBackplanePlugin builds."""
    from bank_adk.zero_trust.plugin import ZeroTrustBackplanePlugin

    ns = SimpleNamespace(parent_by_agent={}, workflow_by_agent={}, runtime_agent_edges=[])
    ZeroTrustBackplanePlugin._index_agent_tree(ns, root)   # original method, run on a plain namespace
    return ns


def original_tool_functions() -> dict[str, Callable[..., Any]]:
    from bank_adk.tools import back_office_tools, csr_tools, customer_tools, knowledge_tools, ops_tools

    out: dict[str, Callable[..., Any]] = {}
    for mod in (back_office_tools, customer_tools, knowledge_tools, csr_tools, ops_tools):
        for name, fn in vars(mod).items():
            if inspect.isfunction(fn) and fn.__module__ == mod.__name__ and not name.startswith("_"):
                out[name] = fn
    return out


ToolCaller = Callable[[str, dict[str, Any], Any], Any]


def make_tool_proxy(original: Callable[..., Any], invoke_remote: ToolCaller) -> Callable[..., Any]:
    """Async proxy with the original tool's name/docstring/parameters (+tool_context)."""
    sig = inspect.signature(original)
    params = list(sig.parameters.values()) + [
        inspect.Parameter("tool_context", inspect.Parameter.KEYWORD_ONLY, annotation=ToolContext)
    ]
    name = original.__name__

    async def proxy(**kwargs: Any) -> Any:
        tool_context = kwargs.pop("tool_context", None)
        return await invoke_remote(name, kwargs, tool_context)

    proxy.__name__ = name
    proxy.__qualname__ = name
    proxy.__doc__ = original.__doc__
    proxy.__signature__ = sig.replace(parameters=params)  # type: ignore[attr-defined]
    proxy.__annotations__ = {**getattr(original, "__annotations__", {}), "tool_context": ToolContext}
    return proxy


AgentCaller = Callable[[str, dict[str, Any]], Any]


class RemoteAgentProxy(BaseAgent):
    """Stands in for an orchestrator child that runs in another workload."""

    output_key: str | None = None
    model_config = {"arbitrary_types_allowed": True}

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        message = ""
        if ctx.user_content and ctx.user_content.parts:
            message = "".join(p.text or "" for p in ctx.user_content.parts)
        delta = await REMOTE_AGENT_CALLER(self.name, {"message": message, "state": dict(ctx.session.state)})
        if not isinstance(delta, dict):
            delta = {}
        if self.output_key and self.output_key not in delta:
            delta[self.output_key] = json.dumps({"status": "no_output"})
        yield Event(
            invocation_id=ctx.invocation_id,
            author=self.name,
            branch=ctx.branch,
            actions=EventActions(state_delta=delta),
            content=types.Content(role="model", parts=[types.Part(text=json.dumps(delta, sort_keys=True)[:4000])]),
        )


async def _unset_remote_agent_caller(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    raise RuntimeError("remote agent caller not configured")

REMOTE_AGENT_CALLER: AgentCaller = _unset_remote_agent_caller


def build_hosted_agent(agent_id: str, *, invoke_tool: ToolCaller, invoke_agent: AgentCaller) -> Any:
    global REMOTE_AGENT_CALLER
    w = catalog.AGENTS[agent_id]
    root = build_original_tree()
    agent = find_agent(root, agent_id)
    agent.parent_agent = None                  # its parent lives in another workload
    if isinstance(agent, LlmAgent):
        agent.model = ScriptedLlm(model=f"scripted/{agent_id}")
        agent.tools = [make_tool_proxy(fn, invoke_tool) for fn in agent.tools]
    elif w.orchestrator:
        REMOTE_AGENT_CALLER = invoke_agent
        proxies = []
        for field, child_name in catalog.ORCHESTRATOR_CHILDREN[agent_id].items():
            child = getattr(agent, field)
            proxy = RemoteAgentProxy(name=child_name, description=child.description,
                                     output_key=getattr(child, "output_key", None))
            setattr(agent, field, proxy)
            proxies.append(proxy)
        agent.sub_agents = proxies
    else:
        raise ValueError(f"unsupported hosted agent type for {agent_id}: {type(agent).__name__}")
    return agent
