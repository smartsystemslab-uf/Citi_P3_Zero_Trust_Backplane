"""ADK semantics across workloads: every agent in its own container, nothing else changed.

A workload builds the application's agent tree from the application's own code and hosts one
agent of it. What lies outside its container is replaced by network stand-ins that go through
the gateway PEP with this workload's SPIFFE identity:

* ``RemoteAgentProxy``   a child of a workflow / custom agent, an LLM transfer target (sub-agent,
                         parent, peer). It sends the session (events, state, user content) to the
                         target's workload and yields the events the target produced there -- the
                         local runner appends them, so state deltas, ``escalate`` (LoopAgent) and
                         ParallelAgent branches behave as in one process.
* ``RemoteFunctionTool`` every tool with an implementation (FunctionTool, LongRunningFunctionTool,
                         toolset tools, custom tools). Its body runs in the gateway's tool host,
                         never in the agent's container; session-state writes and actions
                         (transfer_to_agent, escalate, skip_summarization) come back with the result.
* ``RemoteAgentTool``    an AgentTool: the agent behind it runs in its own workload with a fresh
                         session (as ADK's AgentTool does); the result and state delta come back.

Model-side built-in tools (google_search, ...) stay as they are: the model provider executes them.

ADK builds every agent's model request from the session events (other agents' events become
"For context:" user content), so a hosted agent that receives the full session sees exactly the
conversation it would see in one process.
"""
from __future__ import annotations

import json
from typing import Any, AsyncGenerator, Awaitable, Callable, Optional

from google.adk.agents import BaseAgent, LlmAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event, EventActions
from google.adk.tools.agent_tool import AgentTool
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.base_toolset import BaseToolset
from google.genai import types

from zt_adk.discovery import child_agent_fields, is_builtin_tool

AgentInvoker = Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]
ToolInvoker = Callable[[str, str, dict[str, Any], str, dict[str, Any]], Awaitable[dict[str, Any]]]


class _Hooks:
    invoke_agent: Optional[AgentInvoker] = None
    call_tool: Optional[ToolInvoker] = None


HOOKS = _Hooks()


def dump_event(ev: Event) -> dict[str, Any]:
    return ev.model_dump(mode="json", exclude_none=True)


def load_event(raw: dict[str, Any]) -> Event:
    return Event.model_validate(raw)


def _error_event(name: str, ctx: InvocationContext, body: dict[str, Any]) -> Event:
    return Event(invocation_id=ctx.invocation_id, author=name, branch=ctx.branch,
                 content=types.Content(role="model", parts=[types.Part(text=json.dumps(body, ensure_ascii=False))]))


class RemoteAgentProxy(BaseAgent):
    """Stand-in for an agent that runs in another workload."""

    model_config = {"arbitrary_types_allowed": True}

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        if HOOKS.invoke_agent is None:
            raise RuntimeError("remote agent invocation is not configured in this workload")
        payload = {
            "mode": "run",
            "history": [dump_event(e) for e in ctx.session.events],
            "state": dict(ctx.session.state),
            "user_content": ctx.user_content.model_dump(mode="json", exclude_none=True) if ctx.user_content else None,
        }
        resp = await HOOKS.invoke_agent(self.name, payload)
        if resp.get("status") != "ok":
            yield _error_event(self.name, ctx, {k: v for k, v in resp.items() if k != "events"})
            return
        for raw in resp.get("events") or []:
            ev = load_event(raw)
            ev.invocation_id = ctx.invocation_id
            ev.branch = ctx.branch                    # keep ParallelAgent branch isolation
            yield ev


class RemoteLlmParentProxy(RemoteAgentProxy):
    """Stand-in for an LlmAgent parent: carries the transfer flags ADK reads from a parent."""

    disallow_transfer_to_parent: bool = False
    disallow_transfer_to_peers: bool = False


class RemoteFunctionTool(BaseTool):
    """A tool whose implementation runs behind the gateway PEP (tool host)."""

    def __init__(self, original: BaseTool) -> None:
        super().__init__(name=original.name, description=original.description,
                         is_long_running=bool(getattr(original, "is_long_running", False)))
        self._original = original

    def _get_declaration(self) -> Optional[types.FunctionDeclaration]:
        return self._original._get_declaration()

    async def run_async(self, *, args: dict[str, Any], tool_context: Any) -> Any:
        if HOOKS.call_tool is None:
            raise RuntimeError("remote tool calls are not configured in this workload")
        state = tool_context.state.to_dict() if hasattr(tool_context.state, "to_dict") else dict(tool_context.state)
        resp = await HOOKS.call_tool(str(tool_context.agent_name), self.name, dict(args),
                                     str(getattr(tool_context, "function_call_id", "") or ""), state)
        if resp.get("status") != "ok":
            return {k: v for k, v in resp.items() if k not in ("state_delta", "actions")}
        for key, value in (resp.get("state_delta") or {}).items():
            tool_context.state[key] = value
        actions = resp.get("actions") or {}
        if actions.get("transfer_to_agent"):
            tool_context.actions.transfer_to_agent = actions["transfer_to_agent"]
        if actions.get("escalate"):
            tool_context.actions.escalate = True
        if actions.get("skip_summarization"):
            tool_context.actions.skip_summarization = True
        return resp.get("result")


class RemoteAgentTool(BaseTool):
    """An AgentTool whose agent runs in its own workload (fresh session, as ADK's AgentTool)."""

    def __init__(self, original: AgentTool) -> None:
        super().__init__(name=original.name, description=original.description)
        self._original = original
        self._target = original.agent.name
        self._schema = getattr(original.agent, "output_schema", None)
        self.skip_summarization = bool(getattr(original, "skip_summarization", False))

    def _get_declaration(self) -> Optional[types.FunctionDeclaration]:
        return self._original._get_declaration()

    async def run_async(self, *, args: dict[str, Any], tool_context: Any) -> Any:
        if HOOKS.invoke_agent is None:
            raise RuntimeError("remote agent invocation is not configured in this workload")
        if self.skip_summarization:
            tool_context.actions.skip_summarization = True
        request = args.get("request") if set(args) == {"request"} else json.dumps(args, ensure_ascii=False)
        state = tool_context.state.to_dict() if hasattr(tool_context.state, "to_dict") else dict(tool_context.state)
        resp = await HOOKS.invoke_agent(self._target, {"mode": "agent_tool", "request": str(request), "state": state})
        if resp.get("status") != "ok":
            return {k: v for k, v in resp.items() if k not in ("events",)}
        for key, value in (resp.get("state_delta") or {}).items():
            if not key.startswith("_adk"):
                tool_context.state[key] = value
        text = str(resp.get("result_text") or "")
        if self._schema is not None and text:
            try:
                return json.loads(text)
            except ValueError:
                return text
        return text


def _proxy_for(agent: BaseAgent) -> RemoteAgentProxy:
    return RemoteAgentProxy(name=agent.name, description=agent.description or "")


def host_agent(agents: dict[str, BaseAgent], name: str) -> BaseAgent:
    """Rebind ``agents[name]`` for hosting in its own workload; returns the agent to run."""
    agent = agents[name]
    if isinstance(agent, LlmAgent):
        new_tools: list[Any] = []
        for tool in list(agent.tools or []):
            if isinstance(tool, AgentTool):
                new_tools.append(RemoteAgentTool(tool))
            elif isinstance(tool, BaseToolset):
                raise RuntimeError(f"{name}: toolsets are resolved into tools at hosting time; "
                                   "use host_tools() from the gateway's tool host")
            elif isinstance(tool, BaseTool) and is_builtin_tool(tool):
                new_tools.append(tool)                       # executed by the model provider
            elif isinstance(tool, BaseTool):
                new_tools.append(RemoteFunctionTool(tool))
            elif callable(tool):
                from google.adk.tools.function_tool import FunctionTool

                new_tools.append(RemoteFunctionTool(FunctionTool(tool)))
        agent.tools = new_tools
    else:
        for field_name, children in child_agent_fields(agent).items():
            value = getattr(agent, field_name)
            if isinstance(value, BaseAgent):
                setattr(agent, field_name, _proxy_for(value))
            elif isinstance(value, list):
                setattr(agent, field_name, [_proxy_for(v) if isinstance(v, BaseAgent) else v for v in value])
            elif isinstance(value, dict):
                setattr(agent, field_name, {k: (_proxy_for(v) if isinstance(v, BaseAgent) else v)
                                            for k, v in value.items()})
    proxies = []
    for child in list(agent.sub_agents or []):
        p = _proxy_for(child)
        p.parent_agent = agent
        proxies.append(p)
    agent.sub_agents = proxies
    parent = agent.parent_agent
    agent.parent_agent = None
    if parent is not None:
        peers = [_proxy_for(s) for s in parent.sub_agents if s.name != name]
        if isinstance(parent, LlmAgent):
            stand_in: RemoteAgentProxy = RemoteLlmParentProxy(
                name=parent.name, description=parent.description or "",
                disallow_transfer_to_parent=parent.disallow_transfer_to_parent,
                disallow_transfer_to_peers=parent.disallow_transfer_to_peers, sub_agents=[agent, *peers])
        else:
            stand_in = RemoteAgentProxy(name=parent.name, description=parent.description or "",
                                        sub_agents=[agent, *peers])
        _ = stand_in
    return agent
