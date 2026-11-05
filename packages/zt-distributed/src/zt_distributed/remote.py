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
                         custom tools; ``RemoteDeclaredTool`` for the tools of a toolset, declared
                         by the gateway's tool list). Its body runs in the gateway's tool host,
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

    def __init__(self, original: BaseTool, *, owner: str | None = None) -> None:
        """``owner``: the agent the tool belongs to when the tool context names none (the tool
        node of a graph workflow belongs to the workflow)."""
        super().__init__(name=original.name, description=original.description,
                         is_long_running=bool(getattr(original, "is_long_running", False)))
        self._original = original
        self._owner = owner

    def _get_declaration(self) -> Optional[types.FunctionDeclaration]:
        return self._original._get_declaration()

    async def run_async(self, *, args: dict[str, Any], tool_context: Any) -> Any:
        if HOOKS.call_tool is None:
            raise RuntimeError("remote tool calls are not configured in this workload")
        state = tool_context.state.to_dict() if hasattr(tool_context.state, "to_dict") else dict(tool_context.state)
        resp = await HOOKS.call_tool(self._owner or str(tool_context.agent_name), self.name, dict(args),
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


class RemoteDeclaredTool(RemoteFunctionTool):
    """A tool of one of the hosted agent's toolsets (MCP, OpenAPI, custom BaseToolset).

    A workload never resolves a toolset itself (no connection to an MCP server or API from an
    agent container): the gateway's tool host does, and the gateway's tool list -- derived from
    the signed bundle -- declares exactly the toolset tools this agent may call. Each becomes a
    proxy with that declaration; calls go to the gateway like every other tool."""

    def __init__(self, *, name: str, description: str = "", parameters: dict[str, Any] | None = None,
                 is_long_running: bool = False) -> None:
        BaseTool.__init__(self, name=name, description=description or name, is_long_running=is_long_running)
        self._original = None
        self._owner = None                            # the hosted agent (from the tool context)
        self._parameters = dict(parameters or {"type": "object", "properties": {}})

    def _get_declaration(self) -> Optional[types.FunctionDeclaration]:
        return types.FunctionDeclaration(name=self.name, description=self.description,
                                         parameters_json_schema=self._parameters)


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


# ---------------------------------------------------------------------------- graph workflows
def encode_node_input(value: Any) -> dict[str, Any]:
    """A graph node's input as JSON (what the previous node produced: text, a dict, Content, a
    pydantic model)."""
    from pydantic import BaseModel

    if isinstance(value, types.Content):
        return {"kind": "content", "value": value.model_dump(mode="json", exclude_none=True)}
    if isinstance(value, BaseModel):
        return {"kind": "json", "value": value.model_dump(mode="json")}
    return {"kind": "json", "value": json.loads(json.dumps(value, default=str))}


def decode_node_input(raw: dict[str, Any] | None) -> Any:
    if not raw:
        return None
    if raw.get("kind") == "content":
        return types.Content.model_validate(raw["value"])
    return raw.get("value")


def _graph_node_base() -> type:
    from google.adk.workflow import BaseNode

    return BaseNode


try:
    _BaseNode: Any = _graph_node_base()
except ImportError:                                   # ADK 1.x: no graph workflows
    _BaseNode = None


if _BaseNode is not None:
    class RemoteNodeProxy(_BaseNode):                 # type: ignore[misc,valid-type]
        """A node of a graph workflow that runs in its own workload (an agent node, a nested
        workflow, or an agent a function node starts). It sends the node's input, the session
        and its node path to that workload through the gateway (a route of the workflow) and
        yields the events the node produced there; their ``output`` is the node's output."""

        model_config = {"arbitrary_types_allowed": True}

        @classmethod
        def like(cls, node: Any) -> "RemoteNodeProxy":
            fields = {k: getattr(node, k) for k in ("rerun_on_resume", "wait_for_output", "retry_config", "timeout")
                      if k in type(node).model_fields and k in cls.model_fields}
            return cls(name=node.name, description=getattr(node, "description", "") or "", **fields)

        async def _run_impl(self, *, ctx: Any, node_input: Any) -> AsyncGenerator[Any, None]:
            if HOOKS.invoke_agent is None:
                raise RuntimeError("remote node invocation is not configured in this workload")
            ic = ctx.get_invocation_context()
            payload = {
                "mode": "node",
                "history": [dump_event(e) for e in ic.session.events],
                "state": dict(ic.session.state),
                "user_content": ic.user_content.model_dump(mode="json", exclude_none=True) if ic.user_content else None,
                "node_input": encode_node_input(node_input),
                "node_path": str(ctx.node_path or ""),
                "isolation_scope": getattr(ctx, "isolation_scope", None),
                "branch": ic.branch,
            }
            resp = await HOOKS.invoke_agent(self.name, payload)
            if resp.get("status") != "ok":
                body = {k: v for k, v in resp.items() if k != "events"}
                text = json.dumps(body, ensure_ascii=False)
                yield Event(invocation_id=ic.invocation_id, author=self.name, branch=ic.branch, output=text,
                            content=types.Content(role="model", parts=[types.Part(text=text)]))
                return
            own = str(ctx.node_path or "")
            for raw in resp.get("events") or []:
                ev = load_event(raw)
                ev.invocation_id = ic.invocation_id
                node_info = getattr(ev, "node_info", None)
                path = str(getattr(node_info, "path", "") or "")
                if own and path.startswith(own + "/"):
                    # an event of a descendant node (inside a nested workflow): in one process its
                    # own node runner enqueues it; it is not this node's event
                    await ic._enqueue_event(ev)
                    continue
                # The workload's node runner annotated this node's output event for this node's
                # path; that annotation is the job of the runner that consumes the node's events
                # -- here the workflow's, which annotates it again, exactly as for a local node.
                if node_info is not None and getattr(node_info, "output_for", None):
                    rest = [p for p in node_info.output_for if p != own]
                    node_info.output_for = rest or None
                if ev.author:                         # as LlmAgent._run_impl: keep the node's true author
                    ctx.event_author = ev.author
                yield ev
else:                                                 # pragma: no cover
    RemoteNodeProxy = None                            # type: ignore[assignment,misc]


def host_graph(workflow: Any) -> Any:
    """Host a graph workflow in its own workload: its graph runs here (function, join and custom
    nodes are the workflow's own code); every agent node, nested workflow and agent a function
    node starts is a RemoteNodeProxy of its workload, and every tool node's tool runs in the
    gateway's tool host as a tool of this workflow."""
    from zt_adk.code_analysis import dynamic_run_node_bindings
    from zt_adk.discovery import function_node_callable, is_graph_workflow

    name = str(workflow.name)
    graph = workflow.graph
    proxies: dict[int, Any] = {}

    def proxy_of(node: Any) -> Any:
        if id(node) not in proxies:
            proxies[id(node)] = RemoteNodeProxy.like(node)
        return proxies[id(node)]

    for i, node in enumerate(list(graph.nodes)):
        if str(node.name) == "__START__":
            continue
        inner = getattr(node, "_node", None) or node
        if isinstance(inner, BaseAgent) or is_graph_workflow(inner):
            if inner is node:
                graph.nodes[i] = proxy_of(node)
            else:                                     # _ParallelWorker: the wrapped node runs remotely
                node._node = proxy_of(inner)
        elif type(inner).__name__ == "_ToolNode" and not isinstance(inner.tool, RemoteFunctionTool):
            inner.tool = RemoteFunctionTool(inner.tool, owner=name)
        else:
            fn = function_node_callable(inner)
            for target, rebind in (dynamic_run_node_bindings(fn) if fn is not None else []):
                if isinstance(target, BaseAgent) or is_graph_workflow(target):
                    rebind(proxy_of(target))
                elif isinstance(target, BaseTool) and not isinstance(target, RemoteFunctionTool):
                    rebind(RemoteFunctionTool(target, owner=name))
    for edge in graph.edges:
        edge.from_node = proxies.get(id(edge.from_node), edge.from_node)
        edge.to_node = proxies.get(id(edge.to_node), edge.to_node)
    return workflow


def host_agent(agents: dict[str, BaseAgent], name: str, *,
               toolset_tools: list[dict[str, Any]] | None = None) -> BaseAgent:
    """Rebind ``agents[name]`` for hosting in its own workload; returns the agent to run.

    ``toolset_tools``: declarations ({name, description, parameters}) of the tools the agent's
    toolsets offer, from the gateway's tool list (required when the agent has a toolset)."""
    from zt_adk.discovery import is_graph_workflow

    agent = agents[name]
    if is_graph_workflow(agent):
        return host_graph(agent)
    if isinstance(agent, LlmAgent):
        new_tools: list[Any] = []
        toolsets_replaced = False
        for tool in list(agent.tools or []):
            if isinstance(tool, AgentTool):
                new_tools.append(RemoteAgentTool(tool))
            elif isinstance(tool, BaseToolset):
                if toolset_tools is None:
                    raise RuntimeError(f"{name}: hosting an agent with a toolset needs the declarations of the "
                                       "toolset's tools (the gateway's tool list)")
                if not toolsets_replaced:            # all of the agent's toolsets: the tools the bundle lists
                    new_tools.extend(RemoteDeclaredTool(**d) for d in toolset_tools)
                    toolsets_replaced = True
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
