"""In-process enforcement for any ADK application: ``ZeroTrustPlugin`` (an ADK BasePlugin).

Register it on the application's App or Runner::

    from zt_adk import ZeroTrustPlugin
    plugin = ZeroTrustPlugin.from_profile("zt_adk.yaml", root_agent=root_agent)
    app = App(name="my_app", root_agent=root_agent, plugins=[plugin])

Boundaries (every decision comes from the signed PSL store of the bundle):

* input      on_user_message: content rules (input_message) + PDP input placement; a denied
             message is replaced (never stored) and the entry agent is short-circuited in
             before_agent, so no agent sees it (ADK 2.x ignores content returned by before_run)
* route      before_agent (orchestration by workflow/custom agents, entry, resumption) and the
             transfer_to_agent tool call (LLM transfer): PDP route placement + workflow monitor
* agent tool AgentTool call: agent_message content rules + PDP route placement; the agent
             behind it runs in a child runner that inherits this plugin and the run context
* tool       before_tool: tool_call rules, PDP tool placement (Permit Lease, approvals for
             MANUAL_REVIEW), workflow monitor admission, obligations, idempotency;
             after_tool: masking, tool_result content rules (deny, or flag = taint the run);
             on_tool_error: a call of a function ADK does not offer the agent is refused and
             audited and taints the run (ADK alone ends the run with an exception up to 2.7);
             later ADK 2.x first offers such a call to before_tool, where it is refused the same way
* model      before_model: only functions the bundle lists for the agent, built-in
             capabilities only for agents that declare them (model_request rules + PDP)
* output     on_event: user-visible text is checked (output_message rules + PDP output
             placement); streamed partial text is held back until the final event is checked
"""
from __future__ import annotations

import contextvars
import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from google.adk.plugins.base_plugin import BasePlugin
from google.adk.tools.agent_tool import AgentTool
from google.genai import types

from .content import content_parts_text, text_of
from . import model as M
from .discovery import discover
from .engine import PendingTool, ProtectionEngine, RunContext, Verdict
from .manifest import INGRESS_RUNTIME
from .profile import Profile, load_profile

TRANSFER_TOOL = "transfer_to_agent"
BUILTIN_FIELDS = ("google_search", "google_search_retrieval", "code_execution", "retrieval", "url_context",
                  "enterprise_web_search", "google_maps", "computer_use", "file_search")


class StaleBundleError(RuntimeError):
    """The running application differs from the one the bundle was built for."""


@dataclass
class _Nested:
    run: "_RunState"
    caller: str
    target: str


_NESTED: contextvars.ContextVar[_Nested | None] = contextvars.ContextVar("zt_adk_nested_run", default=None)


@dataclass
class _RunState:
    ctx: RunContext
    nested: bool = False
    nested_target: str = ""
    input_denied: str | None = None
    input_verdict: Verdict | None = None
    running: Counter = field(default_factory=Counter)
    stack: list[str] = field(default_factory=list)
    pending_transfer: dict[str, tuple[str, Verdict | None]] = field(default_factory=dict)   # target -> (caller, verdict)
    pending_tools: dict[str, PendingTool] = field(default_factory=dict)
    agent_tool_tokens: dict[str, contextvars.Token] = field(default_factory=dict)
    output_authorized: dict[str, Verdict] = field(default_factory=dict)
    builtin_authorized: dict[str, Verdict] = field(default_factory=dict)
    started: bool = False
    own_texts: set[str] = field(default_factory=set)   # denials this plugin emitted (whatever author ADK gives them)
    graphs_started: set[str] = field(default_factory=set)   # graph workflows entered in this run
    entry_verdict: Verdict | None = None               # graph root: the refused entry route


def _denial(boundary: str, verdict: Verdict, **extra: Any) -> dict[str, Any]:
    status = "pending_approval" if verdict.decision == "MANUAL_REVIEW" and verdict.approval_id else "zero_trust_denied"
    out = {"status": status, "boundary": boundary, "reason": verdict.reason[:500], "decision": verdict.decision}
    if verdict.rules:
        out["rules"] = verdict.rules
    if verdict.approval_id:
        out["approval_id"] = verdict.approval_id
    out.update(extra)
    return out


def own_plugins(app: Any) -> list[Any]:
    """The application's own plugins (of an App or a Runner), without a ZeroTrustPlugin it may
    already register: the Backplane adds exactly one."""
    plugins = list(getattr(app, "plugins", None) or [])
    manager = getattr(app, "plugin_manager", None)            # a Runner
    if not plugins and manager is not None:
        plugins = list(getattr(manager, "plugins", None) or [])
    return [p for p in plugins if not isinstance(p, ZeroTrustPlugin)]


def protected_runner(app: Any, plugin: "ZeroTrustPlugin", *, root_agent: Any, app_name: str,
                     session_service: Any) -> Any:
    """A Runner for the application object ``app`` (App, root agent or Runner), with ``plugin``
    first and the application's own plugins after it. An App keeps its whole configuration
    (context cache, resumability, compaction, ...). ADK runs plugins in order and the first
    callback that returns a value ends the chain, so the PEP decides before any other plugin."""
    from google.adk.apps import App
    from google.adk.runners import Runner

    plugins = [plugin, *own_plugins(app)]
    adk_app = app if isinstance(app, App) else getattr(app, "app", None)
    if isinstance(adk_app, App):
        return Runner(app=adk_app.model_copy(update={"root_agent": root_agent, "plugins": plugins}),
                      app_name=app_name, session_service=session_service)
    return Runner(app_name=app_name, agent=root_agent, plugins=plugins, session_service=session_service)


def missing_tool(tool: Any) -> bool:
    """ADK's stand-in for a function call that names no tool of the agent: a plain BaseTool
    described "Tool not found". ADK up to 2.7 passes it to on_tool_error with the ValueError of
    the lookup (and ends the run if no callback answers); later 2.x versions first offer it to
    the before_tool callbacks."""
    from google.adk.tools.base_tool import BaseTool

    return type(tool) is BaseTool and str(getattr(tool, "description", "")) == "Tool not found"


def tool_not_found(tool: Any, error: Exception) -> bool:
    return isinstance(error, ValueError) and missing_tool(tool)


# the node path of the tool node running now (set by the tool-node callbacks below on ADK versions
# that do not run plugin callbacks for tool nodes; newer ADK puts the node path on the tool context)
_NODE_PATH: contextvars.ContextVar[str | None] = contextvars.ContextVar("zt_adk_tool_node_path", default=None)


def tool_nodes_run_plugin_callbacks() -> bool:
    """Whether this ADK runs a graph workflow's tool nodes between the plugin tool callbacks
    (newer ADK 2.x does; ADK 2.7 calls the tool directly)."""
    try:
        from google.adk.workflow._tool_node import _ToolNode
    except ImportError:                     # ADK 1.x: no graph workflows
        return True
    return hasattr(_ToolNode, "_run_tool_with_plugin_callbacks") or bool(getattr(_ToolNode, "_zt_adk_callbacks", False))


def guard_tool_nodes(root_agent: Any, plugin: "ZeroTrustPlugin") -> None:
    """Make every tool node run its tool between the plugin tool callbacks, as newer ADK does:
    on an ADK whose tool nodes call the tool directly, ``_ToolNode._run_impl`` is extended once
    per process with exactly the callback steps newer ADK has (before_tool may answer instead of
    the tool, on_tool_error, after_tool may replace the result). All plugins of the run see the
    calls, so tool nodes created at run time (``ctx.run_node(tool)``) are covered too."""
    if tool_nodes_run_plugin_callbacks():
        return
    from google.adk.workflow import _tool_node as tool_node_module

    cls = tool_node_module._ToolNode
    original = cls._run_impl

    async def _run_impl(self: Any, *, ctx: Any, node_input: Any) -> Any:
        tool = self.tool
        if isinstance(tool, _CallbackTool):
            async for item in original(self, ctx=ctx, node_input=node_input):
                yield item
            return
        object.__setattr__(self, "tool", _CallbackTool(tool, str(getattr(ctx, "node_path", "") or "")))
        try:
            async for item in original(self, ctx=ctx, node_input=node_input):
                yield item
        finally:
            object.__setattr__(self, "tool", tool)

    cls._run_impl = _run_impl
    cls._zt_adk_callbacks = True


def _base_tool() -> type:
    from google.adk.tools.base_tool import BaseTool

    return BaseTool


class _CallbackTool(_base_tool()):  # type: ignore[misc]
    """The tool of a tool node, run between the plugin tool callbacks (see guard_tool_nodes)."""

    def __init__(self, tool: Any, node_path: str) -> None:
        super().__init__(name=tool.name, description=getattr(tool, "description", "") or tool.name)
        self._tool = tool
        self._node_path = node_path

    def _get_declaration(self) -> Any:
        return self._tool._get_declaration()

    async def run_async(self, *, args: dict[str, Any], tool_context: Any) -> Any:
        manager = tool_context._invocation_context.plugin_manager
        token = _NODE_PATH.set(self._node_path)
        try:
            response = await manager.run_before_tool_callback(tool=self._tool, tool_args=args,
                                                              tool_context=tool_context)
            if response is not None:
                return response
            try:
                result = await self._tool.run_async(args=args, tool_context=tool_context)
            except Exception as error:
                handled = await manager.run_on_tool_error_callback(tool=self._tool, tool_args=args,
                                                                   tool_context=tool_context, error=error)
                if handled is None:
                    raise
                return handled
            altered = await manager.run_after_tool_callback(tool=self._tool, tool_args=args,
                                                            tool_context=tool_context, result=result)
            return altered if altered is not None else result
        finally:
            _NODE_PATH.reset(token)


def _denial_content(boundary: str, verdict: Verdict, trace_id: str) -> types.Content:
    return types.Content(role="model", parts=[types.Part(text=json.dumps(
        _denial(boundary, verdict, trace_id=trace_id), ensure_ascii=False))])


class ZeroTrustPlugin(BasePlugin):
    def __init__(self, *, root_agent: Any, bundle_dir: str | Path, keys_dir: str | Path, state_dir: str | Path,
                 mode: str | None = None, name: str = "zero_trust_backplane", verify_structure: bool = True,
                 approvals_dir: str | Path | None = None, process_spiffe_id: str | None = None,
                 engine: ProtectionEngine | None = None) -> None:
        super().__init__(name=name)
        self.engine = engine or ProtectionEngine(bundle_dir=bundle_dir, keys_dir=keys_dir, state_dir=state_dir,
                                                 runtime="native", mode=mode, approvals_dir=approvals_dir,
                                                 process_spiffe_id=process_spiffe_id)
        self.root_name = str(root_agent.name)
        live_objects: dict[str, Any] = {}
        if verify_structure:
            live, live_objects, _t = discover(root_agent, resolve_toolsets=False)
            if live.fingerprint() != self.engine.index["fingerprint"]:
                raise StaleBundleError(
                    "the ADK application changed since the protection bundle was built "
                    f"(bundle {self.engine.index['fingerprint'][:12]}, live {live.fingerprint()[:12]}): "
                    "run 'zt-adk build' again")
        self.kinds = {n: a.kind for n, a in self.engine.model.agents.items()}
        self.graph_root = self.kinds.get(self.root_name) == M.GRAPH
        if any(k == M.GRAPH for k in self.kinds.values()):
            guard_tool_nodes(root_agent, self)
        self.parent = {n: a.parent for n, a in self.engine.model.agents.items()}
        self._runs: dict[str, _RunState] = {}
        self._sessions: dict[str, str] = {}
        self._last_run: RunContext | None = None

    @classmethod
    def from_profile(cls, profile: str | Path | Profile, *, root_agent: Any = None, **kwargs: Any) -> "ZeroTrustPlugin":
        prof = profile if isinstance(profile, Profile) else load_profile(profile)
        if root_agent is None:
            from .discovery import load_object, resolve_app

            root_agent, _name, _plugins = resolve_app(load_object(prof.app, [prof.path(p) for p in prof.python_paths]))
        return cls(root_agent=root_agent, bundle_dir=prof.path(prof.bundle_dir), keys_dir=prof.path(prof.keys_dir),
                   state_dir=prof.path(prof.state_dir), **kwargs)

    # -- trusted session facts (the application's authenticated front end calls this) ----------
    def register_session(self, session_id: str, *, user_role: str = "") -> None:
        """Declare a session created by the application's trusted (authenticating) front end and
        the end user's role. Session state written by agents or clients is never trusted."""
        self._sessions[str(session_id)] = str(user_role)

    def last_run(self) -> RunContext | None:
        return self._last_run

    # -- helpers ---------------------------------------------------------------------------------
    def _state(self, invocation_id: str) -> _RunState:
        st = self._runs.get(invocation_id)
        if st is None:                       # a callback without on_user_message (e.g. resumed run)
            st = _RunState(RunContext(invocation_id=invocation_id))
            self._runs[invocation_id] = st
        return st

    @staticmethod
    def _inv(ctx: Any) -> str:
        return str(getattr(ctx, "invocation_id", "") or "unknown-invocation")

    def _caller_of(self, st: _RunState, target: str) -> str:
        if target in st.pending_transfer:
            return st.pending_transfer[target][0]
        parent = self.parent.get(target)
        if parent is not None and st.running.get(parent):
            return parent
        if st.stack:
            return st.stack[-1]
        return INGRESS_RUNTIME

    # -- input -------------------------------------------------------------------------------------
    async def on_user_message_callback(self, *, invocation_context: Any, user_message: Any) -> Any:
        inv = self._inv(invocation_context)
        nested = _NESTED.get()
        entry = str(getattr(getattr(invocation_context, "agent", None), "name", "") or self.root_name)
        if nested is not None and entry == nested.target:
            self._runs[inv] = _RunState(nested.run.ctx, nested=True, nested_target=entry)
            return None
        session = getattr(invocation_context, "session", None)
        session_id = str(getattr(session, "id", "") or "")
        ctx = RunContext(invocation_id=inv, session_id=session_id, user_role=self._sessions.get(session_id, ""),
                         session_present=session_id in self._sessions)
        st = _RunState(ctx)
        self._runs[inv] = st
        self._last_run = ctx
        parts = list(getattr(user_message, "parts", None) or [])
        kind = "function_response" if any(getattr(p, "function_response", None) for p in parts) else "text"
        text = content_parts_text(parts)
        verdict = self.engine.check_input(ctx, text, kind=kind, entry_agent=entry)
        if self.engine.should_execute(verdict):
            verdict = self.engine.authorize(ctx, self.engine.input_placement,
                                            parameters={"message_sha256": hashlib.sha256(text.encode()).hexdigest(),
                                                        "message_length": len(text), "kind": kind},
                                            event="INPUT_AUTHORIZATION", caller=INGRESS_RUNTIME, target=entry)
        if self.engine.should_execute(verdict):
            return None
        st.input_denied = verdict.reason
        st.input_verdict = verdict
        # The refused message is replaced before ADK stores it: its text never reaches the session
        # history or a model. The entry agent is then skipped (before_run / before_agent).
        return types.Content(role="user", parts=[types.Part(text=json.dumps(
            _denial("input", verdict, trace_id=ctx.trace_id), ensure_ascii=False))])

    def _input_denial(self, st: _RunState) -> Any:
        v = st.input_verdict or Verdict(False, "DENY", st.input_denied or "input denied", "INPUT")
        return self._own(st, _denial_content("input", v, st.ctx.trace_id))

    @staticmethod
    def _own(st: _RunState, content: types.Content) -> types.Content:
        """Remember a denial this plugin emits. ADK delivers it as an event (author: the agent, or
        'model' when before_run ends the run early, ADK >= 2.13); on_event passes it unchanged."""
        st.own_texts.add("".join(str(p.text) for p in content.parts or [] if getattr(p, "text", None)))
        return content

    async def before_run_callback(self, *, invocation_context: Any) -> Any:
        st = self._state(self._inv(invocation_context))
        if st.input_denied and not st.nested:
            return self._input_denial(st)
        if self.graph_root and not st.nested:
            # a graph workflow root runs no agent callback of its own: its entry route is decided
            # here, before any of its nodes runs
            v = self._enter_graph(st, self.root_name, INGRESS_RUNTIME)
            if v is not None:
                st.entry_verdict = v
                return self._own(st, _denial_content("agent_route", v, st.ctx.trace_id))
        return None

    def _enter_graph(self, st: _RunState, workflow: str, caller: str) -> Verdict | None:
        """Authorize and admit the route ``caller -> workflow`` (a graph workflow entered in this
        run); None when allowed (or already entered), else the refusing verdict."""
        if workflow in st.graphs_started:
            return None
        v = self.engine.authorize(st.ctx, self.engine.route_placement(caller, workflow),
                                  parameters={"target_agent": workflow}, event="AGENT_ROUTE_AUTHORIZATION",
                                  caller=caller, target=workflow)
        self.engine.admit_route(st.ctx, caller, workflow, v)
        if not self.engine.should_execute(v):
            return v
        st.graphs_started.add(workflow)
        st.running[workflow] += 1
        return None

    def _enter_graph_chain(self, st: _RunState, workflow: str) -> Verdict | None:
        """Enter ``workflow`` and every enclosing graph workflow not entered yet in this run
        (nested workflows run no callback: they are entered when one of their nodes starts)."""
        chain = [workflow]
        while True:
            parent = self.parent.get(chain[-1])
            if parent is None or self.kinds.get(parent) != M.GRAPH:
                break
            chain.append(parent)
        for wf in reversed(chain):
            parent = self.parent.get(wf)
            v = self._enter_graph(st, wf, parent if parent is not None else INGRESS_RUNTIME)
            if v is not None:
                return v
        return None

    def _tool_owner(self, tool_context: Any) -> str:
        """The agent (or graph workflow) a tool call belongs to. A tool node of a graph workflow
        has no owning agent (ADK reports 'unknown'): the nearest graph workflow in its node path
        owns it."""
        agent = str(getattr(tool_context, "agent_name", "") or "")
        if agent in self.kinds:
            return agent
        path = str(getattr(tool_context, "node_path", "") or _NODE_PATH.get() or "")
        for segment in reversed(path.split("/")[:-1]):
            name = segment.rsplit("@", 1)[0]
            if self.kinds.get(name) == M.GRAPH:
                return name
        return agent

    # -- routes --------------------------------------------------------------------------------------
    async def before_agent_callback(self, *, agent: Any, callback_context: Any) -> Any:
        st = self._state(self._inv(callback_context))
        target = str(agent.name)
        if st.input_denied and not st.nested:
            return self._input_denial(st)       # ADK 2.x ignores before_run's content: stop here
        if st.entry_verdict is not None:
            return self._own(st, _denial_content("agent_route", st.entry_verdict, st.ctx.trace_id))
        parent = self.parent.get(target)
        if parent is not None and self.kinds.get(parent) == M.GRAPH:
            refused = self._enter_graph_chain(st, parent)       # the node's caller is its workflow
            if refused is not None:
                return self._own(st, _denial_content("agent_route", refused, st.ctx.trace_id))
        if st.nested and not st.started and target == st.nested_target:
            st.started = True                 # authorized as the AgentTool call
            st.running[target] += 1
            st.stack.append(target)
            return None
        st.started = True
        caller = self._caller_of(st, target)
        pre = st.pending_transfer.pop(target, None)
        if pre is not None and pre[1] is not None and pre[1].allowed:
            verdict = pre[1]                  # authorized (and admitted) at the transfer_to_agent call
        else:
            placement = self.engine.route_placement(caller, target)
            verdict = self.engine.authorize(st.ctx, placement, parameters={"target_agent": target},
                                            event="AGENT_ROUTE_AUTHORIZATION", caller=caller, target=target)
            self.engine.admit_route(st.ctx, caller, target, verdict)
        if not self.engine.should_execute(verdict):
            return self._own(st, _denial_content("agent_route", verdict, st.ctx.trace_id))
        st.running[target] += 1
        st.stack.append(target)
        return None

    async def after_agent_callback(self, *, agent: Any, callback_context: Any) -> Any:
        st = self._state(self._inv(callback_context))
        name = str(agent.name)
        if st.running.get(name):
            st.running[name] -= 1
        for i in range(len(st.stack) - 1, -1, -1):
            if st.stack[i] == name:
                del st.stack[i]
                break
        return None

    # -- tools ---------------------------------------------------------------------------------------
    @staticmethod
    def _call_key(tool_context: Any, tool_name: str) -> str:
        return f"{getattr(tool_context, 'invocation_id', '')}:{getattr(tool_context, 'function_call_id', '') or tool_name}"

    async def before_tool_callback(self, *, tool: Any, tool_args: dict[str, Any], tool_context: Any) -> Any:
        st = self._state(self._inv(tool_context))
        agent = self._tool_owner(tool_context)
        name = str(getattr(tool, "name", "") or "")
        ctx = st.ctx
        if missing_tool(tool):                # a function ADK does not offer this agent (later ADK 2.x)
            return self._refuse_undeclared(st, agent, name, tool_args)
        if name == TRANSFER_TOOL:
            target = str(tool_args.get("agent_name", "") or "")
            placement = self.engine.route_placement(agent, target)
            v = self.engine.authorize(ctx, placement, parameters={"target_agent": target},
                                      event="AGENT_ROUTE_AUTHORIZATION", caller=agent, target=target)
            self.engine.admit_route(ctx, agent, target, v)
            if not self.engine.should_execute(v):
                return _denial("agent_route", v, agent=agent, target_agent=target, trace_id=ctx.trace_id)
            st.pending_transfer[target] = (agent, v)
            return None
        target_agent = self.engine.agent_tool_target(agent, name)
        if isinstance(tool, AgentTool) or target_agent:
            target = target_agent or str(tool.agent.name)
            message = str(tool_args.get("request") if "request" in tool_args else text_of(tool_args))
            check = self.engine.check_agent_message(ctx, agent, target, message)
            if not self.engine.should_execute(check):
                return _denial("agent_message", check, agent=agent, target_agent=target, trace_id=ctx.trace_id)
            placement = self.engine.route_placement(agent, target)
            v = self.engine.authorize(ctx, placement, parameters={"target_agent": target,
                                                                  "request_sha256": hashlib.sha256(
                                                                      message.encode()).hexdigest()},
                                      event="AGENT_TOOL_AUTHORIZATION", caller=agent, target=target)
            self.engine.admit_route(ctx, agent, target, v)
            if not self.engine.should_execute(v):
                return _denial("agent_route", v, agent=agent, target_agent=target, trace_id=ctx.trace_id)
            st.agent_tool_tokens[self._call_key(tool_context, name)] = _NESTED.set(_Nested(st, agent, target))
            return None
        call_key = self._call_key(tool_context, name)
        pending = await self.engine.begin_tool(ctx, agent=agent, tool=name, args=dict(tool_args),
                                               call_id=str(getattr(tool_context, "function_call_id", "") or ""))
        if not self.engine.should_execute(pending.verdict, critical=pending.critical) or (
                pending.verdict.allowed and not pending.reserved and pending.pep is not None):
            return _denial("tool", pending.verdict, tool=name, agent=agent, trace_id=ctx.trace_id)
        st.pending_tools[call_key] = pending
        return None

    async def after_tool_callback(self, *, tool: Any, tool_args: dict[str, Any], tool_context: Any,
                                  result: Any) -> Any:
        st = self._state(self._inv(tool_context))
        agent = self._tool_owner(tool_context)
        name = str(getattr(tool, "name", "") or "")
        actions = getattr(tool_context, "actions", None)
        transfer = getattr(actions, "transfer_to_agent", None) if actions is not None else None
        if transfer and name != TRANSFER_TOOL and transfer not in st.pending_transfer:
            st.pending_transfer[str(transfer)] = (agent, None)     # authorized when the agent starts
        if name == TRANSFER_TOOL:
            return None
        call_key = self._call_key(tool_context, name)
        token = st.agent_tool_tokens.pop(call_key, None)
        if token is not None:
            _NESTED.reset(token)
            check = self.engine.check_tool_result(st.ctx, agent, name, text_of(result))
            if not self.engine.should_execute(check):
                return _denial("tool_result", check, tool=name, agent=agent, trace_id=st.ctx.trace_id)
            return None
        pending = st.pending_tools.pop(call_key, None)
        if pending is None:
            return None
        protected, check = self.engine.finish_tool(pending, result)
        if check is not None and not self.engine.should_execute(check):
            return _denial("tool_result", check, tool=name, agent=agent, trace_id=st.ctx.trace_id)
        return protected if protected is not result else None

    async def on_tool_error_callback(self, *, tool: Any, tool_args: dict[str, Any], tool_context: Any,
                                     error: Exception) -> Any:
        st = self._state(self._inv(tool_context))
        name = str(getattr(tool, "name", "") or "")
        call_key = self._call_key(tool_context, name)
        token = st.agent_tool_tokens.pop(call_key, None)
        if token is not None:
            _NESTED.reset(token)
        pending = st.pending_tools.pop(call_key, None)
        if pending is None and token is None and tool_not_found(tool, error):
            # The model called a function ADK does not offer this agent (ADK up to 2.7: ADK would
            # end the whole run with an exception). The PEP refuses the call; the agent goes on.
            return self._refuse_undeclared(st, self._tool_owner(tool_context), name, tool_args)
        self.engine.abort_tool(pending, f"{type(error).__name__}: {error}")
        return None

    def _refuse_undeclared(self, st: _RunState, agent: str, name: str, tool_args: Any) -> dict[str, Any]:
        v = self.engine.deny_undeclared_call(st.ctx, agent, name, dict(tool_args or {}))
        boundary = "agent_route" if name == TRANSFER_TOOL else "tool"
        return _denial(boundary, v, tool=name, agent=agent, trace_id=st.ctx.trace_id)

    # -- model requests ------------------------------------------------------------------------------
    async def before_model_callback(self, *, callback_context: Any, llm_request: Any) -> Any:
        from google.adk.models import LlmResponse

        st = self._state(self._inv(callback_context))
        agent = str(getattr(callback_context, "agent_name", "") or "")
        functions: set[str] = set((getattr(llm_request, "tools_dict", None) or {}).keys())
        fields: set[str] = set()
        config = getattr(llm_request, "config", None)
        for t in list(getattr(config, "tools", None) or []):
            for fd in list(getattr(t, "function_declarations", None) or []):
                functions.add(str(fd.name))
            for f in BUILTIN_FIELDS:
                if getattr(t, f, None) is not None:
                    fields.add(f)
        names, undeclared = self.engine.builtin_names(agent, fields)
        check = self.engine.check_model_request(st.ctx, agent, sorted(functions), names, undeclared)
        if self.engine.should_execute(check):
            for b in names:
                if b in st.builtin_authorized:
                    continue
                v = self.engine.authorize(st.ctx, self.engine.tool_placement(agent, b), parameters={"builtin": b},
                                          event="BUILTIN_AUTHORIZATION", caller=agent, target=b)
                st.builtin_authorized[b] = v
                if not self.engine.should_execute(v):
                    check = v
                    break
        if not self.engine.should_execute(check):
            return LlmResponse(content=self._own(st, _denial_content("model_request", check, st.ctx.trace_id)))
        return None

    # -- output --------------------------------------------------------------------------------------
    async def on_event_callback(self, *, invocation_context: Any, event: Any) -> Any:
        st = self._runs.get(self._inv(invocation_context))
        if st is None or st.nested:
            return None
        author = str(getattr(event, "author", "") or "")
        content = getattr(event, "content", None)
        parts = list(getattr(content, "parts", None) or [])
        text_parts = [p for p in parts if getattr(p, "text", None)]
        if author in ("", "user") or not text_parts:
            return None
        other = [p for p in parts if not getattr(p, "text", None)]
        if getattr(event, "partial", False):
            # streamed text is withheld; the final (non-partial) event carries the full text and is checked
            return event.model_copy(update={"content": types.Content(role=content.role, parts=other) if other else None})
        text = "".join(str(p.text) for p in text_parts)
        if text in st.own_texts and not other:
            return None                       # the plugin's own denial: already decided, shown as is
        verdict = self.engine.check_output(st.ctx, author, text)
        if self.engine.should_execute(verdict):
            pv = st.output_authorized.get(author)
            if pv is None:
                pv = self.engine.authorize(
                    st.ctx, self.engine.output_placement(author),
                    parameters={"output_sha256": hashlib.sha256(text.encode()).hexdigest(), "output_length": len(text)},
                    event="OUTPUT_AUTHORIZATION", caller=author, target="mas_output_channel")
                if pv.allowed:
                    st.output_authorized[author] = pv
            if not pv.allowed:
                verdict = pv
        if self.engine.should_execute(verdict):
            return None
        denial = types.Part(text=json.dumps(_denial("output", verdict, agent=author, trace_id=st.ctx.trace_id),
                                            ensure_ascii=False))
        return event.model_copy(update={"content": types.Content(role=content.role or "model", parts=other + [denial])})

    async def after_run_callback(self, *, invocation_context: Any) -> Any:
        inv = self._inv(invocation_context)
        st = self._runs.pop(inv, None)
        if st is not None and not st.nested:
            violations = self.engine.close_run(st.ctx)
            self.engine.audit.write("RUN_COMPLETE", run=st.ctx.workflow_instance_id, trace_id=st.ctx.trace_id,
                                    invocation_id=inv, tainted=st.ctx.tainted, taint=st.ctx.taint_reasons,
                                    close_violations=violations)
        return None

    async def close(self) -> None:
        self.engine.close()
