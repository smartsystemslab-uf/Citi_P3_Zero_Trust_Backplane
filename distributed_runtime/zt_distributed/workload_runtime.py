"""Workload-side and gateway-side execution of the distributed ADK application.

``HostedAgentRunner``  runs this workload's agent for one remote invocation:
                       mode ``run``         the caller's session is rebuilt (state + events) and the
                                            agent continues it, exactly as in one process;
                       mode ``agent_tool``  a fresh session with the request as the user message
                                            (ADK AgentTool semantics); the final text and the
                                            state delta are returned.
``ToolHost``           the gateway's tool host: executes the application's real tool objects with a
                       real ADK ToolContext over the caller's session state; the state delta and the
                       tool's actions go back to the calling agent.
``ConversationStore``  the gateway's multi-turn sessions (events + state per session id) and ADK's
                       rule for which agent continues a conversation.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from google.adk.agents import BaseAgent
from google.adk.events import Event, EventActions
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from zt_adk.discovery import resumable

from .remote import dump_event, host_agent, load_event

USER_ID = "zt-workload"


def _state_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in after.items() if before.get(k, object()) != v and not k.startswith("temp:")}


def _final_text(events: list[Event]) -> str:
    for ev in reversed(events):
        if ev.content and ev.content.parts:
            texts = [p.text for p in ev.content.parts if getattr(p, "text", None) and not getattr(p, "thought", False)]
            if texts:
                return "\n".join(texts)
    return ""


class HostedAgentRunner:
    def __init__(self, *, agents: dict[str, BaseAgent], agent_name: str, app_name: str) -> None:
        self.agent = host_agent(agents, agent_name)
        self.app_name = app_name
        self.sessions = InMemorySessionService()
        self.runner = Runner(app_name=app_name, agent=self.agent, session_service=self.sessions)

    async def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        mode = payload.get("mode")
        if mode == "agent_tool":
            return await self._agent_tool(payload)
        if mode == "run":
            return await self._run(payload)
        return {"status": "bad_request", "reason": f"unknown mode {mode!r}"}

    async def _run(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Continue the caller's session with this workload's agent.

        The session is rebuilt from the caller's state and events (state deltas of past events
        are not re-applied: the state already contains them). The invocation context is made
        by the Runner itself, with the run's original user content, and the hosted agent runs
        in it as ADK runs a sub-agent: every event it yields is appended to the session before
        the next step reads the session (as the Runner does), so model requests are built from
        the same events as in one process."""
        from google.adk.agents.run_config import RunConfig

        state = dict(payload.get("state") or {})
        session = await self.sessions.create_session(app_name=self.app_name, user_id=USER_ID, state=state)
        try:
            for raw in payload.get("history") or []:
                ev = load_event(raw)
                ev.actions = ev.actions.model_copy(update={"state_delta": {}}) if ev.actions else EventActions()
                await self.sessions.append_event(session, ev)
            raw_uc = payload.get("user_content")
            user_content = types.Content.model_validate(raw_uc) if raw_uc else None
            ic = self.runner._new_invocation_context(session, new_message=user_content, run_config=RunConfig())
            ic.agent = self.agent
            out: list[Event] = []
            agen = self.agent.run_async(ic)
            try:
                async for ev in agen:
                    if not ev.partial:
                        await self.sessions.append_event(session, ev)
                        out.append(ev)
            finally:
                await agen.aclose()
            return {"status": "ok", "events": [dump_event(e) for e in out]}
        finally:
            await self.sessions.delete_session(app_name=self.app_name, user_id=USER_ID, session_id=session.id)

    async def _agent_tool(self, payload: dict[str, Any]) -> dict[str, Any]:
        state = {k: v for k, v in (payload.get("state") or {}).items() if not k.startswith("_adk")}
        session = await self.sessions.create_session(app_name=self.app_name, user_id=USER_ID, state=dict(state))
        try:
            out: list[Event] = []
            msg = types.Content(role="user", parts=[types.Part(text=str(payload.get("request") or ""))])
            async for ev in self.runner.run_async(user_id=USER_ID, session_id=session.id, new_message=msg):
                if not ev.partial:
                    out.append(ev)
            final = await self.sessions.get_session(app_name=self.app_name, user_id=USER_ID, session_id=session.id)
            return {"status": "ok", "result_text": _final_text(out),
                    "state_delta": _state_delta(state, dict(final.state) if final else {}), "events": len(out)}
        finally:
            await self.sessions.delete_session(app_name=self.app_name, user_id=USER_ID, session_id=session.id)


class ToolHost:
    def __init__(self, *, agents: dict[str, BaseAgent], tools: dict[str, Any], app_name: str) -> None:
        self.agents = agents
        self.tools = tools
        self.app_name = app_name
        self.sessions = InMemorySessionService()
        try:
            from google.adk.artifacts import InMemoryArtifactService

            self.artifacts: Any = InMemoryArtifactService()
        except ImportError:                       # pragma: no cover
            self.artifacts = None

    def callable_tool(self, agent: str, name: str) -> Any:
        from google.adk.tools.base_tool import BaseTool
        from google.adk.tools.function_tool import FunctionTool

        tool = self.tools.get(f"{agent}/{name}")
        if tool is None:
            return None
        return tool if isinstance(tool, BaseTool) else FunctionTool(tool)

    async def execute(self, *, agent: str, name: str, args: dict[str, Any], call_id: str,
                      state: dict[str, Any], invocation_id: str) -> dict[str, Any]:
        from google.adk.agents.invocation_context import InvocationContext
        from google.adk.tools.tool_context import ToolContext

        tool = self.callable_tool(agent, name)
        if tool is None:
            return {"status": "tool_error", "error": f"tool {agent}/{name} is not hosted"}
        session = await self.sessions.create_session(app_name=self.app_name, user_id=f"tools-{agent}",
                                                     state=dict(state))
        try:
            kwargs: dict[str, Any] = {"session_service": self.sessions, "invocation_id": invocation_id,
                                      "agent": self.agents[agent], "session": session}
            if self.artifacts is not None:
                kwargs["artifact_service"] = self.artifacts
            ic = InvocationContext(**kwargs)
            tc = ToolContext(ic, function_call_id=call_id or f"zt-{uuid.uuid4().hex[:12]}")
            t0 = time.perf_counter_ns()
            result = await tool.run_async(args=dict(args), tool_context=tc)
            actions = {"transfer_to_agent": tc.actions.transfer_to_agent, "escalate": bool(tc.actions.escalate),
                       "skip_summarization": bool(tc.actions.skip_summarization)}
            return {"status": "ok", "result": result, "state_delta": dict(tc.actions.state_delta or {}),
                    "actions": actions, "exec_ms": (time.perf_counter_ns() - t0) / 1e6}
        finally:
            await self.sessions.delete_session(app_name=self.app_name, user_id=f"tools-{agent}", session_id=session.id)


@dataclass
class Conversation:
    session_id: str
    events: list[dict[str, Any]] = field(default_factory=list)
    state: dict[str, Any] = field(default_factory=dict)
    updated: float = field(default_factory=time.time)


class ConversationStore:
    """Multi-turn sessions kept by the gateway (the agents' workloads are stateless)."""

    def __init__(self, *, agents: dict[str, BaseAgent], root: str, ttl_s: float = 3600, max_sessions: int = 10000):
        self.agents = agents
        self.root = root
        self.ttl = ttl_s
        self.max = max_sessions
        self._items: dict[str, Conversation] = {}

    def get(self, session_id: str) -> Conversation:
        now = time.time()
        for k in [k for k, v in self._items.items() if now - v.updated > self.ttl]:
            self._items.pop(k, None)
        conv = self._items.get(session_id)
        if conv is None:
            if len(self._items) >= self.max:
                oldest = min(self._items.values(), key=lambda c: c.updated)
                self._items.pop(oldest.session_id, None)
            conv = Conversation(session_id)
            self._items[session_id] = conv
        return conv

    def entry_agent(self, conv: Conversation) -> str:
        """ADK Runner._find_agent_to_run: the root, or the last agent that replied if it (and all its
        ancestors) can transfer across the tree; a pending function call's agent first."""
        pending_calls: dict[str, str] = {}
        for raw in conv.events:
            for part in ((raw.get("content") or {}).get("parts") or []):
                fc, fr = part.get("function_call"), part.get("function_response")
                if fc and fc.get("id"):
                    pending_calls[fc["id"]] = raw.get("author", "")
                if fr and fr.get("id"):
                    pending_calls.pop(fr["id"], None)
        for raw in reversed(conv.events):
            author = raw.get("author", "")
            if author in ("", "user"):
                continue
            actions = raw.get("actions") or {}
            if actions.get("agent_state") is not None or actions.get("end_of_agent"):
                continue
            if author == self.root:
                return self.root
            agent = self.agents.get(author)
            if agent is None:
                continue
            if resumable(agent):
                return author
        return self.root

    def append(self, conv: Conversation, events: list[dict[str, Any]]) -> None:
        for raw in events:
            delta = ((raw.get("actions") or {}).get("state_delta") or {})
            conv.state.update({k: v for k, v in delta.items() if not str(k).startswith("temp:")})
            conv.events.append(raw)
        conv.updated = time.time()
