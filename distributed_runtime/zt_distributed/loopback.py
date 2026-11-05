"""In-process loopback of the distributed hosting (no network, no identity, no PEP).

Every agent gets its own copy of the application's agent tree and its own HostedAgentRunner;
remote agent calls and tool calls are wired directly to the target runner and to a ToolHost.
Used by the unit tests to prove that the hosting layer reproduces ADK's in-process behaviour
(same tool calls, same results, same final answers) before the network and the PEP are added.
"""
from __future__ import annotations

import uuid
from typing import Any, Callable

from google.adk.events import Event
from google.genai import types

from zt_adk.discovery import discover

from . import remote
from .remote import dump_event
from .workload_runtime import ConversationStore, HostedAgentRunner, ToolHost


class Loopback:
    def __init__(self, build_root: Callable[[], Any], *, app_name: str = "app",
                 prepare: Callable[[Any], None] | None = None) -> None:
        def tree() -> tuple[Any, dict[str, Any], dict[str, Any]]:
            root = build_root()
            if prepare is not None:
                prepare(root)
            model, agents, tools = discover(root, resolve_toolsets=False)
            return root, agents, tools

        root, agents, tools = tree()
        self.model = discover(root, resolve_toolsets=False)[0]
        self.runners: dict[str, HostedAgentRunner] = {}
        for name in agents:
            _r, own, _t = tree()
            self.runners[name] = HostedAgentRunner(agents=own, agent_name=name, app_name=app_name)
        _r, host_agents, host_tools = tree()
        self.tool_host = ToolHost(agents=host_agents, tools=host_tools, app_name=app_name)
        self.conversations = ConversationStore(agents=agents, root=root.name)
        self.agent_calls: list[tuple[str, str]] = []
        self.tool_calls: list[tuple[str, str]] = []
        remote.HOOKS.invoke_agent = self._invoke
        remote.HOOKS.call_tool = self._tool

    async def _invoke(self, target: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.agent_calls.append((payload.get("mode", ""), target))
        return await self.runners[target].run(payload)

    async def _tool(self, agent: str, name: str, args: dict[str, Any], call_id: str,
                    state: dict[str, Any]) -> dict[str, Any]:
        self.tool_calls.append((agent, name))
        return await self.tool_host.execute(agent=agent, name=name, args=args, call_id=call_id, state=state,
                                            invocation_id=f"tool-{uuid.uuid4().hex[:8]}")

    async def say(self, session_id: str, text: str) -> list[Event]:
        conv = self.conversations.get(session_id)
        entry = self.conversations.entry_agent(conv)
        user = Event(author="user", invocation_id=f"in-{uuid.uuid4().hex[:8]}",
                     content=types.Content(role="user", parts=[types.Part(text=text)]))
        payload = {"mode": "run", "history": conv.events + [dump_event(user)], "state": dict(conv.state),
                   "user_content": user.content.model_dump(mode="json", exclude_none=True)}
        resp = await self.runners[entry].run(payload)
        if resp.get("status") != "ok":
            raise RuntimeError(f"entry agent {entry} failed: {resp}")
        events = [dump_event(user)] + list(resp["events"])
        self.conversations.append(conv, events)
        return [Event.model_validate(e) for e in resp["events"]]
