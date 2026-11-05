"""PlaybackLlm: a deterministic stand-in for the model, driven by a script (tests and demos).

The Backplane protects whatever the model decides; to test that protection reproducibly (and
without an API key) the model's decisions are replayed from a YAML script. The script lists,
per agent, rules evaluated in order on every model call of that agent::

    agents:
      service_desk:
        - when: {user: "(?i)password"}            # regex on the latest user text
          transfer: account_agent                  # -> transfer_to_agent(agent_name=...)
        - text: "I can help with accounts and incidents."
      account_agent:
        - when: {after: reset_password}            # the last content is this tool's result
          text: "Done: {result[status]}"
        - when: {user: "reset .*password for (?P<username>\\\\w+)"}
          call: reset_password                     # function call; args are templates
          args: {username: "{username}"}

``when.instruction`` matches the agent's system instruction (ADK has already filled in
``{state}`` placeholders, so a rule can pick up values from session state). Rules without
``when`` never fire right after a tool result (a model that called a tool
gets one turn to react, then the turn ends). Templates may use the regex's named groups and
``result`` (the last tool result). ``calls:`` gives several function calls in one response.

Never used by a production deployment: ``model_override`` in ``zt_adk.yaml`` (or
``install_playback``) must name it explicitly.
"""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any, AsyncGenerator

import yaml
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def _render(value: Any, values: dict[str, Any]) -> Any:
    if isinstance(value, str):
        try:
            return value.format_map(_SafeDict(values))
        except (KeyError, IndexError, ValueError, AttributeError):
            return value
    if isinstance(value, dict):
        return {k: _render(v, values) for k, v in value.items()}
    if isinstance(value, list):
        return [_render(v, values) for v in value]
    return value


def load_script(path: str | Path) -> dict[str, list[dict[str, Any]]]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    agents = raw.get("agents") or {}
    if not isinstance(agents, dict):
        raise ValueError(f"{path}: 'agents' must be a mapping")
    return {str(k): list(v or []) for k, v in agents.items()}


def _instruction_text(req: LlmRequest) -> str:
    si = getattr(req.config, "system_instruction", None) if req.config is not None else None
    if si is None:
        return ""
    if isinstance(si, str):
        return si
    parts = getattr(si, "parts", None)
    if parts is not None:
        return "\n".join(str(p.text) for p in parts if getattr(p, "text", None))
    if isinstance(si, list):
        return "\n".join(str(getattr(x, "text", x)) for x in si)
    return str(si)


class PlaybackLlm(BaseLlm):
    agent_name: str
    rules: list[dict[str, Any]]
    chunk_size: int = 0                 # > 0: stream text in partial chunks when ADK asks for streaming

    @classmethod
    def supported_models(cls) -> list[str]:
        return [r"playback/.*"]

    def _situation(self, req: LlmRequest) -> tuple[str | None, Any, str]:
        contents = list(req.contents or [])
        after, result = None, None
        if contents:
            for part in contents[-1].parts or []:
                fr = getattr(part, "function_response", None)
                if fr is not None:
                    after, result = fr.name, fr.response
        # The user's message of this turn: the latest user-role text that is not one of the
        # "For context: ..." notes ADK inserts for other agents' turns after a transfer.
        user_texts = []
        for c in reversed(contents):
            if c.role == "user":
                texts = [str(p.text) for p in (c.parts or []) if getattr(p, "text", None)]
                if texts and not texts[0].lstrip().startswith("For context:"):
                    user_texts.append("\n".join(texts))
                    break
        return after, result, user_texts

    def _choose(self, req: LlmRequest) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        after, result, user_texts = self._situation(req)
        result_value = result
        if isinstance(result, dict) and set(result) == {"result"} and isinstance(result["result"], str):
            try:
                result_value = json.loads(result["result"])
            except ValueError:
                pass
        for rule in self.rules:
            when = rule.get("when") or {}
            values: dict[str, Any] = {"result": result_value if result_value is not None else {}}
            if after is not None:
                if when.get("after") != after:
                    continue
                if "result_status" in when and str((result_value or {}).get("status")) != str(when["result_status"]):
                    continue
            elif "after" in when:
                continue
            if "user" in when:
                m = next((x for x in (re.search(str(when["user"]), t) for t in user_texts) if x), None)
                if not m:
                    continue
                values.update(m.groupdict())
            if "instruction" in when:
                m = re.search(str(when["instruction"]), _instruction_text(req))
                if not m:
                    continue
                values.update(m.groupdict())
            return rule, values
        return None, {"result": result_value}

    async def generate_content_async(self, llm_request: LlmRequest, stream: bool = False
                                     ) -> AsyncGenerator[LlmResponse, None]:
        rule, values = self._choose(llm_request)
        parts: list[types.Part] = []
        if rule is None:
            parts.append(types.Part(text="Done."))
        else:
            calls = list(rule.get("calls") or [])
            if "call" in rule:
                calls.insert(0, {"name": rule["call"], "args": rule.get("args") or {}})
            if "transfer" in rule:
                calls.insert(0, {"name": "transfer_to_agent", "args": {"agent_name": rule["transfer"]}})
            for c in calls:
                parts.append(types.Part(function_call=types.FunctionCall(
                    id=f"pb-{uuid.uuid4().hex[:12]}", name=str(c["name"]), args=_render(c.get("args") or {}, values))))
            if "text" in rule:
                parts.insert(0, types.Part(text=str(_render(rule["text"], values))))
        text_only = all(p.text for p in parts)
        if stream and self.chunk_size and text_only:
            full = "".join(p.text for p in parts)
            for i in range(0, len(full), self.chunk_size):
                yield LlmResponse(content=types.Content(role="model", parts=[types.Part(text=full[i:i + self.chunk_size])]),
                                  partial=True)
        yield LlmResponse(content=types.Content(role="model", parts=parts), partial=False, turn_complete=True)


def install_playback(root_agent: Any, script: str | Path | dict[str, list[dict[str, Any]]], *,
                     chunk_size: int = 0) -> int:
    """Replace the model of every LlmAgent reachable from ``root_agent`` (including agents
    behind AgentTools, and in a graph workflow the agent nodes it runs and the agents its
    function nodes start). Returns the number of agents changed."""
    from google.adk.agents import LlmAgent
    from google.adk.tools.agent_tool import AgentTool

    from ..code_analysis import dynamic_run_nodes
    from ..discovery import function_node_callable

    rules = script if isinstance(script, dict) else load_script(script)
    seen: set[int] = set()
    count = 0
    stack = [root_agent]
    while stack:
        agent = stack.pop()
        if id(agent) in seen:
            continue
        seen.add(id(agent))
        graph = getattr(agent, "graph", None) if not hasattr(agent, "sub_agents") else None
        if graph is not None:                     # graph workflow: the node objects it runs
            for node in graph.nodes:
                inner = getattr(node, "_node", None) or node
                if hasattr(inner, "sub_agents") or getattr(inner, "graph", None) is not None:
                    stack.append(inner)
                fn = function_node_callable(inner)
                if fn is not None:
                    stack.extend(dynamic_run_nodes(fn)[0])
            continue
        if not hasattr(agent, "sub_agents"):
            continue
        if isinstance(agent, LlmAgent):
            # keep the configured model name: ADK's request processors (built-in tools) check it
            original = agent.model if isinstance(agent.model, str) and agent.model else \
                str(getattr(agent.model, "model", "") or "gemini-2.5-flash")
            agent.model = PlaybackLlm(model=original, agent_name=agent.name,
                                      rules=list(rules.get(agent.name, [])), chunk_size=chunk_size)
            count += 1
            for t in agent.tools or []:
                if isinstance(t, AgentTool):
                    stack.append(t.agent)
        stack.extend(agent.sub_agents or [])
    return count
