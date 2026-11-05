"""Discovery of an ADK multi-agent system from its live object graph.

The application is imported (``module:attribute`` -- an ADK ``App``, a root agent, or a
factory ``module:function()``) and its agent tree is walked exactly as ADK walks it at run
time: ``sub_agents`` for transfers and workflow children, agent-valued attributes of
custom agents, ``tools`` (plain callables, FunctionTool, LongRunningFunctionTool,
AgentTool and ADK 2.x single-turn/task sub-agent tools, model-side built-in tools, custom
BaseTool subclasses, BaseToolset instances such as MCP or OpenAPI toolsets), and the
agents behind AgentTools (each runs as the root of its own runner).

The transitions that ADK can take are derived with ADK's own rules:

* transfer targets of an LlmAgent: its sub-agents (ADK 2.x: except single-turn / task
  mode sub-agents, which are tools), its parent unless ``disallow_transfer_to_parent``,
  its peers unless ``disallow_transfer_to_peers`` (only when the parent is an LlmAgent);
* entry points of a user message: the root agent, every LlmAgent of the main tree that
  ADK may resume a conversation with (it and all its ancestors are LlmAgents that allow
  transfer to their parent), and agents that own long-running tools (a function response
  sent by the client resumes the agent that issued the call);
* workflow agents (Sequential / Parallel / Loop / custom BaseAgent with children) run
  their children: each step of a workflow belongs to the nearest enclosing workflow.
"""
from __future__ import annotations

import asyncio
import importlib
import inspect
import sys
import threading
from pathlib import Path
from typing import Any, Iterable

from . import model as M
from .code_analysis import CodeEvidence, analyze_callable, analyze_tool_object

try:                                            # ADK is a hard dependency; keep import errors explicit
    from google.adk.agents import BaseAgent, LlmAgent, LoopAgent, ParallelAgent, SequentialAgent
    from google.adk.tools.agent_tool import AgentTool
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.base_toolset import BaseToolset
    from google.adk.tools.function_tool import FunctionTool
except ImportError as exc:                       # pragma: no cover
    raise ImportError("zt_adk needs google-adk (pip install google-adk)") from exc

try:
    from google.adk.tools.long_running_tool import LongRunningFunctionTool
except ImportError:                              # pragma: no cover
    LongRunningFunctionTool = ()                 # type: ignore[assignment,misc]

try:
    from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
except Exception:                                # optional extra (a2a)
    RemoteA2aAgent = ()                          # type: ignore[assignment,misc]

try:
    from google.adk.version import __version__ as ADK_VERSION
except ImportError:                              # pragma: no cover
    ADK_VERSION = "unknown"


class DiscoveryError(RuntimeError):
    pass


# ---------------------------------------------------------------------------------------
# loading the application
# ---------------------------------------------------------------------------------------
def load_object(ref: str, python_paths: Iterable[str | Path] = ()) -> Any:
    for p in python_paths:
        text = str(Path(p).resolve())
        if text not in sys.path:
            sys.path.insert(0, text)
    module_name, _, attr = ref.partition(":")
    if not module_name or not attr:
        raise DiscoveryError(f"invalid application reference {ref!r} (expected module:attribute)")
    call = attr.endswith("()")
    attr = attr[:-2] if call else attr
    obj: Any = importlib.import_module(module_name)
    for part in attr.split("."):
        obj = getattr(obj, part)
    return obj() if call else obj


def resolve_app(obj: Any) -> tuple[Any, str | None, list[Any]]:
    """(root agent, app name, app plugins) of an App, an agent, or a Runner."""
    if isinstance(obj, BaseAgent):
        return obj, None, []
    root = getattr(obj, "root_agent", None) or getattr(obj, "agent", None)
    if isinstance(root, BaseAgent):
        name = getattr(obj, "name", None) or getattr(obj, "app_name", None)
        plugins = list(getattr(obj, "plugins", None) or [])
        return root, name, plugins
    node = root if root is not None else (obj if _is_workflow_node(obj) else getattr(obj, "node", None))
    if node is not None and _is_workflow_node(node):
        raise DiscoveryError(
            f"the application's root is a graph workflow node ({type(node).__name__} "
            f"{getattr(node, 'name', '')!r}, google.adk.workflow): zt-adk protects agent trees "
            "(LlmAgent, SequentialAgent / ParallelAgent / LoopAgent, custom BaseAgent orchestration, "
            "AgentTool) and does not protect graph workflows yet")
    raise DiscoveryError(f"{type(obj).__name__} is neither an ADK App, an agent nor a Runner")


def _is_workflow_node(obj: Any) -> bool:
    try:
        from google.adk.workflow import BaseNode            # ADK >= 2.x
    except ImportError:
        return False
    return isinstance(obj, BaseNode) and not isinstance(obj, BaseAgent)


# ---------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------
def agent_kind(agent: Any) -> str:
    if isinstance(agent, LlmAgent):
        return M.LLM
    if isinstance(agent, SequentialAgent):
        return M.SEQUENTIAL
    if isinstance(agent, ParallelAgent):
        return M.PARALLEL
    if isinstance(agent, LoopAgent):
        return M.LOOP
    if RemoteA2aAgent and isinstance(agent, RemoteA2aAgent):
        return M.REMOTE
    return M.CUSTOM


def _qualname(obj: Any) -> str:
    t = obj if inspect.isclass(obj) else type(obj)
    return f"{t.__module__}.{t.__qualname__}"


def _func_ref(fn: Any) -> str | None:
    fn = inspect.unwrap(fn) if callable(fn) else fn
    mod, qn = getattr(fn, "__module__", None), getattr(fn, "__qualname__", None)
    return f"{mod}:{qn}" if mod and qn else None


def _source(obj: Any) -> tuple[str | None, int | None]:
    try:
        target = inspect.unwrap(obj) if callable(obj) and not inspect.isclass(obj) else obj
        return inspect.getsourcefile(target), inspect.getsourcelines(target)[1]
    except (TypeError, OSError):
        return None, None


def _schema_to_json(value: Any) -> Any:
    """genai Schema dump (TYPE enums upper-case) -> JSON-schema-like dict."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k == "type" and isinstance(v, str):
                out[k] = v.lower()
            else:
                out[k] = _schema_to_json(v)
        return out
    if isinstance(value, list):
        return [_schema_to_json(v) for v in value]
    return value


def tool_parameters(tool: Any) -> tuple[dict[str, Any], str]:
    try:
        decl = tool._get_declaration()
    except Exception as exc:                   # declaration needs optional deps / env
        return {}, f"declaration unavailable: {type(exc).__name__}"
    if decl is None:
        return {}, ""
    raw = decl.model_dump(mode="json", exclude_none=True)
    if raw.get("parameters_json_schema"):
        params = dict(raw["parameters_json_schema"])
    elif raw.get("parameters"):
        params = _schema_to_json(raw["parameters"])
    else:
        params = {"type": "object", "properties": {}}
    params.pop("title", None)
    for prop in (params.get("properties") or {}).values():
        if isinstance(prop, dict):
            prop.pop("title", None)
    return params, str(raw.get("description") or "")


def _run_coro_blocking(coro_factory: Any, timeout: float) -> Any:
    """Run an async call to completion whether or not an event loop is running here."""
    result: dict[str, Any] = {}

    def target() -> None:
        loop = asyncio.new_event_loop()
        try:
            result["value"] = loop.run_until_complete(asyncio.wait_for(coro_factory(), timeout))
        except BaseException as exc:          # noqa: BLE001 -- reported to the caller
            result["error"] = exc
        finally:
            loop.close()

    t = threading.Thread(target=target, name="zt-adk-toolset-resolve", daemon=True)
    t.start()
    t.join(timeout + 5)
    if "error" in result:
        raise result["error"]
    if "value" not in result:
        raise TimeoutError("toolset resolution timed out")
    return result["value"]


def is_builtin_tool(tool: Any) -> bool:
    """Model-side capability: a BaseTool that does not implement run_async (ADK adds it to
    the model request, the model provider executes it; no tool callback ever runs)."""
    return isinstance(tool, BaseTool) and type(tool).run_async is BaseTool.run_async


MODEL_CAPABILITY_FIELDS = ("google_search", "google_search_retrieval", "code_execution", "retrieval", "url_context",
                           "enterprise_web_search", "google_maps", "computer_use", "file_search")


def builtin_model_fields(tool: Any, agent: Any) -> list[str]:
    """The capability fields (types.Tool) a built-in tool adds to a model request, found by
    letting the tool process an empty request exactly as ADK does before every model call."""
    from google.adk.models.llm_request import LlmRequest

    model = getattr(agent, "model", None)
    names = [model if isinstance(model, str) and model else getattr(model, "model", None), "gemini-2.5-flash"]
    for name in [n for n in names if n]:
        req = LlmRequest(model=name)
        try:
            _run_coro_blocking(lambda: tool.process_llm_request(tool_context=None, llm_request=req), 10)
        except BaseException:              # noqa: BLE001 -- e.g. the model is not a Gemini model
            continue
        found = [f for t in (req.config.tools or []) for f in MODEL_CAPABILITY_FIELDS if getattr(t, f, None) is not None]
        if found:
            return sorted(set(found))
    return [str(tool.name)]


def child_agent_fields(agent: Any) -> dict[str, list[Any]]:
    """Agent-valued attributes of a custom agent (pydantic fields and private attributes)."""
    out: dict[str, list[Any]] = {}
    names = list(getattr(type(agent), "model_fields", {}) or {})
    for name in names:
        if name in {"sub_agents", "parent_agent"}:
            continue
        try:
            value = getattr(agent, name)
        except Exception:
            continue
        agents = _agents_in(value)
        if agents:
            out[name] = agents
    private = getattr(agent, "__pydantic_private__", None) or {}
    for name, value in private.items():
        agents = _agents_in(value)
        if agents:
            out[name] = agents
    return out


def _agents_in(value: Any) -> list[Any]:
    if isinstance(value, BaseAgent):
        return [value]
    if isinstance(value, (list, tuple)):
        return [v for v in value if isinstance(v, BaseAgent)]
    if isinstance(value, dict):
        return [v for v in value.values() if isinstance(v, BaseAgent)]
    return []


def transfer_targets(agent: Any) -> list[Any]:
    """ADK's own rule (flows/llm_flows/agent_transfer._get_transfer_targets)."""
    result = [s for s in agent.sub_agents if getattr(s, "mode", None) not in ("single_turn", "task")]
    parent = agent.parent_agent
    if not parent or not hasattr(parent, "disallow_transfer_to_parent"):
        return result
    if not agent.disallow_transfer_to_parent:
        result.append(parent)
    if not agent.disallow_transfer_to_peers:
        result.extend(p for p in parent.sub_agents
                      if p.name != agent.name and getattr(p, "mode", None) not in ("single_turn", "task"))
    return result


def resumable(agent: Any) -> bool:
    """ADK Runner._is_transferable_across_agent_tree."""
    a = agent
    while a is not None:
        if not hasattr(a, "disallow_transfer_to_parent") or a.disallow_transfer_to_parent:
            return False
        a = a.parent_agent
    return True


def uses_transfer_flow(agent: Any) -> bool:
    """LlmAgent gets the transfer_to_agent tool (AutoFlow) unless it has no sub-agents and
    disallows transfer to both parent and peers."""
    return not (agent.disallow_transfer_to_parent and agent.disallow_transfer_to_peers and not agent.sub_agents)


# ---------------------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------------------
class _Walker:
    def __init__(self, *, resolve_toolsets: bool, toolset_timeout: float,
                 declared_toolset_tools: dict[str, list[str]], toolset_resolution: dict[str, bool]) -> None:
        self.agents: dict[str, M.AgentInfo] = {}
        self.objects: dict[str, Any] = {}
        self.tools: dict[str, M.ToolInfo] = {}
        self.tool_objects: dict[str, Any] = {}
        self.toolsets: dict[str, dict[str, Any]] = {}
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.pending_agent_tools: list[tuple[Any, str]] = []
        self.resolve_toolsets = resolve_toolsets
        self.toolset_timeout = toolset_timeout
        self.declared_toolset_tools = declared_toolset_tools
        self.toolset_resolution = toolset_resolution

    def walk(self, agent: Any, parent: str | None, reached_via: str, tree_root: str) -> None:
        name = str(agent.name)
        if name in self.objects:
            if self.objects[name] is not agent:
                self.errors.append(f"two different agents are named {name!r}; agent names must be unique "
                                   "across the application (including agents behind AgentTools)")
            return
        self.objects[name] = agent
        kind = agent_kind(agent)
        src_file, src_line = _source(type(agent)) if kind == M.CUSTOM else (None, None)
        model_name = None
        if kind == M.LLM:
            m = getattr(agent, "model", None)
            model_name = m if isinstance(m, str) else (getattr(m, "model", None) or type(m).__name__ if m else None)
        info = M.AgentInfo(
            name=name, kind=kind, class_name=_qualname(agent), description=str(agent.description or ""),
            parent=parent, sub_agents=[s.name for s in agent.sub_agents],
            model=str(model_name) if model_name else None,
            output_key=getattr(agent, "output_key", None),
            disallow_transfer_to_parent=bool(getattr(agent, "disallow_transfer_to_parent", False)),
            disallow_transfer_to_peers=bool(getattr(agent, "disallow_transfer_to_peers", False)),
            mode=getattr(agent, "mode", None), reached_via=reached_via, tree_root=tree_root,
            source_file=src_file, source_line=src_line,
            callbacks=sorted(cb for cb in ("before_agent_callback", "after_agent_callback", "before_model_callback",
                                           "after_model_callback", "before_tool_callback", "after_tool_callback")
                             if getattr(agent, cb, None)),
        )
        self.agents[name] = info
        if kind == M.CUSTOM:
            for field_name, children in child_agent_fields(agent).items():
                info.child_fields[field_name] = [c.name for c in children]
        if kind == M.LLM:
            for tool in list(agent.tools or []):
                self._tool(agent, info, tool)
        for child in agent.sub_agents:
            self.walk(child, name, reached_via, tree_root)
        for children in info.child_fields.values():
            for child_name in children:
                if child_name not in info.sub_agents:
                    child = next(c for cs in child_agent_fields(agent).values() for c in cs if c.name == child_name)
                    self.warnings.append(f"custom agent {name} runs {child_name} through attribute without "
                                         "listing it in sub_agents; it is protected as an orchestrated child")
                    self.walk(child, name, reached_via, tree_root)

    # -- tools -----------------------------------------------------------------------
    def _add_tool(self, agent_info: M.AgentInfo, tool_obj: Any, info: M.ToolInfo) -> None:
        if info.key in self.tools:
            self.errors.append(f"agent {agent_info.name} has two tools named {info.name!r}")
            return
        self.tools[info.key] = info
        self.tool_objects[info.key] = tool_obj
        agent_info.tools.append(info.key)

    def _tool(self, agent: Any, agent_info: M.AgentInfo, tool: Any) -> None:
        a = agent_info.name
        if isinstance(tool, BaseToolset):
            self._toolset(agent, agent_info, tool)
            return
        if isinstance(tool, AgentTool):
            target = tool.agent
            params, desc = tool_parameters(tool)
            info = M.ToolInfo(key=f"{a}/{tool.name}", name=tool.name, agent=a, kind=M.AGENT_TOOL,
                              description=desc or str(target.description or ""), parameters=params,
                              implementation=_qualname(tool), target_agent=target.name,
                              include_plugins=bool(getattr(tool, "include_plugins", True)))
            if info.include_plugins is False:
                self.errors.append(f"AgentTool {tool.name} of agent {a} has include_plugins=False: the agent behind "
                                   "it would run without the Zero Trust plugin; remove include_plugins=False")
            self._add_tool(agent_info, tool, info)
            self.pending_agent_tools.append((target, a))
            return
        if isinstance(tool, FunctionTool):
            fn = tool.func
            params, desc = tool_parameters(tool)
            kind = M.LONG_RUNNING if (LongRunningFunctionTool and isinstance(tool, LongRunningFunctionTool)) \
                or getattr(tool, "is_long_running", False) else M.FUNCTION
            self._function(agent_info, tool, fn, tool.name, kind, params, desc)
            return
        if isinstance(tool, BaseTool):
            params, desc = tool_parameters(tool)
            if is_builtin_tool(tool):
                info = M.ToolInfo(key=f"{a}/{tool.name}", name=tool.name, agent=a, kind=M.BUILTIN,
                                  description=desc or str(getattr(tool, "description", "") or ""),
                                  parameters=params, implementation=_qualname(tool),
                                  analysis={"model_fields": builtin_model_fields(tool, agent)})
                self._add_tool(agent_info, tool, info)
                return
            ev = analyze_tool_object(tool)
            src_file, src_line = _source(type(tool))
            info = M.ToolInfo(key=f"{a}/{tool.name}", name=tool.name, agent=a, kind=M.CUSTOM_TOOL,
                              description=desc or str(getattr(tool, "description", "") or ""), parameters=params,
                              implementation=_qualname(tool), source_file=src_file, source_line=src_line,
                              is_long_running=bool(getattr(tool, "is_long_running", False)),
                              analysis=ev.as_dict())
            self._add_tool(agent_info, tool, info)
            return
        if callable(tool):
            ft = FunctionTool(tool)
            params, desc = tool_parameters(ft)
            self._function(agent_info, ft, tool, ft.name, M.FUNCTION, params, desc)
            return
        self.errors.append(f"agent {a}: unsupported tool object {type(tool).__name__}")

    def _function(self, agent_info: M.AgentInfo, tool_obj: Any, fn: Any, name: str, kind: str,
                  params: dict[str, Any], desc: str) -> None:
        ev: CodeEvidence = analyze_callable(fn)
        src_file, src_line = _source(fn)
        info = M.ToolInfo(key=f"{agent_info.name}/{name}", name=name, agent=agent_info.name, kind=kind,
                          description=desc or (inspect.getdoc(fn) or ""), parameters=params,
                          implementation=_func_ref(fn), source_file=src_file, source_line=src_line,
                          is_long_running=kind == M.LONG_RUNNING, analysis=ev.as_dict())
        self._add_tool(agent_info, tool_obj, info)

    def _toolset(self, agent: Any, agent_info: M.AgentInfo, toolset: Any) -> None:
        ts_name = f"{agent_info.name}/{type(toolset).__name__}"
        n = 2
        while ts_name in self.toolsets:
            ts_name = f"{agent_info.name}/{type(toolset).__name__}_{n}"
            n += 1
        short = ts_name.split("/", 1)[1]
        record: dict[str, Any] = {"agent": agent_info.name, "class": _qualname(toolset), "resolved": False,
                                  "tools": [], "error": None}
        self.toolsets[ts_name] = record
        resolve = self.toolset_resolution.get(short, self.toolset_resolution.get(ts_name, self.resolve_toolsets))
        tools: list[Any] = []
        if resolve:
            try:
                tools = list(_run_coro_blocking(lambda: toolset.get_tools(None), self.toolset_timeout))
                record["resolved"] = True
            except BaseException as exc:          # noqa: BLE001 -- recorded, decided below
                record["error"] = f"{type(exc).__name__}: {exc}"[:300]
            finally:
                try:
                    _run_coro_blocking(lambda: toolset.close(), self.toolset_timeout)
                except BaseException:             # noqa: BLE001
                    pass
        declared = self.declared_toolset_tools.get(short) or self.declared_toolset_tools.get(ts_name) or []
        for tool in tools:
            params, desc = tool_parameters(tool)
            info = M.ToolInfo(key=f"{agent_info.name}/{tool.name}", name=tool.name, agent=agent_info.name,
                              kind=M.TOOLSET_TOOL, description=desc, parameters=params,
                              implementation=_qualname(tool), toolset=ts_name)
            self._add_tool(agent_info, tool, info)
            record["tools"].append(tool.name)
        for name in declared:
            if name not in record["tools"]:
                info = M.ToolInfo(key=f"{agent_info.name}/{name}", name=name, agent=agent_info.name,
                                  kind=M.TOOLSET_TOOL, description="declared in zt_adk.yaml",
                                  implementation=_qualname(toolset), toolset=ts_name)
                self._add_tool(agent_info, None, info)
                record["tools"].append(name)
        if not record["tools"]:
            msg = (f"toolset {ts_name} could not be resolved ({record['error'] or 'resolution disabled'}) and "
                   "zt_adk.yaml declares no tools for it: every tool it offers at run time is denied")
            self.warnings.append(msg)


def discover(
    root_agent: Any,
    *,
    app_name: str | None = None,
    resolve_toolsets: bool = True,
    toolset_timeout: float = 20.0,
    declared_toolset_tools: dict[str, list[str]] | None = None,
    toolset_resolution: dict[str, bool] | None = None,
) -> tuple[M.SystemModel, dict[str, Any], dict[str, Any]]:
    """Return (model, agent objects by name, tool objects by tool key)."""
    if not isinstance(root_agent, BaseAgent):
        raise DiscoveryError("root_agent must be an ADK agent")
    w = _Walker(resolve_toolsets=resolve_toolsets, toolset_timeout=toolset_timeout,
                declared_toolset_tools=declared_toolset_tools or {}, toolset_resolution=toolset_resolution or {})
    w.walk(root_agent, None, "tree", root_agent.name)
    done: set[str] = set()
    while w.pending_agent_tools:
        target, _caller = w.pending_agent_tools.pop(0)
        if target.name in done:
            continue
        done.add(target.name)
        if target.name in w.objects and w.objects[target.name] is target:
            continue                              # also part of a tree already walked
        w.walk(target, None, "agent_tool", target.name)

    edges, workflows, workflow_of = _edges(root_agent, w)
    model = M.SystemModel(
        app_name=app_name or root_agent.name, root_agent=root_agent.name, adk_version=ADK_VERSION,
        agents=w.agents, tools=w.tools, edges=edges, workflows=workflows, workflow_of=workflow_of,
        toolsets=w.toolsets, warnings=w.warnings, errors=w.errors)
    return model, dict(w.objects), dict(w.tool_objects)


def _edges(root: Any, w: _Walker) -> tuple[list[M.Edge], dict[str, list[str]], dict[str, str | None]]:
    agents, objs = w.agents, w.objects
    workflows: dict[str, list[str]] = {}
    for name, info in agents.items():
        if info.kind in M.WORKFLOW_KINDS:
            children = list(info.sub_agents) + [c for cs in info.child_fields.values() for c in cs
                                                if c not in info.sub_agents]
            if children:
                workflows[name] = children
    workflow_of: dict[str, str | None] = {}
    for name, info in agents.items():
        p, wf = info.parent, None
        while p is not None:
            if p in workflows:
                wf = p
                break
            p = agents[p].parent
        workflow_of[name] = wf

    edges: list[M.Edge] = []
    seen: set[tuple[str, str, str]] = set()

    def add(kind: str, caller: str, target: str, workflow: str | None) -> None:
        key = (kind, caller, target)
        if key not in seen:
            seen.add(key)
            edges.append(M.Edge(kind, caller, target, workflow))

    # entry points
    add(M.EDGE_ENTRY, M.SystemModel.INGRESS, root.name, None)
    for name, info in agents.items():
        if info.reached_via != "tree":
            continue
        obj = objs[name]
        if info.kind == M.LLM and name != root.name and resumable(obj):
            add(M.EDGE_ENTRY, M.SystemModel.INGRESS, name, None)
        if any(w.tools[k].kind == M.LONG_RUNNING or w.tools[k].is_long_running for k in info.tools):
            add(M.EDGE_ENTRY, M.SystemModel.INGRESS, name, None)

    for name, info in agents.items():
        obj = objs[name]
        wf = workflow_of.get(name)
        if info.kind == M.LLM:
            if uses_transfer_flow(obj):
                for t in transfer_targets(obj):
                    add(M.EDGE_TRANSFER, name, t.name, wf)
            # ADK 2.x single-turn / task sub-agents are run as tools (their AgentTool edge
            # is added below); they still start as agents with this agent as the caller
            for s in obj.sub_agents:
                if getattr(s, "mode", None) in ("single_turn", "task"):
                    add(M.EDGE_AGENT_TOOL, name, s.name, wf)
        else:
            for child in workflows.get(name, []):
                add(M.EDGE_ORCHESTRATE, name, child, name)
        for key in info.tools:
            t = w.tools[key]
            if t.kind == M.AGENT_TOOL:
                add(M.EDGE_AGENT_TOOL, name, str(t.target_agent), wf)
            elif t.kind == M.BUILTIN:
                add(M.EDGE_BUILTIN, name, key, wf)
            else:
                add(M.EDGE_TOOL, name, key, wf)
        if info.reached_via == "tree" and info.kind in (M.LLM, M.CUSTOM, M.REMOTE):
            add(M.EDGE_OUTPUT, name, "output", wf)
        # a tool may set tool_context.actions.transfer_to_agent: that transfer is a route too
        for key in info.tools:
            if "transfer_to_agent" in (w.tools[key].analysis.get("control_flow") or []) and info.kind == M.LLM:
                for t in transfer_targets(obj):
                    add(M.EDGE_TRANSFER, name, t.name, wf)
    return edges, workflows, workflow_of


def discover_app(ref: str, *, python_paths: Iterable[str | Path] = (), app_name: str | None = None,
                 **kwargs: Any) -> tuple[M.SystemModel, Any, dict[str, Any], dict[str, Any]]:
    obj = load_object(ref, python_paths)
    root, name, _plugins = resolve_app(obj)
    model, agents, tools = discover(root, app_name=app_name or name, **kwargs)
    return model, root, agents, tools
