"""System model of an ADK multi-agent system: what the Backplane protects.

Produced by ``discovery`` from the live ADK object graph (authoritative) and compared with
the static source scan. Everything downstream -- unified manifest, PEP plan, generated PSL
policies, the runtime plugin's lookups and the distributed runtime's workloads -- is derived
from this model, so it is serialised into the protection bundle (``system_model.json``) and
its structural fingerprint is checked again when the protected application starts.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

# agent kinds
LLM, SEQUENTIAL, PARALLEL, LOOP, CUSTOM, REMOTE = "llm", "sequential", "parallel", "loop", "custom", "remote"
GRAPH = "graph"                        # ADK 2.x graph workflow (google.adk.workflow.Workflow)
WORKFLOW_KINDS = (SEQUENTIAL, PARALLEL, LOOP, CUSTOM, GRAPH)
# graph node kinds (AgentInfo.graph["nodes"][i]["kind"])
NODE_AGENT, NODE_WORKFLOW, NODE_TOOL, NODE_FUNCTION, NODE_JOIN, NODE_CUSTOM = (
    "agent", "workflow", "tool", "function", "join", "custom_node")
OBSERVABLE_NODE_KINDS = (NODE_AGENT, NODE_WORKFLOW, NODE_TOOL)    # the PEP sees them start

# tool kinds
FUNCTION = "function"                  # FunctionTool / plain callable, runs in the agent's process
LONG_RUNNING = "long_running_function"  # LongRunningFunctionTool (result may arrive later as user input)
AGENT_TOOL = "agent_tool"              # AgentTool (and ADK 2.x single-turn / task sub-agent tools)
BUILTIN = "builtin"                    # model-side capability (google_search, code execution, ...)
TOOLSET_TOOL = "toolset_tool"          # tool resolved from a BaseToolset (MCP, OpenAPI, ...)
CUSTOM_TOOL = "custom_tool"            # BaseTool subclass with its own run_async

# edge kinds
EDGE_TRANSFER = "transfer"             # LLM-driven transfer_to_agent
EDGE_ORCHESTRATE = "orchestrate"       # workflow / custom agent runs a child
EDGE_AGENT_TOOL = "agent_tool"         # AgentTool call
EDGE_ENTRY = "entry"                   # a user message starts (or resumes) this agent
EDGE_TOOL = "tool"                     # agent calls a tool
EDGE_BUILTIN = "builtin"               # agent's model request uses a built-in capability
EDGE_OUTPUT = "output"                 # agent emits user-visible content


# code-analysis evidence classification is derived from (code_analysis.CodeEvidence.as_dict)
EVIDENCE_KEYS = ("analyzed", "http_methods", "sql", "db_write", "db_delete", "db_read", "file_write", "file_delete",
                 "file_read", "process_exec", "messaging", "state_write", "memory_write", "control_flow",
                 "unresolved_calls", "opaque_calls", "indirect", "model_fields")


def evidence_signature(analysis: dict[str, Any] | None) -> dict[str, Any]:
    return {k: analysis[k] for k in EVIDENCE_KEYS if analysis and k in analysis}


def graph_structure(graph: dict[str, Any] | None) -> dict[str, Any] | None:
    """What protection depends on in a graph workflow: its nodes (kind, implementation, code
    evidence of function nodes) and edges with their routes."""
    if not graph:
        return None
    return {"nodes": [{k: (evidence_signature(v) if k == "analysis" else v) for k, v in sorted(n.items())}
                      for n in graph.get("nodes", [])],
            "edges": [list(e) for e in graph.get("edges", [])],
            "dynamic": {k: sorted((d["name"], d["kind"]) for d in v)
                        for k, v in sorted((graph.get("dynamic") or {}).items())}}


@dataclass
class ToolInfo:
    key: str                           # "<agent>/<tool name>": tool names are unique per agent in ADK
    name: str
    agent: str
    kind: str
    description: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)     # JSON schema of the declaration
    implementation: str | None = None  # "module:qualname" of the function / class
    source_file: str | None = None
    source_line: int | None = None
    target_agent: str | None = None    # AgentTool
    include_plugins: bool | None = None
    toolset: str | None = None
    is_long_running: bool = False
    analysis: dict[str, Any] = field(default_factory=dict)       # code-analysis evidence


@dataclass
class AgentInfo:
    name: str
    kind: str
    class_name: str
    description: str = ""
    parent: str | None = None
    sub_agents: list[str] = field(default_factory=list)
    child_fields: dict[str, list[str]] = field(default_factory=dict)  # custom agents: attribute -> agents
    tools: list[str] = field(default_factory=list)                    # tool keys
    model: str | None = None
    output_key: str | None = None
    disallow_transfer_to_parent: bool = False
    disallow_transfer_to_peers: bool = False
    mode: str | None = None            # ADK 2.x: chat | task | single_turn
    reached_via: str = "tree"          # tree | agent_tool
    tree_root: str = ""                # root of the agent tree this agent belongs to
    source_file: str | None = None
    source_line: int | None = None
    callbacks: list[str] = field(default_factory=list)
    # graph workflows: {"nodes": [{name, kind, implementation, tool?, dynamic?, analysis?}],
    #                   "edges": [[from, to, route]], "dynamic": {function node: [started nodes]}}
    graph: dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    kind: str
    caller: str                        # agent name, or "ingress"
    target: str                        # agent name or tool key
    workflow: str | None = None        # workflow agent whose run contains this step


@dataclass
class SystemModel:
    app_name: str
    root_agent: str
    adk_version: str
    agents: dict[str, AgentInfo]
    tools: dict[str, ToolInfo]
    edges: list[Edge]
    workflows: dict[str, list[str]]    # workflow agent -> ordered direct children
    workflow_of: dict[str, str | None]  # agent -> nearest enclosing workflow agent
    toolsets: dict[str, dict[str, Any]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    INGRESS = "ingress"

    def to_dict(self) -> dict[str, Any]:
        return {
            "app_name": self.app_name,
            "root_agent": self.root_agent,
            "adk_version": self.adk_version,
            "agents": {k: asdict(v) for k, v in sorted(self.agents.items())},
            "tools": {k: asdict(v) for k, v in sorted(self.tools.items())},
            "edges": [asdict(e) for e in self.edges],
            "workflows": self.workflows,
            "workflow_of": self.workflow_of,
            "toolsets": self.toolsets,
            "warnings": self.warnings,
            "errors": self.errors,
            "fingerprint": self.fingerprint(),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SystemModel":
        return cls(
            app_name=raw["app_name"],
            root_agent=raw["root_agent"],
            adk_version=raw.get("adk_version", ""),
            agents={k: AgentInfo(**v) for k, v in raw["agents"].items()},
            tools={k: ToolInfo(**v) for k, v in raw["tools"].items()},
            edges=[Edge(**e) for e in raw["edges"]],
            workflows={k: list(v) for k, v in raw["workflows"].items()},
            workflow_of=dict(raw["workflow_of"]),
            toolsets=dict(raw.get("toolsets", {})),
            warnings=list(raw.get("warnings", [])),
            errors=list(raw.get("errors", [])),
        )

    # -- structure ---------------------------------------------------------------------
    def structure(self) -> dict[str, Any]:
        """What protection depends on: agents, their kinds and relations, tools with their
        implementation, parameter schema and the code evidence their classification is
        derived from, edges. Descriptions and instructions are excluded (changing a prompt
        does not change who may call what); so are code changes that leave the evidence as it
        is. A tool whose code now does something else (a SELECT that became a DELETE, a new
        HTTP POST, an SDK call) changes the structure: its classification would differ.
        Tools a toolset offers are not part of the structure (only the toolset itself is):
        which of them may be called is fixed by the bundle, and any other tool is denied at
        run time."""
        dynamic = {k for k, t in self.tools.items() if t.kind == TOOLSET_TOOL}
        return {
            "root": self.root_agent,
            "agents": {
                n: {"kind": a.kind, "class": a.class_name, "parent": a.parent, "sub_agents": a.sub_agents,
                    "child_fields": a.child_fields, "tools": [k for k in a.tools if k not in dynamic],
                    "mode": a.mode, "disallow_transfer_to_parent": a.disallow_transfer_to_parent,
                    "disallow_transfer_to_peers": a.disallow_transfer_to_peers, "reached_via": a.reached_via,
                    "graph": graph_structure(a.graph)}
                for n, a in sorted(self.agents.items())
            },
            "tools": {
                k: {"name": t.name, "kind": t.kind, "implementation": t.implementation,
                    "parameters": t.parameters, "target_agent": t.target_agent,
                    "include_plugins": t.include_plugins, "evidence": evidence_signature(t.analysis)}
                for k, t in sorted(self.tools.items()) if k not in dynamic
            },
            "toolsets": {k: v.get("class") for k, v in sorted(self.toolsets.items())},
            "edges": sorted([e.kind, e.caller, e.target, e.workflow or ""] for e in self.edges
                            if e.target not in dynamic),
        }

    def fingerprint(self) -> str:
        raw = json.dumps(self.structure(), sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    # -- lookups -----------------------------------------------------------------------
    def tool(self, agent: str, name: str) -> ToolInfo | None:
        return self.tools.get(f"{agent}/{name}")

    def edges_of(self, kind: str) -> list[Edge]:
        return [e for e in self.edges if e.kind == kind]
