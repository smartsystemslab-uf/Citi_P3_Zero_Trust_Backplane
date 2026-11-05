"""System model -> unified Zero Trust manifest (packages/zt-interface, ztb/v1alpha1).

No baseline is required: every subject, resource, interface, workflow and interaction comes
from the discovered system model and its classification. Canonical ids are derived from
the names in the application:

  agent.<domain>.<agent>                 an agent (subject)
  service.external.ingress               the front end that delivers user messages
  resource.<domain>.agent_<agent>        an agent as the target of a route / AgentTool call
  resource.<domain>.tool_<agent>__<tool> one agent's tool (tools are protected per agent)
  resource.<domain>.builtin_<agent>__<t> a model-side built-in capability of one agent
  resource.external.mas_input / mas_output   the user-facing input and output channels
  workflow.<domain>.<agent>              a workflow agent's run
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from . import model as M
from .classify import OperationClass, classify_tool
from .profile import Profile

INPUT_RUNTIME, OUTPUT_RUNTIME, INGRESS_RUNTIME = "mas_input_channel", "mas_output_channel", "ingress"
INGRESS_SUBJECT = "service.external.ingress"
INPUT_RESOURCE, OUTPUT_RESOURCE = "resource.external.mas_input", "resource.external.mas_output"
RISK_OF = {"low": "low", "medium": "medium", "high": "high", "critical": "critical"}


def slug(text: str, maxlen: int = 48) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(text)).lower()).strip("_")
    if not s or not s[0].isalpha():
        s = "x_" + s
    return s[:maxlen].rstrip("_") or "x"


def assign_domains(model: M.SystemModel, profile: Profile) -> dict[str, str]:
    cfg = profile.domains
    agents = model.agents
    out: dict[str, str] = {}

    def explicit(name: str) -> str | None:
        d = cfg.agents.get(name)
        return d if d else None

    def resolve(name: str) -> str:
        if name in out:
            return out[name]
        info = agents[name]
        dom = explicit(name)
        if dom is None:
            if cfg.mode == "single":
                dom = cfg.default
            elif info.parent is None:
                if info.reached_via == "agent_tool":
                    callers = [e.caller for e in model.edges if e.kind == M.EDGE_AGENT_TOOL and e.target == name]
                    dom = resolve(callers[0]) if callers else cfg.default
                else:
                    dom = cfg.default
            elif cfg.mode == "subtree" and agents[info.parent].parent is None \
                    and agents[info.parent].reached_via == "tree":
                dom = slug(name, 40)          # direct child of the root: its own domain
            else:
                dom = resolve(info.parent)
        out[name] = dom
        return dom

    for name in agents:
        resolve(name)
    return out


@dataclass
class IdMaps:
    environment: str
    domains: dict[str, str] = field(default_factory=dict)
    subject: dict[str, str] = field(default_factory=dict)            # agent -> subject id
    agent_resource: dict[str, str] = field(default_factory=dict)     # agent -> resource id
    agent_runtime: dict[str, str] = field(default_factory=dict)      # agent -> resource runtime id
    tool_resource: dict[str, str] = field(default_factory=dict)      # tool key -> resource id
    workflow: dict[str, str] = field(default_factory=dict)           # workflow agent -> workflow id
    interaction: dict[str, str] = field(default_factory=dict)        # "kind|caller|target" -> edge id
    operations: dict[str, dict[str, Any]] = field(default_factory=dict)   # tool key -> OperationClass dict

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "IdMaps":
        return cls(**raw)


def _meta(display: str, description: str, reference: str, now: str, *, tags: list[str] | None = None,
          status: str = "confirmed", notes: str = "") -> dict[str, Any]:
    src: dict[str, Any] = {"provided_by": "zt_adk.discovery", "reference": reference, "verified_at": now}
    if notes:
        src["notes"] = notes[:1000]
    return {"display_name": display[:200], "description": (description or display)[:2000], "status": status,
            "source": src, "owner": None, "tags": tags or [], "extensions": {}}


def _binding(env: str, runtime_id: str, *, function_name: str | None = None,
             service_name: str | None = None) -> dict[str, Any]:
    return {env: {"runtime_id": runtime_id, "endpoint": None, "function_name": function_name,
                  "service_name": service_name, "namespace": None, "secret_refs": [], "extensions": {}}}


def _action(name: str, side_effect: bool, criticality: str, approval: bool, idempotent: bool) -> dict[str, Any]:
    return {"name": name, "side_effect": side_effect, "criticality": criticality,
            "requires_human_approval": approval, "idempotent": idempotent, "parameter_schema_ref": None}


def build_manifest(model: M.SystemModel, profile: Profile) -> tuple[dict[str, Any], IdMaps]:
    env = profile.environment
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    domains = assign_domains(model, profile)
    ids = IdMaps(environment=env, domains=dict(domains))
    used: set[str] = set()

    def unique(candidate: str) -> str:
        base, n = candidate, 2
        while candidate in used:
            candidate = f"{base}_{n}"
            n += 1
        used.add(candidate)
        return candidate

    subjects: list[dict[str, Any]] = []
    resources: list[dict[str, Any]] = []
    interfaces: list[dict[str, Any]] = []
    workflows: list[dict[str, Any]] = []
    interactions: list[dict[str, Any]] = []

    # -- subjects ------------------------------------------------------------------------
    subjects.append({
        "id": unique(INGRESS_SUBJECT), "type": "service", "roles": ["ingress"], "domain": "external",
        "enabled": True,
        "metadata": _meta("Ingress", "Front end that delivers user messages to the agents.", "zt_adk:ingress", now,
                          tags=["ingress"]),
        "bindings": _binding(env, INGRESS_RUNTIME, service_name="ingress"),
        "attributes": {"zt_adk_role": "ingress"},
    })
    for name, info in sorted(model.agents.items()):
        dom = domains[name]
        sid = unique(f"agent.{dom}.{slug(name)}")
        ids.subject[name] = sid
        subjects.append({
            "id": sid, "type": "agent", "roles": sorted({f"adk_{info.kind}", "adk_agent"}), "domain": dom,
            "enabled": True,
            "metadata": _meta(name, info.description, f"agent:{name} ({info.class_name})", now, tags=["adk_agent"]),
            "bindings": _binding(env, name),
            "attributes": {"adk_kind": info.kind, "adk_class": info.class_name, "reached_via": info.reached_via,
                           "workflow": model.workflow_of.get(name)},
        })
        rid = unique(f"resource.{dom}.agent_{slug(name)}")
        ids.agent_resource[name] = rid
        ids.agent_runtime[name] = f"agent:{name}"
        resources.append({
            "id": rid, "type": "other", "domain": dom, "classification": "internal",
            "actions": [_action("invoke", False, "medium", False, True)],
            "metadata": _meta(f"{name} (as a target)", f"Starting agent {name}.", f"agent:{name}", now,
                              tags=["adk_agent_target"]),
            "bindings": _binding(env, f"agent:{name}"),
            "attributes": {"resource_kind": "agent", "scanner_target_type": "subject", "agent": name},
        })

    # -- I/O channels ----------------------------------------------------------------------
    resources.append({
        "id": unique(INPUT_RESOURCE), "type": "other", "domain": "external", "classification": "internal",
        "actions": [_action("invoke", False, "medium", False, True)],
        "metadata": _meta("Input channel", "User messages entering the agents.", "zt_adk:input", now),
        "bindings": _binding(env, INPUT_RUNTIME), "attributes": {"zt_adk_boundary": "input"},
    })
    resources.append({
        "id": unique(OUTPUT_RESOURCE), "type": "other", "domain": "external", "classification": "internal",
        "actions": [_action("emit", False, "medium", False, True)],
        "metadata": _meta("Output channel", "Agent content shown to the user.", "zt_adk:output", now),
        "bindings": _binding(env, OUTPUT_RUNTIME), "attributes": {"zt_adk_boundary": "output"},
    })

    # -- tools -----------------------------------------------------------------------------
    for key, tool in sorted(model.tools.items()):
        if tool.kind == M.AGENT_TOOL:
            continue                                   # the target agent's resource is used
        op: OperationClass = classify_tool(tool, profile)
        ids.operations[key] = op.as_dict()
        owner_dom = domains[tool.agent]
        prefix = "builtin" if tool.kind == M.BUILTIN else "tool"
        rid = unique(f"resource.{owner_dom}.{prefix}_{slug(tool.agent, 30)}__{slug(tool.name, 40)}")
        ids.tool_resource[key] = rid
        rtype = "model" if tool.kind == M.BUILTIN else "tool"
        resources.append({
            "id": rid, "type": rtype, "domain": owner_dom, "classification": op.classification,
            "actions": [_action(op.action, op.side_effect, op.criticality, op.requires_approval, op.idempotent)],
            "metadata": _meta(f"{tool.agent}/{tool.name}", tool.description or tool.name,
                              f"{tool.source_file or tool.implementation}:{tool.source_line or 0}", now,
                              tags=[f"adk_{tool.kind}"], notes="; ".join(op.evidence)),
            "bindings": _binding(env, key, function_name=tool.implementation),
            "attributes": {"tool_kind": tool.kind, "agent": tool.agent, "tool": tool.name,
                           "implementation": tool.implementation, "toolset": tool.toolset,
                           "parameters": tool.parameters, "classification_evidence": op.evidence,
                           "declared": op.declared, "secondary_approval": op.secondary_approval,
                           "allowed_roles": op.allowed_roles, "mask_fields": op.mask_fields},
        })
        itype = {M.TOOLSET_TOOL: "mcp" if "mcp" in str(tool.toolset or "").lower() else "custom",
                 M.BUILTIN: "custom"}.get(tool.kind, "python_function")
        if tool.kind == M.TOOLSET_TOOL and "openapi" in str(tool.toolset or "").lower():
            itype = "http"
        iid = unique(f"interface.{owner_dom}.{slug(tool.agent, 30)}__{slug(tool.name, 40)}")
        interfaces.append({
            "id": iid, "type": itype,
            "metadata": _meta(f"{tool.name} interface", f"Call interface of {key}.", key, now),
            "bindings": _binding(env, key, function_name=tool.implementation),
            "authentication": {"method": "spiffe" if itype in ("mcp", "http") else "none", "issuer": None,
                               "audience": None, "subject_claim": None, "credential_ref": None, "jwks_uri": None,
                               "extensions": {}},
            "request_schema_ref": None, "response_schema_ref": None,
        })
        ids.interaction[f"interface|{key}"] = iid

    # -- workflows ---------------------------------------------------------------------------
    for wf_agent, children in sorted(model.workflows.items()):
        dom = domains[wf_agent]
        wid = unique(f"workflow.{dom}.{slug(wf_agent)}")
        ids.workflow[wf_agent] = wid
        kind = model.agents[wf_agent].kind
        steps = []
        for i, child in enumerate(children):
            nxt: list[str] = []
            if kind == M.SEQUENTIAL and i + 1 < len(children):
                nxt = [f"step_{i + 2}"]
            elif kind == M.LOOP:
                nxt = [f"step_{i + 2}" if i + 1 < len(children) else "step_1"]
            steps.append({"id": f"step_{i + 1}", "subject_id": ids.subject[wf_agent], "action": "invoke",
                          "resource_id": ids.agent_resource[child], "interface_id": None, "next": nxt,
                          "conditions": {}})
        workflows.append({
            "id": wid, "domain": dom,
            "metadata": _meta(f"{wf_agent} ({kind})", model.agents[wf_agent].description or wf_agent,
                              f"agent:{wf_agent}", now, tags=[f"adk_{kind}"]),
            "steps": steps, "entry_step": "step_1" if steps else None,
            "attributes": {"adk_kind": kind, "children": children},
        })

    # -- interactions ------------------------------------------------------------------------
    def edge_id(kind: str, caller: str, target: str) -> str:
        return unique(f"edge.{kind}.{slug(caller, 40)}__{slug(target, 60)}")

    def pep(ptype: str, placement: str, critical: bool) -> dict[str, Any]:
        return {"required": True, "type": ptype, "mode": profile.mode, "placement_id": placement,
                "fail_mode": "closed"}

    def wf(e: M.Edge) -> str | None:
        return ids.workflow.get(e.workflow) if e.workflow else None

    interactions.append({
        "id": edge_id("input", "ingress", "mas_input"), "caller_id": INGRESS_SUBJECT, "target_id": INPUT_RESOURCE,
        "resource_id": INPUT_RESOURCE, "action": "invoke", "workflow_id": None, "interface_id": None,
        "trust_boundary_id": "boundary.user.input", "risk": "medium", "data_types": ["user_message"],
        "side_effect": False, "pep": pep("input", "pep.input.ingress", False),
        "metadata": _meta("User input", "A user message enters the agents.", "zt_adk:input", now),
        "attributes": {"zt_adk_edge": "input"},
    })
    ids.interaction["input|ingress|input"] = interactions[-1]["id"]
    for e in model.edges:
        key = f"{e.kind}|{e.caller}|{e.target}"
        if e.kind in (M.EDGE_ENTRY, M.EDGE_TRANSFER, M.EDGE_ORCHESTRATE, M.EDGE_AGENT_TOOL):
            caller_sid = INGRESS_SUBJECT if e.caller == M.SystemModel.INGRESS else ids.subject[e.caller]
            eid = edge_id(e.kind, e.caller, e.target)
            boundary = "boundary.ingress.agents" if e.kind == M.EDGE_ENTRY else "boundary.agent.agent"
            interactions.append({
                "id": eid, "caller_id": caller_sid, "target_id": ids.agent_resource[e.target],
                "resource_id": ids.agent_resource[e.target], "action": "invoke",
                "workflow_id": wf(e), "interface_id": None, "trust_boundary_id": boundary, "risk": "medium",
                "data_types": ["agent_invocation"], "side_effect": False,
                "pep": pep("agent_route", f"pep.{e.kind}.{slug(e.caller, 40)}__{slug(e.target, 60)}", False),
                "metadata": _meta(f"{e.caller} -> {e.target}", f"{e.kind} edge discovered from the ADK tree.",
                                  f"zt_adk:{e.kind}", now),
                "attributes": {"zt_adk_edge": e.kind, "caller": e.caller, "target": e.target},
            })
            ids.interaction[key] = eid
        elif e.kind in (M.EDGE_TOOL, M.EDGE_BUILTIN):
            tool = model.tools[e.target]
            op = ids.operations[e.target]
            eid = edge_id(e.kind, e.caller, tool.name)
            ptype = "mcp" if tool.kind == M.TOOLSET_TOOL and "mcp" in str(tool.toolset or "").lower() else "tool"
            boundary = "boundary.agent.model" if e.kind == M.EDGE_BUILTIN else "boundary.agent.tool"
            interactions.append({
                "id": eid, "caller_id": ids.subject[e.caller], "target_id": ids.tool_resource[e.target],
                "resource_id": ids.tool_resource[e.target], "action": op["action"], "workflow_id": wf(e),
                "interface_id": ids.interaction.get(f"interface|{e.target}"), "trust_boundary_id": boundary,
                "risk": RISK_OF[op["criticality"]], "data_types": ["tool_arguments"],
                "side_effect": bool(op["side_effect"]),
                "pep": pep(ptype, f"pep.{e.kind}.{slug(e.caller, 40)}__{slug(tool.name, 60)}",
                           op["criticality"] == "critical"),
                "metadata": _meta(f"{e.caller} -> {tool.name}", f"{tool.kind} call", f"zt_adk:{e.kind}", now),
                "attributes": {"zt_adk_edge": e.kind, "caller": e.caller, "tool_key": e.target,
                               "enforced_at": "model_request" if e.kind == M.EDGE_BUILTIN else "tool_call"},
            })
            ids.interaction[key] = eid
        elif e.kind == M.EDGE_OUTPUT:
            eid = edge_id("output", e.caller, "mas_output")
            interactions.append({
                "id": eid, "caller_id": ids.subject[e.caller], "target_id": OUTPUT_RESOURCE,
                "resource_id": OUTPUT_RESOURCE, "action": "emit", "workflow_id": wf(e), "interface_id": None,
                "trust_boundary_id": "boundary.output.external", "risk": "medium", "data_types": ["agent_output"],
                "side_effect": False, "pep": pep("output", f"pep.output.{slug(e.caller, 60)}", False),
                "metadata": _meta(f"{e.caller} -> user", "User-visible content of the agent.", "zt_adk:output",
                                  now),
                "attributes": {"zt_adk_edge": "output", "caller": e.caller},
            })
            ids.interaction[key] = eid

    boundaries = []
    for bid, frm, to, title in (("boundary.user.input", "user", "ingress", "User input"),
                                ("boundary.ingress.agents", "ingress", "agent", "Ingress to agents"),
                                ("boundary.agent.agent", "agent", "agent", "Agent to agent"),
                                ("boundary.agent.tool", "agent", "tool", "Agent to tool"),
                                ("boundary.agent.model", "agent", "model", "Agent to model capabilities"),
                                ("boundary.output.external", "agent", "external", "Output to the user")):
        boundaries.append({"id": bid, "from_zone": frm, "to_zone": to,
                           "metadata": _meta(title, title, "zt_adk", now), "attributes": {}})

    name = slug(model.app_name, 60).replace("_", "-")
    manifest = {
        "apiVersion": "ztb/v1alpha1",
        "kind": "ZeroTrustSystemManifest",
        "metadata": {"name": name, "manifest_version": "1.0.0", "environment": env, "created_at": now,
                     "updated_at": now, "owner": "zt-adk", "source_revision": model.fingerprint(),
                     "description": f"Generated by zt-adk from the ADK application {model.app_name} "
                                    f"(google-adk {model.adk_version})."},
        "spec": {
            "defaults": {"decision": "DENY", "pep_mode": profile.mode, "environment_binding": env,
                         "placeholder_token": "__REQUIRED__", "clock_skew_seconds": 5, "extensions": {}},
            "subjects": subjects, "resources": resources, "interfaces": interfaces, "workflows": workflows,
            "interactions": interactions, "trust_boundaries": boundaries, "policy_bundles": [],
            "audit": {"schema_ref": "schemas/audit_event.schema.json", "sink_interface_id": None,
                      "required_fields": ["timestamp", "trace_id", "subject_id", "resource_id", "action",
                                          "workflow_id", "decision", "policy_version", "outcome"],
                      "retention": "deployment-defined",
                      "redaction": ["tool_arguments", "message_text", "tool_results"]},
            "unresolved": [],
            "extensions": {"zt_adk": {"fingerprint": model.fingerprint(), "root_agent": model.root_agent}},
        },
    }
    return manifest, ids
