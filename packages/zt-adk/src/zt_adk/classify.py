"""Classification of every protected operation: action, side effect, criticality, data class.

Precedence, per attribute:

1. the system owner's declaration in ``zt_adk.yaml`` (``tools.<name>`` or ``tools.<agent>/<name>``);
2. evidence from the implementation (``code_analysis``): what the code actually does
   (SQL verbs, HTTP methods, file and process operations, messaging, session state);
3. the tool's name (verb) and description;
4. a conservative default: an operation nothing explains is treated as a side effect of
   high criticality (protected, logged, idempotency required) -- never as a harmless read.

Absence of evidence is not evidence of a harmless read: code is called pure only when the
analysis saw every call it makes (application code it entered, or library code known to be
free of external effects). A call into an SDK or object it cannot see into leaves the decision
to the name and the conservative default.

Criticality ``critical`` means: irreversible or high-impact (deletion, process execution,
credential or permission changes, money movement, external publication of data). Critical
operations need a human approval by default (``approvals.critical``).
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from . import model as M
from .profile import Profile

READ_VERBS = {"get", "list", "search", "find", "lookup", "look", "fetch", "read", "query", "check", "show",
              "describe", "count", "view", "load", "retrieve", "browse", "inspect", "summarize", "summarise",
              "explain", "estimate", "calculate", "compute", "validate", "verify", "preview", "status", "is",
              "has", "can", "lookup"}
CREATE_VERBS = {"create", "add", "insert", "open", "register", "book", "reserve", "schedule", "new", "submit",
                "file", "request", "enqueue", "upload", "save", "store", "record", "log"}
UPDATE_VERBS = {"update", "set", "modify", "change", "edit", "patch", "rename", "assign", "move", "unlock", "lock",
                "enable", "disable", "close", "resolve", "reopen", "approve", "reject", "escalate", "mark",
                "apply", "post", "write", "restore", "renew", "extend", "suspend", "activate", "deactivate"}
DELETE_VERBS = {"delete", "remove", "drop", "purge", "erase", "destroy", "cancel", "revoke", "terminate",
                "wipe", "truncate", "clear", "void"}
SEND_VERBS = {"send", "email", "mail", "notify", "message", "publish", "broadcast", "share", "post_to", "sms",
              "text", "call", "page", "alert", "forward", "reply", "tweet"}
EXEC_VERBS = {"run", "execute", "exec", "invoke", "deploy", "restart", "reboot", "shutdown", "kill", "start",
              "stop", "trigger", "launch", "install", "provision", "migrate", "rollback", "release"}
CRITICAL_TERMS = {"transfer", "payment", "pay", "refund", "wire", "withdraw", "charge", "purchase", "payout",
                  "password", "credential", "secret", "token", "permission", "privilege", "role", "grant",
                  "revoke", "admin", "root", "sudo", "delete", "drop", "purge", "wipe", "destroy", "terminate",
                  "deploy", "shutdown", "reboot", "production", "prod", "mfa", "2fa", "key", "certificate",
                  "firewall", "security", "salary", "payroll", "invoice", "contract", "legal", "trade", "order"}
RESTRICTED_TERMS = {"password", "credential", "secret", "token", "private_key", "api_key", "mfa", "otp", "pin",
                    "cvv", "ssn", "social_security", "passport", "biometric"}
CONFIDENTIAL_TERMS = {"account", "card", "salary", "payroll", "medical", "health", "diagnosis", "patient", "dob",
                      "birth", "address", "phone", "email", "customer", "employee", "user", "personal", "profile",
                      "balance", "transaction", "invoice", "contract", "ticket", "history", "hr", "tax", "iban"}

CRIT_ORDER = ["low", "medium", "high", "critical"]


def _words(text: str) -> list[str]:
    return [w for w in re.split(r"[^a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text).lower()) if w]


def _max_crit(*values: str) -> str:
    return max(values, key=CRIT_ORDER.index)


@dataclass
class OperationClass:
    action: str
    side_effect: bool
    criticality: str
    classification: str
    requires_approval: bool
    secondary_approval: bool
    idempotent: bool
    risk: str
    allowed_roles: list[str] | None = None
    mask_fields: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    declared: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _verb_action(words: list[str]) -> str | None:
    if not words:
        return None
    first = words[0]
    for verbs, action in ((DELETE_VERBS, "delete"), (SEND_VERBS, "send"), (EXEC_VERBS, "execute"),
                          (CREATE_VERBS, "create"), (UPDATE_VERBS, "update"), (READ_VERBS, "read")):
        if first in verbs:
            return action
    return None


def classify_tool(tool: M.ToolInfo, profile: Profile, *, target_agent_critical: bool = False) -> OperationClass:
    """Classify one agent -> tool operation."""
    evidence: list[str] = []
    words = _words(tool.name)
    text_words = set(words) | set(_words(tool.description or "")[:60])
    params = list((tool.parameters.get("properties") or {}).keys())
    param_words = {w for p in params for w in _words(p)}

    if tool.kind == M.AGENT_TOOL:
        action, side_effect, crit = "invoke", False, "medium"
        evidence.append(f"AgentTool for agent {tool.target_agent}: its own tools are protected individually")
    elif tool.kind == M.BUILTIN:
        action, side_effect = "use", False
        crit = "high" if "code" in words or "execution" in words else "low"
        evidence.append("model-side built-in capability (executed by the model provider)")
    else:
        a = tool.analysis or {}
        action, side_effect, crit = None, None, "low"
        if a.get("analyzed") or a.get("http_methods") or a.get("sql"):
            if a.get("process_exec"):
                action, side_effect, crit = "execute", True, "critical"
                evidence.append("code executes a process / dynamic code")
            elif a.get("destructive"):
                action, side_effect, crit = "delete", True, "critical"
                evidence.append("code deletes data (SQL DELETE/DROP, HTTP DELETE, file removal)")
            elif a.get("messaging"):
                action, side_effect, crit = "send", True, "high"
                evidence.append("code sends a message (mail / chat / queue)")
            elif set(a.get("http_methods") or []) & {"post", "put", "patch"} or a.get("db_write") \
                    or a.get("file_write") or set(a.get("sql") or []) & {"INSERT", "UPDATE", "REPLACE", "MERGE",
                                                                         "UPSERT", "CREATE", "ALTER"}:
                action, side_effect, crit = "write", True, "high"
                evidence.append("code writes (SQL INSERT/UPDATE, HTTP POST/PUT/PATCH, ORM/file writes)")
            elif a.get("state_write"):
                action, side_effect, crit = "write", True, "medium"
                evidence.append("code changes ADK session state only")
            elif a.get("reads") and not a.get("opaque_calls"):
                action, side_effect, crit = "read", False, "low"
                evidence.append("code only reads (SQL SELECT, HTTP GET, file reads)")
            elif a.get("memory_write"):
                action, side_effect, crit = "write", True, "medium"
                evidence.append("code changes application objects that outlive the call (module-level or "
                                "instance state)")
            elif a.get("analyzed") and not a.get("unresolved_calls") and not a.get("opaque_calls"):
                action, side_effect, crit = "read", False, "low"
                evidence.append("code has no I/O, no state change and no calls it cannot see into "
                                "(pure computation)")
            if action is None and a.get("opaque_calls"):
                evidence.append(f"calls the analysis cannot see into: {list(a['opaque_calls'])[:5]}")
            if a.get("indirect", {}).get("side_effect") and not side_effect:
                evidence.append("callees may write (lazy initialisation / helpers): ignored for classification, "
                                "the tool's own operation decides")
        verb = _verb_action(words)
        if action is None:
            if verb is not None:
                action = verb
                side_effect = verb != "read"
                crit = {"read": "low", "create": "high", "update": "high", "send": "high", "execute": "critical",
                        "delete": "critical"}[verb]
                evidence.append(f"no conclusive code evidence; name verb '{words[0]}' -> {verb}")
            else:
                action, side_effect, crit = "execute", True, "high"
                evidence.append("unclassified: no code evidence and no known verb -> treated as a side effect "
                                "(declare it in zt_adk.yaml)")
        elif verb is not None and verb != "read" and action in ("write", "read") and side_effect:
            action = verb if verb in ("create", "update", "send", "delete", "execute") else action
        if side_effect and (text_words & CRITICAL_TERMS):
            crit = "critical"
            evidence.append(f"critical term in name/description: {sorted(text_words & CRITICAL_TERMS)}")
        if action == "send":
            crit = _max_crit(crit, "high")
        if tool.kind == M.TOOLSET_TOOL and action == "read" and not (tool.analysis or {}).get("analyzed"):
            evidence.append("toolset tool classified from its name only")

    terms = text_words | param_words
    if terms & RESTRICTED_TERMS:
        classification = "restricted"
    elif terms & CONFIDENTIAL_TERMS:
        classification = "confidential"
    elif tool.kind == M.BUILTIN:
        classification = "public"
    else:
        classification = "internal"

    requires_approval = crit == "critical" and profile.approvals.critical != "none"
    secondary = crit == "critical" and profile.approvals.critical == "dual"
    out = OperationClass(action=action, side_effect=bool(side_effect), criticality=crit,
                         classification=classification, requires_approval=requires_approval,
                         secondary_approval=secondary, idempotent=not side_effect, risk=crit, evidence=evidence)

    ov = profile.tool_override(tool.agent, tool.name)
    if ov is not None:
        declared = ov.model_dump(exclude_none=True)
        for key in ("action", "side_effect", "criticality", "classification", "requires_approval",
                    "secondary_approval", "allowed_roles", "idempotent"):
            if key in declared:
                setattr(out, key, declared[key])
        out.mask_fields = list(ov.mask_fields)
        # what is not declared follows the (possibly declared) criticality and approvals.critical
        if "criticality" in declared and "requires_approval" not in declared:
            out.requires_approval = out.criticality == "critical" and profile.approvals.critical != "none"
        if "secondary_approval" not in declared:
            if declared.get("requires_approval") is False:
                out.secondary_approval = False      # no approval at all: no secondary authorization either
            else:
                out.secondary_approval = out.criticality == "critical" and profile.approvals.critical == "dual"
        if "side_effect" in declared and "idempotent" not in declared:
            out.idempotent = not out.side_effect
        out.risk = out.criticality
        out.declared = True
        out.evidence.append(f"declared in zt_adk.yaml: {sorted(declared)}")
    if out.secondary_approval and not out.requires_approval:
        out.requires_approval = True
    return out
