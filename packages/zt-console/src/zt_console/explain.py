"""Plain-English explanation of audit records: which boundary decided, and what it means."""
from __future__ import annotations

from typing import Any

BOUNDARY = {
    "INPUT_AUTHORIZATION": "Input", "CONTENT_INPUT": "Input",
    "AGENT_ROUTE_AUTHORIZATION": "Route", "CONTENT_AGENT_MESSAGE": "Route",
    "TOOL_AUTHORIZATION": "Tool", "CONTENT_TOOL_CALL": "Tool", "TOOL_FAILED": "Tool",
    "TOOL_OBLIGATION_REJECTED": "Tool", "TOOL_EXECUTED": "Tool result", "CONTENT_TOOL_RESULT": "Tool result",
    "OUTPUT_AUTHORIZATION": "Output", "CONTENT_OUTPUT": "Output",
    "CONTENT_MODEL": "Model", "UNDECLARED_FUNCTION_CALL": "Model",
    "APPROVAL_REQUESTED": "Approval", "APPROVAL_DENIED": "Approval", "APPROVAL_APPLIED": "Approval",
    "WORKFLOW_VIOLATION": "Workflow", "WORKFLOW_CLOSE_VIOLATION": "Workflow",
    "IDENTITY_VERSION_CHANGED": "Identity", "DISPATCH_REFUSED": "Identity",
    "ENGINE_START": "System", "RUN_COMPLETE": "System",
}


def outcome(rec: dict[str, Any]) -> str:
    """allowed | denied | held | flagged | info"""
    event = str(rec.get("event", ""))
    if rec.get("decision") == "MANUAL_REVIEW" or event == "APPROVAL_REQUESTED":
        return "held"
    if event in ("WORKFLOW_VIOLATION", "WORKFLOW_CLOSE_VIOLATION", "UNDECLARED_FUNCTION_CALL", "APPROVAL_DENIED",
                 "TOOL_OBLIGATION_REJECTED", "DISPATCH_REFUSED"):
        return "denied"
    allowed = rec.get("allowed")
    if allowed is False:
        return "denied"
    if rec.get("flagged"):
        return "flagged"
    if allowed is True:
        return "allowed"
    return "info"


def _who(rec: dict[str, Any]) -> str:
    caller, target = rec.get("caller"), rec.get("target")
    if caller and target:
        return f"{caller} -> {target}"
    return str(caller or target or "")


def describe(rec: dict[str, Any], rule_text: dict[str, str] | None = None) -> dict[str, Any]:
    event = str(rec.get("event", ""))
    out = outcome(rec)
    reason = str(rec.get("reason") or "")
    who = _who(rec)
    ok = out == "allowed"
    texts = {
        "ENGINE_START": f"The protection engine started with policy version {rec.get('policy_version')} in "
                        f"{rec.get('mode')} mode.",
        "INPUT_AUTHORIZATION": ("The user's message passed the input check and was allowed to enter the system."
                                if ok else f"The user's message was stopped at the input boundary ({reason})."),
        "CONTENT_INPUT": ("The message was flagged by an input content rule." if out == "flagged" else
                          f"An input content rule refused the message ({reason})."),
        "AGENT_ROUTE_AUTHORIZATION": (f"Handing the conversation over ({who}) is permitted by a generated route "
                                      "permit." if ok else f"The hand-over {who} was refused ({reason})."),
        "TOOL_AUTHORIZATION": (f"The tool call by {rec.get('caller')} to {rec.get('target')} was authorised "
                               "(permit issued, obligations such as masking attached)." if ok else
                               f"The tool call to {rec.get('target')} was not authorised ({reason})."),
        "TOOL_EXECUTED": f"The tool {rec.get('tool') or rec.get('agent')} ran and its result was checked "
                         f"(result policy: {rec.get('result_policy')}).",
        "TOOL_FAILED": f"The tool call failed: {rec.get('error') or reason}",
        "CONTENT_TOOL_CALL": f"A tool-call content rule decided ({reason or out}).",
        "CONTENT_TOOL_RESULT": ("A tool result was flagged; the run is now treated as higher risk and later side "
                                "effects need approval." if out == "flagged" else
                                f"A tool result was withheld by a content rule ({reason})."),
        "OUTPUT_AUTHORIZATION": ("The answer shown to the user passed the output check." if ok else
                                 f"The answer was withheld at the output boundary ({reason})."),
        "CONTENT_OUTPUT": ("The answer was flagged by an output content rule." if out == "flagged" else
                           f"An output content rule withheld the answer ({reason})."),
        "CONTENT_AGENT_MESSAGE": ("A message between agents was flagged." if out == "flagged" else
                                  f"A message between agents was refused ({reason})."),
        "CONTENT_MODEL": f"The model request was checked against the agent's declared functions ({reason or out}).",
        "UNDECLARED_FUNCTION_CALL": f"The model asked for a function this agent does not have; the call was refused "
                                    f"and the run marked as tainted ({reason}).",
        "APPROVAL_REQUESTED": f"The operation is critical and was held for human approval "
                              f"(approval {rec.get('approval_id')}).",
        "APPROVAL_DENIED": f"An approver denied the operation (approval {rec.get('approval_id')}).",
        "APPROVAL_APPLIED": ("A signed approval was applied and the operation was allowed." if rec.get("allowed")
                             else "A signed approval was presented but the operation was still refused."),
        "WORKFLOW_VIOLATION": f"A step was refused because it broke a workflow-order rule ({', '.join(rec.get('rules') or [])}).",
        "WORKFLOW_CLOSE_VIOLATION": "A workflow ended without meeting a required ordering rule.",
        "IDENTITY_VERSION_CHANGED": "An agent's identity version changed; its outstanding permits were revoked.",
        "DISPATCH_REFUSED": f"Work was not sent to an agent ({reason}).",
        "RUN_COMPLETE": "The run finished.",
    }
    text = texts.get(event, event.replace("_", " ").capitalize())
    rules = [{"id": r, "text": (rule_text or {}).get(r, "")} for r in (rec.get("rules") or []) + (rec.get("flagged") or [])]
    return {"boundary": BOUNDARY.get(event, "System"), "outcome": out, "text": text, "rules": rules}
