"""Deterministic model-output boundary fixture.

The ONLY thing replaced in the distributed runtime's functional runs is the LLM's output:
`ScriptedLlm` is an ADK `BaseLlm` that returns fixed, rule-derived function
calls / final JSON for each original agent. Agents, instructions, output keys,
tool declarations, the ADK Runner/flow, tool execution, SPIRE/mTLS, agent
signatures, PEP/PDP and Permit Leases are all real. The scripts only read the
user message, the tool results the real tools returned, and the session state
the agent was invoked with.

`install_fixture_llm_module()` injects a replacement for `bank_adk.llm` before
the original agent factories are imported, so `build_model()` never constructs
a LiteLlm client and no network model call can happen.
"""
from __future__ import annotations

import contextvars
import json
import re
import sys
import types as pytypes
from dataclasses import dataclass
from typing import Any, AsyncGenerator, Callable

from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types

INVOCATION_STATE: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar("invocation_state", default={})


@dataclass(frozen=True)
class Step:
    kind: str                      # "call" | "final"
    name: str = ""
    args: dict[str, Any] | None = None
    text: str = ""


def call(name: str, **args: Any) -> Step:
    return Step("call", name=name, args=args)


def final(obj: dict[str, Any]) -> Step:
    return Step("final", text=json.dumps(obj, sort_keys=True))


def _j(resp: Any) -> dict[str, Any]:
    """Decode a tool result the way the agent's LLM would read it."""
    if isinstance(resp, dict) and "result" in resp and len(resp) == 1:
        resp = resp["result"]
    if isinstance(resp, str):
        try:
            resp = json.loads(resp)
        except ValueError:
            return {"raw": resp}
    return resp if isinstance(resp, dict) else {"value": resp}


def _denied(resp: Any) -> bool:
    d = _j(resp)
    return d.get("status") == "zero_trust_denied" or "error" in d


def _find(pattern: str, text: str) -> str:
    m = re.search(pattern, text)
    return m.group(0) if m else ""


def _state_json(state: dict[str, Any], key: str) -> dict[str, Any]:
    raw = state.get(key)
    return _j(raw) if raw is not None else {}


# ---------------------------------------------------------------------------
# Per-agent scripts: (user_text, tool_responses, invocation_state) -> Step
# ---------------------------------------------------------------------------
def monitoring(user: str, r: list[Any], state: dict[str, Any]) -> Step:
    txn = _find(r"TXN-[A-Z0-9-]+", user)
    cust = _find(r"CUST-[A-Z0-9-]+", user)
    if len(r) == 0:
        return call("get_transaction_context", transaction_id=txn)
    if len(r) == 1:
        return call("get_customer_context", customer_id=cust)
    if len(r) == 2:
        return call("list_recent_transactions", customer_id=cust, limit=5)
    ok = not any(_denied(x) for x in r)
    tx = _j(r[0])
    amount = float(tx.get("amount") or 0)
    recent = _j(r[2])
    n_recent = len(recent.get("value", [])) if isinstance(recent.get("value"), list) else 0
    risky = amount >= 5000 or int(tx.get("risk_score") or 0) >= 40
    return final({
        "suspicious": risky,
        "risk_level": "high" if risky else "low",
        "confidence": 0.9 if ok else 0.0,
        "triggers": ["amount_threshold"] if amount >= 5000 else [],
        "summary": f"{txn} amount={amount:.2f} recent={n_recent}",
        "recommended_next_step": "fraud_review" if risky else "none",
        "evidence_ok": ok,
        "transaction_id": txn,
        "customer_id": cust,
    })


def transaction_processing(user: str, r: list[Any], state: dict[str, Any]) -> Step:
    plan = _state_json(state, "fo_service_result")
    if not r:
        if not (plan.get("execution_required") and plan.get("source_account")):
            return final({"status": "not_executed", "execution_performed": False, "transaction_id": "",
                          "outcome": "incomplete_plan", "customer_message": "No backend posting was performed."})
        return call("execute_transfer", source_account=plan["source_account"],
                    destination_account=plan["destination_account"], amount=float(plan["amount"]),
                    memo=str(plan.get("memo", "")), customer_id=str(plan.get("customer_id", "")))
    res = _j(r[0])
    if res.get("status") == "zero_trust_denied":
        return final({"status": "blocked", "execution_performed": False, "transaction_id": "",
                      "outcome": res.get("reason", "zero_trust_denied"),
                      "customer_message": "The transfer was not completed and requires manual review."})
    posted = res.get("status") == "completed"
    return final({"status": res.get("status"), "execution_performed": posted,
                  "transaction_id": res.get("transaction_id") or "", "outcome": res.get("decision_reason", ""),
                  "customer_message": "Transfer completed." if posted else "Transfer not completed."})


def _batch(user: str) -> str:
    return _find(r"EOD-[A-Z0-9-]+", user)


def validation_checkpoint(user: str, r: list[Any], state: dict[str, Any]) -> Step:
    if not r:
        return call("validate_eod_readiness", batch_id=_batch(user))
    d = _j(r[0])
    return final({"ready": bool(d.get("ready")) and not _denied(r[0]), "blockers": [] if d.get("ready") else ["not_ready"],
                  "evidence": {"status": d.get("status"), "business_date": d.get("business_date")},
                  "recommendation": "proceed" if d.get("ready") else "hold"})


def eod_processing(user: str, r: list[Any], state: dict[str, Any]) -> Step:
    if not r:
        return call("get_eod_batch", batch_id=_batch(user))
    d = _j(r[0])
    total = float(d.get("expected_total") or 0)
    return final({"processing_status": "prepared" if not _denied(r[0]) else "failed",
                  "posting_instructions": f"POST {total:.2f} USD to GL for {_batch(user)}",
                  "control_checks": ["batch_found", "ready_flag"], "summary": f"expected_total={total:.2f}"})


def ledger_update(user: str, r: list[Any], state: dict[str, Any]) -> Step:
    if not r:
        proc = _state_json(state, "bo_processing_report")
        return call("apply_ledger_updates", batch_id=_batch(user),
                    posting_instructions=str(proc.get("posting_instructions", "")))
    d = _j(r[0])
    return final({"ledger_update_status": d.get("status", d.get("reason", "failed")),
                  "ledger_reference": d.get("batch_id", ""), "affected_accounts": ["GL-EOD"],
                  "notes": "zero_trust_denied" if _denied(r[0]) else "posted"})


def reconciliation(user: str, r: list[Any], state: dict[str, Any]) -> Step:
    if not r:
        return call("get_reconciliation_data", batch_id=_batch(user))
    d = _j(r[0])
    diff = d.get("difference")
    matched = (not _denied(r[0])) and diff is not None and abs(float(diff)) < 0.005
    return final({"matched": matched, "difference": diff, "confidence": 0.99,
                  "rationale": f"expected={d.get('expected_total')} posted={d.get('ledger_posted_total')}",
                  "recommended_next_step": "report" if matched else "exception"})


def report_writing(user: str, r: list[Any], state: dict[str, Any]) -> Step:
    if not r:
        body = json.dumps({"batch": _batch(user),
                           "processing": _state_json(state, "bo_processing_report").get("summary"),
                           "reconciliation": _state_json(state, "bo_reconciliation_report").get("rationale")},
                          sort_keys=True)
        return call("store_report", batch_id=_batch(user), report_body=body)
    d = _j(r[0])
    return final({"report_summary": f"EOD report for {_batch(user)}", "report_id": d.get("report_id", ""),
                  "downstream_notes": "stored" if d.get("report_id") else "not_stored"})


def exception_handling(user: str, r: list[Any], state: dict[str, Any]) -> Step:
    if not r:
        rec = _state_json(state, "bo_reconciliation_report")
        return call("create_exception_case", batch_id=_batch(user),
                    mismatch_summary=f"difference={rec.get('difference')}")
    d = _j(r[0])
    return final({"exception_case_id": d.get("exception_id", ""), "summary": f"mismatch for {_batch(user)}",
                  "immediate_actions": ["hold_batch"], "escalation_owner": "eod_operations"})


_TRANSFER_RE = re.compile(r"transfer\s+([0-9]+(?:\.[0-9]+)?)\s*USD\s+from\s+(ACC-[A-Z0-9]+)\s+to\s+(ACC-[A-Z0-9]+)",
                          re.IGNORECASE)


def chatbot_intent(user: str, r: list[Any], state: dict[str, Any]) -> Step:
    service = bool(_TRANSFER_RE.search(user)) or re.search(r"(transfer|send|pay)", user, re.IGNORECASE)
    return final({"route": "service" if service else "knowledge", "confidence": 0.9,
                  "rationale": "action request" if service else "informational question"})


def customer_service(user: str, r: list[Any], state: dict[str, Any]) -> Step:
    m = _TRANSFER_RE.search(user)
    if not m:
        return final({"service_type": "service_request", "execution_required": False,
                      "customer_message": "Your request was recorded.", "next_step": "manual_follow_up"})
    return final({"service_type": "transaction_execution", "execution_required": True,
                  "customer_id": _find(r"CUST-[A-Z0-9-]+", user), "source_account": m.group(2),
                  "destination_account": m.group(3), "amount": float(m.group(1)),
                  "memo": _find(r"memo [^.]+", user)[5:], "customer_message": "Transfer requested."})


def knowledge_base(user: str, r: list[Any], state: dict[str, Any]) -> Step:
    if not r:
        return call("search_faqs", query=user[:200])
    hits = _j(r[0]).get("value")
    top = hits[0] if isinstance(hits, list) and hits and isinstance(hits[0], dict) else {}
    return final({"answer": str(top.get("answer", "No matching FAQ entry was found."))[:500],
                  "source": str(top.get("question", ""))[:200]})


SCRIPTS: dict[str, Callable[[str, list[Any], dict[str, Any]], Step]] = {
    "chatbot_intent_agent": chatbot_intent,
    "customer_service_agent": customer_service,
    "knowledge_base_agent": knowledge_base,
    "transaction_monitoring_agent": monitoring,
    "transaction_processing_agent": transaction_processing,
    "validation_checkpoint_agent": validation_checkpoint,
    "eod_processing_agent": eod_processing,
    "ledger_update_agent": ledger_update,
    "reconciliation_agent": reconciliation,
    "report_writing_agent": report_writing,
    "exception_agent": exception_handling,
}


def script_for(agent_name: str) -> Callable[[str, list[Any], dict[str, Any]], Step]:
    return SCRIPTS[agent_name]


class ScriptedLlm(BaseLlm):
    """model = "scripted/<agent_name>"."""

    @classmethod
    def supported_models(cls) -> list[str]:
        return [r"scripted/.*"]

    async def generate_content_async(self, llm_request: LlmRequest, stream: bool = False) -> AsyncGenerator[LlmResponse, None]:
        agent_name = self.model.split("/", 1)[1]
        user_text = ""
        responses: list[Any] = []
        for content in llm_request.contents or []:
            for part in content.parts or []:
                if content.role == "user" and part.text and not user_text:
                    user_text = part.text
                if part.function_response is not None:
                    responses.append(part.function_response.response)
        step = script_for(agent_name)(user_text, responses, INVOCATION_STATE.get())
        if step.kind == "call":
            part = types.Part(function_call=types.FunctionCall(name=step.name, args=step.args or {}))
        else:
            part = types.Part(text=step.text)
        yield LlmResponse(content=types.Content(role="model", parts=[part]))


def install_fixture_llm_module() -> None:
    """Replace bank_adk.llm (LiteLlm factory) with the fixture before agents import it."""
    if "bank_adk.agents.root" in sys.modules:
        raise RuntimeError("agent modules already imported with the original LLM factory")
    mod = pytypes.ModuleType("bank_adk.llm")
    mod.build_model = lambda: ScriptedLlm(model="scripted/unassigned")  # type: ignore[attr-defined]
    mod.__doc__ = "Model-boundary fixture injected by zt_distributed.scripted_model"
    import bank_adk  # noqa: F401  (package __init__ only)

    sys.modules["bank_adk.llm"] = mod
