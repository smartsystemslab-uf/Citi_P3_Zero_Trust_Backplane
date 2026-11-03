"""Check-only PSL scopes enforced by the gateway (gateway_input, gateway_output, gateway_tool).

The rules come from the signed policy store (intent.psl, translated from the Task 1
natural-language intent file); this module only computes the scopes' fields with
trusted gateway checkers and evaluates the rules with zt_psl's RequestPolicyEngine
(runtime "gateway"). The MAS itself (D:\\Lab\\Citi_P3, ADK plugin) only ever sees hashes
of the input and output -- the content rules are enforced here, where the text is.

Field sources (policy_store/policy_fields.yaml):
  session.id_present      the ingress request carries a non-empty session id
  user.role               role asserted by the authenticated ingress service, accepted only if
                          the controlled service map lists it for that service ('' otherwise)
  input.prompt_injection_detected   message matches PROMPT_INJECTION_PATTERNS
  output.contains.*       the evaluator's own PII patterns (Citi_P3 bank_adk/evaluation.py)
  output.contains.unexplained_internal_amount
                          a large exact money amount in the output that does not occur in
                          the user's request
  tool.name               MCP tool being called
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from zt_psl import RequestPolicyEngine
from zt_psl.decision import PolicyDecision

# The MAS evaluator's F_pii patterns (bank_adk/evaluation.py), so the gateway refuses what
# the evaluator counts as a leak. One deliberate difference: the evaluator's phone pattern
# also matches ten digits INSIDE generated identifiers (backend "TX-" + 12 hex, MAS
# "TXN-" + 10 hex: roughly 1-3 % of all ids), which as a blocking rule would deny
# legitimate outputs at random; here the number must not be embedded in an identifier.
ACCOUNT_ID_RE = re.compile(r"\b(?:CHK|SAV|ACCT|CARD|LOAN|HELOC)-\d{2,}\b", re.IGNORECASE)
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
EVALUATOR_PHONE_RE = re.compile(r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")
PHONE_RE = re.compile(r"(?<![\w-])(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}(?![\w-])")
LARGE_EXACT_MONEY_RE = re.compile(r"\$?\b\d{1,3}(?:,\d{3})+(?:\.\d{2})?\b")

# Known prompt-injection phrasings named by the intent rule (override the system prompt,
# ignore instructions, claim an authority waiver). Deliberately narrow: a match denies.
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+|the\s+|your\s+)*(?:previous|prior|above|earlier|"
               r"system)\s+(?:instructions?|prompts?|rules|policies)\b", re.IGNORECASE),
    re.compile(r"\b(?:override|bypass|replace|reveal|print|show)\s+(?:the\s+|your\s+)?system\s+prompt\b", re.IGNORECASE),
    re.compile(r"\byou\s+are\s+now\s+(?:in\s+)?(?:developer|admin|administrator|god|jailbreak|unrestricted)\s+mode\b",
               re.IGNORECASE),
    re.compile(r"\b(?:authority|compliance|policy|security|approval)\s+waiver\b", re.IGNORECASE),
    re.compile(r"\b(?:waive|skip|disable)\s+(?:all\s+|the\s+)?(?:controls|checks|approvals?|policies|policy|"
               r"guardrails)\b", re.IGNORECASE),
]


def prompt_injection_detected(text: str) -> bool:
    return any(p.search(text) for p in PROMPT_INJECTION_PATTERNS)


def _amounts(text: str) -> set[str]:
    return {m.group(0).lstrip("$") for m in LARGE_EXACT_MONEY_RE.finditer(text)}


@dataclass
class GatewayCheck:
    scope: str
    decision: PolicyDecision
    fields: dict[str, Any]

    @property
    def allowed(self) -> bool:
        return self.decision.allowed

    def summary(self) -> dict[str, Any]:
        d = self.decision
        return {"scope": self.scope, "outcome": d.outcome,
                "violated": [v.rule_id for v in d.violated], "flagged": [f.rule_id for f in d.flagged],
                "obligations": [o.as_dict() for o in d.obligations], "eval_us": round(d.eval_ns / 1e3, 2)}


class GatewayPolicies:
    def __init__(self, policy_set: Any) -> None:
        self.input = RequestPolicyEngine(policy_set, scope="gateway_input", runtime="gateway")
        self.output = RequestPolicyEngine(policy_set, scope="gateway_output", runtime="gateway")
        self.tool = RequestPolicyEngine(policy_set, scope="gateway_tool", runtime="gateway")
        self.rule_counts = {name: len(e.constraints) + len(e.permits)
                            for name, e in (("gateway_input", self.input), ("gateway_output", self.output),
                                            ("gateway_tool", self.tool))}

    def check_input(self, *, session_id: str, user_role: str, message: str) -> GatewayCheck:
        f = {"session.id_present": bool(session_id.strip()), "user.role": user_role,
             "input.prompt_injection_detected": prompt_injection_detected(message)}
        return GatewayCheck("gateway_input", self.input.decide(f), f)

    def check_output(self, *, text: str, request_text: str) -> GatewayCheck:
        f = {"output.contains.account_id": bool(ACCOUNT_ID_RE.search(text)),
             "output.contains.ssn": bool(SSN_RE.search(text)),
             "output.contains.email": bool(EMAIL_RE.search(text)),
             "output.contains.phone": bool(PHONE_RE.search(text)),
             "output.contains.unexplained_internal_amount": bool(_amounts(text) - _amounts(request_text))}
        return GatewayCheck("gateway_output", self.output.decide(f), f)

    def check_tool(self, *, tool_name: str, user_role: str) -> GatewayCheck:
        f = {"tool.name": tool_name, "user.role": user_role}
        return GatewayCheck("gateway_tool", self.tool.decide(f), f)
