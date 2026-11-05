"""Content inspection at the input, output, inter-agent and tool-result boundaries.

Detectors compute boolean facts only (``input.contains.email``, ...); what a fact means
(deny, flag, nothing) is decided by the PSL rules of the signed policy store. Detection is
deliberately precise rather than broad: card numbers must pass the Luhn check, IBANs the
ISO 13616 mod-97 check, US SSNs exclude the never-issued ranges, phone numbers need a
country code or a separated NANP layout. No matched text is ever written to an audit
record -- only detector names and counts.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from .profile import Content

EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}(?![\w-])")
PHONE_RE = re.compile(
    r"(?<![\w+-])(?:\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?\d{1,4}(?:[ .-]?\d{2,4}){2,3}"
    r"|\(?\b\d{3}\)?[ .-]\d{3}[ .-]\d{4})(?![\w-])")
SSN_RE = re.compile(r"(?<![\w-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\w-])")
CARD_CANDIDATE_RE = re.compile(r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])")
IBAN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}(?![A-Za-z0-9])")
API_KEY_RES = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                                  # AWS access key id
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),                             # Google API key
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),                        # GitHub token
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),                      # Slack token
    re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b"),              # OpenAI / Anthropic style
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),   # JWT
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{24,}=*"),
]
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")

PROMPT_INJECTION_PATTERNS = [
    r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+|your\s+|of\s+)*(?:previous|prior|above|"
    r"earlier|preceding|system|original)\s+(?:instructions?|prompts?|rules|policies|directions|guidelines)\b",
    r"\b(?:override|bypass|replace|reveal|print|show|leak|repeat)\s+(?:the\s+|your\s+)?(?:system|hidden|initial)\s+"
    r"(?:prompt|instructions?|message)\b",
    r"\byou\s+are\s+now\s+(?:in\s+)?(?:developer|admin|administrator|god|jailbreak|unrestricted|dan)\s+mode\b",
    r"\b(?:do\s+anything\s+now|jailbreak(?:ed)?)\b",
    r"\b(?:authority|compliance|policy|security|approval)\s+waiver\b",
    r"\b(?:waive|skip|disable|turn\s+off)\s+(?:all\s+|the\s+|your\s+)?(?:controls|checks|approvals?|policies|policy|"
    r"guardrails|safety|security|filters)\b",
    r"(?im)^\s*(?:system|developer)\s*(?:prompt)?\s*:\s*\S",
    r"<\|im_start\|>|<\|system\|>|\[/?INST\]|<<SYS>>",
    r"\bnew\s+instructions?\s*:",
]


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def iban_ok(candidate: str) -> bool:
    s = candidate.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in rearranged)
    return int(num) % 97 == 1


def _cards(text: str) -> int:
    n = 0
    for m in CARD_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and digits[0] in "3456" and luhn_ok(digits) and len(set(digits)) >= 2:
            n += 1
    return n


BUILTIN_DETECTORS = ("email", "phone", "ssn", "credit_card", "iban", "api_key", "private_key")


@dataclass
class Findings:
    prompt_injection: bool
    counts: dict[str, int]

    def contains(self) -> dict[str, bool]:
        return {k: v > 0 for k, v in self.counts.items()}

    def summary(self) -> dict[str, Any]:
        return {"prompt_injection": self.prompt_injection,
                "detected": sorted(k for k, v in self.counts.items() if v)}


class ContentInspector:
    def __init__(self, content: Content) -> None:
        self.config = content
        patterns = list(PROMPT_INJECTION_PATTERNS) + list(content.prompt_injection.extra_patterns)
        self.injection = [re.compile(p, re.IGNORECASE) for p in patterns]
        self.custom = {name: re.compile(d.pattern, re.IGNORECASE if d.ignore_case else 0)
                       for name, d in content.custom.items()}
        self.detector_names = tuple(sorted(set(content.detectors) | set(self.custom)))

    def prompt_injection(self, text: str) -> bool:
        return any(p.search(text) for p in self.injection)

    def counts(self, text: str) -> dict[str, int]:
        out: dict[str, int] = {}
        for name in self.detector_names:
            if name in self.custom:
                out[name] = len(self.custom[name].findall(text))
            elif name == "email":
                out[name] = len(EMAIL_RE.findall(text))
            elif name == "phone":
                out[name] = len(PHONE_RE.findall(text))
            elif name == "ssn":
                out[name] = len(SSN_RE.findall(text))
            elif name == "credit_card":
                out[name] = _cards(text)
            elif name == "iban":
                out[name] = sum(1 for m in IBAN_RE.finditer(text) if iban_ok(m.group(0)))
            elif name == "api_key":
                out[name] = sum(len(r.findall(text)) for r in API_KEY_RES)
            elif name == "private_key":
                out[name] = len(PRIVATE_KEY_RE.findall(text))
            else:
                raise ValueError(f"unknown content detector {name!r} (declare it under content.custom)")
        return out

    def inspect(self, text: str) -> Findings:
        text = text if len(text) <= 2_000_000 else text[:2_000_000]
        return Findings(prompt_injection=self.prompt_injection(text), counts=self.counts(text))


def text_of(value: Any, limit: int = 2_000_000) -> str:
    """Flatten a tool result / event payload into text for inspection (keys and values)."""
    parts: list[str] = []
    size = 0

    def walk(v: Any) -> None:
        nonlocal size
        if size > limit:
            return
        if isinstance(v, str):
            parts.append(v)
            size += len(v)
        elif isinstance(v, dict):
            for k, x in v.items():
                parts.append(str(k))
                walk(x)
        elif isinstance(v, (list, tuple, set)):
            for x in v:
                walk(x)
        elif v is not None:
            s = str(v)
            parts.append(s)
            size += len(s)

    walk(value)
    return "\n".join(parts)[:limit]


def content_parts_text(parts: Iterable[Any]) -> str:
    """Text and function-response payloads of genai Content parts."""
    out = []
    for part in parts or []:
        if getattr(part, "text", None):
            out.append(str(part.text))
        fr = getattr(part, "function_response", None)
        if fr is not None and getattr(fr, "response", None) is not None:
            out.append(text_of(fr.response))
    return "\n".join(out)
