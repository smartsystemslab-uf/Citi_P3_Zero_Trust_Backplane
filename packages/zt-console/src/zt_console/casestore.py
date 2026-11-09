"""User-defined test cases (message, role, expected outcome), kept in a JSON file in the console's data directory."""
from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path
from typing import Any

STATES = {"allowed", "completed", "flagged", "blocked", "held"}
BOUNDARIES = {"Input", "Route", "Tool", "Tool result", "Model", "Output", "Approval", "Workflow", "Identity"}
ROLE_RE = re.compile(r"^[A-Za-z0-9_.-]{0,40}$")
EXPECT_KEYS = ("state", "boundary", "rule", "answer_contains", "answer_not_contains")


class CaseError(ValueError):
    pass


def clean_expect(raw: Any) -> dict[str, str]:
    raw = raw if isinstance(raw, dict) else {}
    out: dict[str, str] = {}
    for key in EXPECT_KEYS:
        val = str(raw.get(key) or "").strip()
        if not val:
            continue
        if len(val) > 200:
            raise CaseError(f"expectation {key} is longer than 200 characters")
        if key == "state" and val not in STATES:
            raise CaseError(f"expected state must be one of {sorted(STATES)}")
        if key == "boundary" and val not in BOUNDARIES:
            raise CaseError(f"expected boundary must be one of {sorted(BOUNDARIES)}")
        out[key] = val
    return out


def clean_messages(raw: Any, limit: int = 4000) -> list[str]:
    msgs = [str(m).strip() for m in (raw if isinstance(raw, list) else [raw]) if m is not None and str(m).strip()]
    if not msgs:
        raise CaseError("at least one message is required")
    if len(msgs) > 10:
        raise CaseError("at most 10 turns per test")
    if any(len(m) > limit for m in msgs):
        raise CaseError(f"a message is longer than {limit} characters")
    return msgs


class CaseStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def _load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            return list(json.loads(self.path.read_text(encoding="utf-8")).get("cases", []))
        except ValueError:
            return []

    def _save(self, cases: list[dict[str, Any]]) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"cases": cases}, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)

    def list(self, apps: str | tuple[str, ...]) -> list[dict[str, Any]]:
        names = (apps,) if isinstance(apps, str) else tuple(apps)
        with self._lock:
            return [c for c in self._load() if c.get("app") in ("*", *names)]

    def save(self, body: dict[str, Any], app: str) -> dict[str, Any]:
        name = str(body.get("name") or "").strip()
        if not name or len(name) > 120:
            raise CaseError("name is required (at most 120 characters)")
        role = str(body.get("role") or "").strip()
        if not ROLE_RE.match(role):
            raise CaseError("role may contain letters, digits, '.', '_' and '-' only")
        case = {"name": name, "app": app, "messages": clean_messages(body.get("messages")), "role": role,
                "expect": clean_expect(body.get("expect")), "note": str(body.get("note") or "")[:500]}
        with self._lock:
            cases = self._load()
            cid = str(body.get("id") or "")
            existing = next((c for c in cases if c.get("id") == cid), None)
            if existing is not None:
                existing.update(case)
                case = existing
            else:
                n = 1 + max([int(c["id"][2:]) for c in cases if str(c.get("id", "")).startswith("C-") and c["id"][2:].isdigit()] or [0])
                case["id"] = f"C-{n:03d}"
                cases.append(case)
            self._save(cases)
        return case

    def delete(self, cid: str) -> bool:
        with self._lock:
            cases = self._load()
            keep = [c for c in cases if c.get("id") != cid]
            if len(keep) == len(cases):
                return False
            self._save(keep)
            return True
