"""Read-only view of a protected application: bundle, policies, audit log and approvals.

Nothing here executes the application or touches key material. Everything is read from the files the Backplane
already writes (bundle directory, state directory).
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .config import Config
from .explain import describe

GENESIS = "0" * 64
LAYERS = {
    "00_core": "Approvals and risk: critical operations need a human approval bound to the exact request.",
    "10_access": "Least privilege: one permit per generated placement (who may do what, where).",
    "15_domains": "Domain isolation: which agents may start agents of another domain.",
    "20_identity": "Authenticated identity at the decision point.",
    "30_content": "Content rules: input, output, tool calls, tool results, agent messages, model requests.",
    "40_workflow": "Workflow order: steps of sequential workflows and graph nodes.",
    "50_gateway_runtime": "Properties of the distributed tool path (permit binding, audit before execution, ...).",
    "90_overlay": "Your own rules from the profile (they can only narrow what the generated permits allow).",
}
SAFE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
READ_WINDOW = 8_000_000          # bytes of the audit log the views read (the newest part); verification reads it all


class BackplaneUnavailable(RuntimeError):
    pass


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _canonical(rec: dict[str, Any]) -> bytes:
    return json.dumps(rec, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False).encode("utf-8")


def verify_chain(path: Path) -> dict[str, Any]:
    """Same check as zt_adk.audit.verify_chain. The chain is unkeyed: it detects accidental or naive edits only."""
    prev, n = GENESIS, 0
    if not path.exists():
        return {"ok": True, "records": 0, "head": prev, "note": "no audit log yet"}
    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                return {"ok": False, "records": n, "error": f"line {lineno}: not valid JSON"}
            h = rec.pop("hash", None)
            if rec.get("prev") != prev:
                return {"ok": False, "records": n, "error": f"line {lineno}: previous-hash link broken"}
            if hashlib.sha256(prev.encode() + _canonical(rec)).hexdigest() != h:
                return {"ok": False, "records": n, "error": f"line {lineno}: record hash mismatch"}
            prev, n = h, n + 1
    return {"ok": True, "records": n, "head": prev}


class Backplane:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    # ------------------------------------------------------------------ helpers
    def _require(self) -> Path:
        if not self.cfg.configured:
            raise BackplaneUnavailable("no protected application is loaded: start the console with --profile "
                                       "and build the bundle first (zt-adk build)")
        assert self.cfg.bundle_dir is not None
        return self.cfg.bundle_dir

    def bundle_app_name(self) -> str:
        """The application name recorded in the built bundle, or "" before the first build (reads one small file)."""
        if not self.cfg.configured:
            return ""
        try:
            return str(_read_json(self.cfg.bundle_dir / "bundle.json").get("app_name") or "")   # type: ignore[operator]
        except (OSError, ValueError):
            return ""

    @property
    def audit_path(self) -> Path | None:
        return self.cfg.state_dir / "audit.jsonl" if self.cfg.state_dir else None

    def log_truncated(self) -> bool:
        """True when the audit log is larger than the window the views read, so they show only its newest part."""
        p = self.audit_path
        return bool(p and p.exists() and p.stat().st_size > READ_WINDOW)

    def read_events(self, max_bytes: int | None = None) -> list[dict[str, Any]]:
        max_bytes = max_bytes or READ_WINDOW
        p = self.audit_path
        if p is None or not p.exists():
            return []
        size = p.stat().st_size
        with p.open("rb") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
                fh.readline()                                  # drop a partial first line
            raw = fh.read().decode("utf-8", errors="replace")
        out = []
        for line in raw.splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

    def last_seq(self) -> int:
        ev = self.read_events(max_bytes=200_000)
        return int(ev[-1].get("seq", 0)) if ev else 0

    # ------------------------------------------------------------------ views
    def overview(self) -> dict[str, Any]:
        bundle = self._require()
        index = _read_json(bundle / "bundle.json")
        profile = _read_json(bundle / "runtime_profile.json") if (bundle / "runtime_profile.json").exists() else {}
        model = _read_json(bundle / "system_model.json")
        verify = verify_chain(self.audit_path) if self.audit_path else {"ok": True, "records": 0}
        pending = [a for a in self.approvals() if a["status"] == "pending"]
        return {
            "app": index.get("app_name"), "fingerprint": index.get("fingerprint"),
            "policy_version": index.get("policy_version"), "created_at": index.get("created_at"),
            "mode": index.get("mode") or profile.get("mode"), "environment": index.get("environment"),
            "adk_version": index.get("adk_version") or model.get("adk_version"),
            "counts": {"agents": len(model.get("agents", {})), "tools": len(model.get("tools", {})),
                       "edges": len(model.get("edges", [])), "placements": index.get("logical_peps"),
                       "policy_sets": len(index.get("policy_sets", {}))},
            "roles": (profile.get("session") or {}).get("roles") or [],
            "approvals_wait_s": (profile.get("approvals") or {}).get("wait_seconds"),
            "audit": verify, "pending_approvals": len(pending),
        }

    def system(self) -> dict[str, Any]:
        bundle = self._require()
        model = _read_json(bundle / "system_model.json")
        bindings = _read_json(bundle / "bindings.json") if (bundle / "bindings.json").exists() else {}
        ops = bindings.get("operations", {})
        domains = bindings.get("domains", {})
        tools = []
        for key, t in model.get("tools", {}).items():
            op = ops.get(key, {})
            tools.append({
                "key": key, "agent": t.get("agent"), "name": t.get("name"), "kind": t.get("kind"),
                "description": t.get("description", ""), "action": op.get("action"),
                "side_effect": op.get("side_effect"), "criticality": op.get("criticality"),
                "classification": op.get("classification"), "requires_approval": op.get("requires_approval"),
                "secondary_approval": op.get("secondary_approval"), "allowed_roles": op.get("allowed_roles"),
                "mask_fields": op.get("mask_fields") or [], "declared": op.get("declared"),
                "evidence": (op.get("evidence") or [])[:6]})
        agents = []
        for name, a in model.get("agents", {}).items():
            agents.append({"name": name, "kind": a.get("kind"), "description": a.get("description", ""),
                           "parent": a.get("parent"), "sub_agents": a.get("sub_agents", []),
                           "domain": domains.get(name), "model": a.get("model"),
                           "tools": [t["name"] for t in tools if t["agent"] == name]})
        return {"app": model.get("app_name"), "root": model.get("root_agent"), "agents": agents, "tools": tools,
                "edges": model.get("edges", []), "workflows": list((model.get("workflows") or {}).keys()),
                "warnings": model.get("warnings", [])}

    def policies(self) -> dict[str, Any]:
        bundle = self._require()
        store = bundle / "policy_store"
        files = []
        for p in sorted(store.glob("*.psl")):
            layer = next((v for k, v in LAYERS.items() if p.name.startswith(k)), "")
            files.append({"file": p.name, "layer": layer, "rules": parse_psl(p.read_text(encoding="utf-8"))})
        return {"version": _read_json(bundle / "bundle.json").get("policy_version"), "files": files}

    def rule_text(self) -> dict[str, str]:
        try:
            return {r["id"]: r["nl"] for f in self.policies()["files"] for r in f["rules"]}
        except BackplaneUnavailable:
            return {}

    def events(self, *, limit: int = 200, offset: int = 0, outcome: str = "", boundary: str = "", q: str = "",
               after_seq: int = 0, max_seq: int = 0) -> dict[str, Any]:
        rt = self.rule_text()
        rows = []
        for rec in self.read_events():
            seq = int(rec.get("seq", 0))
            if seq <= after_seq or (max_seq and seq > max_seq):         # max_seq: a page of an older listing
                continue
            d = describe(rec, rt)
            if outcome and d["outcome"] != outcome:
                continue
            if boundary and d["boundary"] != boundary:
                continue
            if q and q.lower() not in json.dumps(rec, default=str).lower():
                continue
            rows.append({**d, "seq": rec.get("seq"), "ts": rec.get("ts"), "event": rec.get("event"),
                         "caller": rec.get("caller"), "target": rec.get("target"), "run": rec.get("run"),
                         "trace_id": rec.get("trace_id"), "hash": rec.get("hash"), "raw": rec})
        rows.reverse()
        return {"total": len(rows), "items": rows[offset: offset + max(1, min(limit, 500))],
                "truncated": self.log_truncated()}

    def verify(self) -> dict[str, Any]:
        return verify_chain(self.audit_path) if self.audit_path else {"ok": True, "records": 0}

    def stats(self) -> dict[str, Any]:
        """Counts over the audit log: decisions by outcome and boundary, rules that fired, runs."""
        rt = self.rule_text()
        by_outcome: Counter[str] = Counter()
        by_boundary: dict[str, Counter[str]] = defaultdict(Counter)
        rules: Counter[str] = Counter()
        runs = 0
        first = last = None
        for rec in self.read_events():
            event = str(rec.get("event", ""))
            first = first or rec.get("ts")
            last = rec.get("ts") or last
            if event == "RUN_COMPLETE":
                runs += 1
            d = describe(rec, rt)
            if d["boundary"] == "System":
                continue
            by_outcome[d["outcome"]] += 1
            by_boundary[d["boundary"]][d["outcome"]] += 1
            if d["outcome"] in ("denied", "held", "flagged"):
                for r in d["rules"]:
                    rules[r["id"]] += 1
        return {"runs": runs, "decisions": sum(by_outcome.values()), "by_outcome": dict(by_outcome),
                "by_boundary": {b: dict(c) for b, c in by_boundary.items()},
                "top_rules": [{"id": r, "text": rt.get(r, ""), "count": n} for r, n in rules.most_common(8)],
                "first": first, "last": last, "truncated": self.log_truncated()}

    def approvals(self) -> list[dict[str, Any]]:
        d = self.cfg.approvals_dir
        if d is None or not (d / "requests").is_dir():
            return []
        out = []
        for p in sorted((d / "requests").glob("apr-*.json"), reverse=True):
            try:
                rec = _read_json(p)
            except ValueError:
                continue
            decisions = {}
            for purpose in ("human_approval", "secondary_authorization"):
                dp = d / "decisions" / f"{rec['approval_id']}.{purpose}.json"
                if dp.exists():
                    try:
                        sig = _read_json(dp)
                        decisions[purpose] = {"decision": sig.get("decision"), "issuer": sig.get("issuer"),
                                              "expires_at": sig.get("expires_at")}
                    except ValueError:
                        pass
            op = rec.get("operation") or {}
            out.append({"approval_id": rec["approval_id"], "status": rec.get("status"), "agent": rec.get("agent"),
                        "tool": rec.get("tool"), "reason": rec.get("reason"), "purposes": rec.get("purposes", []),
                        "created_at": rec.get("created_at"), "expires_at": rec.get("expires_at"),
                        "request_hash": rec.get("request_hash"), "parameters": op.get("parameters") or {},
                        "environment": op.get("environment"), "trace_id": rec.get("trace_id"),
                        "decisions": decisions})
        return out


# ---------------------------------------------------------------------- PSL catalogue
def parse_psl(text: str) -> list[dict[str, Any]]:
    """Rules of a PSL file from its annotations: // @rule, // @nl, // @permit, // @on_violation."""
    rules: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    policy_set, version, scope = "", "", ""
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("// @policy_set"):
            policy_set = s.split(None, 2)[2].strip() if len(s.split(None, 2)) > 2 else ""
        elif s.startswith("// @version"):
            version = s.split(None, 2)[2].strip() if len(s.split(None, 2)) > 2 else ""
        elif s.startswith("vunit "):
            m = re.match(r"vunit\s+\w+\s*\((\w+)\)", s)
            scope = m.group(1) if m else ""
        elif s.startswith("// @rule "):
            cur = {"id": s[len("// @rule "):].strip(), "nl": "", "effect": "deny", "set": policy_set,
                   "version": version, "scope": scope}
            rules.append(cur)
        elif cur is not None and s.startswith("// @nl"):
            cur["nl"] = s[len("// @nl"):].strip()
        elif cur is not None and s.startswith("// @permit"):
            cur["effect"] = "permit"
        elif cur is not None and s.startswith("// @on_violation"):
            cur["effect"] = s[len("// @on_violation"):].strip().lower() or "deny"
    return rules
