#!/usr/bin/env python3
"""Differential comparison: legacy YAML engine (priority) vs PSL engine (deny-overrides).

Both engines get the SAME verified security context (a stub verifier), so every
difference comes from the policy semantics alone. The request corpus is the full
cross product of

    identities x (resource, action) x workflows x risk level x auth strength
    x (approval, secondary approval) x decision time (in / outside business hours)

using the Task 4 registries and every workflow named in either policy set (plus ""
and an unknown workflow). Output: a Markdown report and a JSON summary.

    python scripts/psl_differential_report.py [--out-md ../docs/PSL_DIFFERENTIAL_REPORT.md]
"""
from __future__ import annotations

import argparse
import itertools
import shutil
import tempfile
import json
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from zt_backplane.crypto import TrustedKeyStore                      # noqa: E402
from zt_backplane.engine import PolicyEngine                          # noqa: E402
from zt_backplane.evidence import FixedClock                          # noqa: E402
from zt_backplane.legacy_engine import LegacyPolicyEngine             # noqa: E402
from zt_backplane.models import PDPRequest, RiskLevel, VerifiedSecurityContext  # noqa: E402
from zt_backplane.policy import PolicyBundle                          # noqa: E402
from zt_backplane.psl_policy import PslPolicyStore                    # noqa: E402
from zt_backplane.registry import IdentityRegistry, ResourceCatalog   # noqa: E402

RISK_SCORE = {"low": 100, "medium": 400, "high": 700, "critical": 950}
TIMES = {"business_hours": datetime(2026, 7, 27, 14, 0, tzinfo=timezone.utc),     # Mon 10:00 New York
         "night": datetime(2026, 7, 27, 3, 0, tzinfo=timezone.utc)}               # Sun 23:00 New York


class StubVerifier:
    """Returns a prepared VerifiedSecurityContext: isolates policy semantics."""

    def __init__(self) -> None:
        self.ctx: VerifiedSecurityContext | None = None
        self.clock = FixedClock(TIMES["business_hours"])

    def verify(self, request: PDPRequest) -> VerifiedSecurityContext:
        assert self.ctx is not None
        return self.ctx


def workflows(legacy_dir: Path, psl_dir: Path) -> list[str]:
    found: set[str] = set()
    for p in legacy_dir.glob("*.yaml"):
        for pol in (yaml.safe_load(p.read_text(encoding="utf-8")) or {}).get("policies", []):
            found.update(pol.get("match", {}).get("workflows", []) or [])
    for p in psl_dir.glob("*.psl"):
        found.update(re.findall(r'workflow\.id == "([^"]+)"', p.read_text(encoding="utf-8")))
    return sorted(found) + ["", "workflow.unknown.other"]


def build_engines(legacy_dir: Path, psl_dir: Path, config: Path) -> tuple[Any, Any, StubVerifier, StubVerifier]:
    trust = config / "trusted_issuers.yaml"
    keys = TrustedKeyStore(trust if trust.exists() else ROOT / "config" / "trusted_issuers.yaml")
    identities = IdentityRegistry.from_yaml(config / "identities.yaml")
    resources = ResourceCatalog.from_yaml(config / "resources.yaml")
    sv_old, sv_new = StubVerifier(), StubVerifier()
    legacy = LegacyPolicyEngine(
        bundle=PolicyBundle.load(legacy_dir, schema_path=ROOT / "interface_contract" / "schemas" /
                                 "policy_bundle.schema.json", keys=keys),
        identities=identities, resources=resources, evidence_verifier=sv_old)   # type: ignore[arg-type]
    new = PolicyEngine(bundle=PslPolicyStore.load(psl_dir, keys=keys), identities=identities,
                       resources=resources, evidence_verifier=sv_new)            # type: ignore[arg-type]
    return legacy, new, sv_old, sv_new


def store_without(psl_dir: Path, exclude: tuple[str, ...], tmp: Path) -> Path:
    """Copy of a signed PSL store without some policy files (the remaining signatures stay valid)."""
    out = tmp / "store"
    shutil.copytree(psl_dir, out)
    for name in exclude:
        for f in (out / name, out / name.replace(".psl", ".sig.json")):
            if f.exists():
                f.unlink()
    return out


STRICT = {"ALLOW": 0, "ALLOW_WITH_OBLIGATIONS": 0, "MANUAL_REVIEW": 1, "REAUTHENTICATE": 2, "DENY": 3}


def run(legacy_dir: Path, psl_dir: Path, config: Path, *, risks: tuple[str, ...] = ("low", "medium", "high", "critical"),
        auths: tuple[int, ...] = (0, 1, 2, 3),
        approvals: tuple[tuple[bool, bool], ...] = ((False, False), (True, False), (False, True), (True, True)),
        times: tuple[str, ...] = tuple(TIMES)) -> dict[str, Any]:
    legacy, new, sv_old, sv_new = build_engines(legacy_dir, psl_dir, config)
    ident = yaml.safe_load((config / "identities.yaml").read_text(encoding="utf-8"))
    res = yaml.safe_load((config / "resources.yaml").read_text(encoding="utf-8"))
    subjects = ident.get("identities", ident)
    resources = res.get("resources", res)
    wfs = workflows(legacy_dir, psl_dir)
    total = 0
    same = 0
    diffs: Counter = Counter()
    examples: dict[tuple, dict[str, Any]] = {}
    obligation_diffs: Counter = Counter()
    by_outcome: dict[str, Counter] = defaultdict(Counter)
    t0 = time.perf_counter()
    for s, r, wf in itertools.product(subjects, resources, wfs):
        for action in r["actions"]:
            req = PDPRequest.model_validate({
                "request_id": "diff", "trace_id": "diff",
                "subject": {"canonical_id": s["canonical_id"], "runtime_id": s["id"], "identity_evidence": {}},
                "resource": {"canonical_id": r["canonical_id"], "runtime_id": r["id"]},
                "action": action,
                "context": {"workflow_id": wf or None, "risk": "low", "timestamp": TIMES["business_hours"],
                            "environment": "test"},
                "parameters": {}})
            for risk, auth, (appr, sec), tname in itertools.product(risks, auths, approvals, times):
                ctx = VerifiedSecurityContext(
                    decision_time=TIMES[tname], identity_verified=True, identity_issuer="diff", request_jti="j",
                    request_nonce="n", identity_version="1", risk_verified=True, risk_issuer="diff",
                    risk_score=RISK_SCORE[risk], risk_level=RiskLevel(risk), risk_version="1", auth_verified=True,
                    auth_issuer="diff", auth_strength=auth, workflow_verified=bool(wf), approval_valid=appr,
                    secondary_authorization_valid=sec)
                sv_old.ctx = sv_new.ctx = ctx
                a, b = legacy.evaluate(req), new.evaluate(req)
                total += 1
                by_outcome["legacy"][a.decision.value] += 1
                by_outcome["psl"][b.decision.value] += 1
                if a.decision == b.decision:
                    same += 1
                    oa = Counter(_obligation_label(o) for o in a.obligations)
                    ob = Counter(_obligation_label(o) for o in b.obligations)
                    if oa != ob:
                        obligation_diffs[(a.policy_id, tuple(p for p in b.matched_policy_ids),
                                          tuple(sorted((ob - oa).elements())),
                                          tuple(sorted((oa - ob).elements())))] += 1
                    continue
                key = (a.decision.value, b.decision.value, a.policy_id or a.reason, b.policy_id or b.reason)
                diffs[key] += 1
                examples.setdefault(key, {"subject": s["canonical_id"], "resource": r["canonical_id"],
                                          "action": action, "workflow": wf, "risk": risk, "auth_strength": auth,
                                          "approval": appr, "secondary": sec, "time": tname,
                                          "legacy_reason": a.reason, "psl_reason": b.reason,
                                          "psl_matched": b.matched_policy_ids})
    return {"requests": total, "same_decision": same, "different_decision": total - same,
            "seconds": round(time.perf_counter() - t0, 1),
            "corpus": {"subjects": len(subjects), "resource_actions": sum(len(r["actions"]) for r in resources),
                       "workflows": wfs, "risk_levels": list(risks), "auth_strengths": list(auths),
                       "approval_combinations": len(approvals), "decision_times": list(times)},
            "legacy_policy_version": legacy.bundle.version, "psl_policy_version": new.bundle.version,
            "outcomes": {k: dict(v) for k, v in by_outcome.items()},
            "differences": [{"legacy": k[0], "psl": k[1], "legacy_policy": k[2], "psl_policy": k[3], "count": c,
                             "example": examples[k]} for k, c in sorted(diffs.items(), key=lambda x: -x[1])],
            "obligation_differences": [{"legacy_policy": k[0], "psl_permits_and_violations": list(k[1]),
                                        "added_in_psl": list(k[2]), "removed_in_psl": list(k[3]), "count": c}
                                       for k, c in sorted(obligation_diffs.items(), key=lambda x: -x[1])]}


def _obligation_label(o: Any) -> str:
    params = json.dumps(o.parameters, sort_keys=True)
    return o.type if params == "{}" else f"{o.type}{params}"


def to_markdown(r: dict[str, Any]) -> str:
    lines = ["# Differential report: legacy priority engine vs PSL deny-overrides", "",
             "Generated by `zero_trust_pdp_task4_secure/scripts/psl_differential_report.py`. Both engines receive the "
             "same verified security context; differences come from the policy semantics only.", "",
             f"* corpus: {r['corpus']['subjects']} identities x {r['corpus']['resource_actions']} (resource, action) x "
             f"{len(r['corpus']['workflows'])} workflows x {len(r['corpus']['risk_levels'])} risk levels x "
             f"{len(r['corpus']['auth_strengths'])} auth strengths x {r['corpus']['approval_combinations']} approval "
             f"combinations x {len(r['corpus']['decision_times'])} decision times = **{r['requests']:,} requests** "
             f"({r['seconds']} s)",
             f"* legacy policy version `{r['legacy_policy_version']}`, PSL policy version `{r['psl_policy_version']}`",
             f"* same decision: **{r['same_decision']:,}**; different decision: **{r['different_decision']:,}**", "",
             "| outcome | legacy | PSL |", "|---|---|---|"]
    for k in ("ALLOW", "ALLOW_WITH_OBLIGATIONS", "MANUAL_REVIEW", "REAUTHENTICATE", "DENY"):
        lines.append(f"| {k} | {r['outcomes']['legacy'].get(k, 0):,} | {r['outcomes']['psl'].get(k, 0):,} |")
    lines += ["", "## Decision differences", ""]
    if not r["differences"]:
        lines.append("None: the PSL policy set reproduces every legacy decision on this corpus.")
    else:
        lines += ["| legacy | PSL | legacy deciding policy | PSL deciding rule | requests | example |",
                  "|---|---|---|---|---|---|"]
        for d in r["differences"]:
            e = d["example"]
            ex = (f"{e['subject']} {e['action']} {e['resource']} wf=`{e['workflow']}` risk={e['risk']} "
                  f"auth={e['auth_strength']} appr={int(e['approval'])}/{int(e['secondary'])} {e['time']}")
            lines.append(f"| {d['legacy']} | {d['psl']} | `{d['legacy_policy']}` | `{d['psl_policy']}` | "
                         f"{d['count']:,} | {ex} |")
    lines += ["", "## Obligation differences (same decision)", ""]
    if not r["obligation_differences"]:
        lines.append("None.")
    else:
        added = Counter()
        removed = Counter()
        for d in r["obligation_differences"]:
            for x in d["added_in_psl"]:
                added[x] += d["count"]
            for x in d["removed_in_psl"]:
                removed[x] += d["count"]
        fmt = lambda c: ", ".join(f"`{k}` ({v:,} requests)" for k, v in sorted(c.items())) or "none"  # noqa: E731
        lines += [f"Obligations added by PSL: {fmt(added)}. Obligations removed by PSL: {fmt(removed)}.", "",
                  "| legacy deciding policy | PSL permits / violations | added in PSL | removed in PSL | requests |",
                  "|---|---|---|---|---|"]
        for d in r["obligation_differences"]:
            lines.append(f"| `{d['legacy_policy']}` | {', '.join(f'`{x}`' for x in d['psl_permits_and_violations'])} "
                         f"| {', '.join(f'`{x}`' for x in d['added_in_psl']) or '-'} "
                         f"| {', '.join(f'`{x}`' for x in d['removed_in_psl']) or '-'} | {d['count']:,} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--legacy", default=str(ROOT / "legacy_policy_store"))
    ap.add_argument("--psl", default=str(ROOT / "policy_store"))
    ap.add_argument("--config", default=str(ROOT / "config"))
    ap.add_argument("--out-md", default=str(ROOT.parent / "docs" / "PSL_DIFFERENTIAL_REPORT.md"))
    ap.add_argument("--out-json", default=str(ROOT.parent / "docs" / "psl_differential_task4.json"))
    ns = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        translated = store_without(Path(ns.psl), ("intent.psl",), Path(tmp))
        r = run(Path(ns.legacy), translated, Path(ns.config))
    r_int = run(Path(ns.legacy), Path(ns.psl), Path(ns.config))
    Path(ns.out_json).write_text(json.dumps({"translation": r, "with_intent": r_int}, indent=1, default=str) + "\n",
                                 encoding="utf-8")
    title = "# Differential report: legacy priority engine vs PSL deny-overrides"
    md1 = to_markdown(r).replace(title, title + "\n\n## Part 1 -- translated Task 4 policies (policy_store without "
                                 "intent.psl)")
    md2 = to_markdown(r_int).replace(title, "## Part 2 -- with the natural-language intent rules (intent.psl) "
                                     "enforced\n\nEvery difference below must come from an `intent.*` rule and must "
                                     "be stricter than the legacy decision.")
    Path(ns.out_md).write_text(md1 + "\n" + md2, encoding="utf-8")
    for name, x in (("translation", r), ("with intent", r_int)):
        print(f"{name}: {x['requests']} requests, {x['different_decision']} different "
              f"({len(x['differences'])} kinds), {len(x['obligation_differences'])} obligation-difference kinds, "
              f"{x['seconds']} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
