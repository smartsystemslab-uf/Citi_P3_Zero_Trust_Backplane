#!/usr/bin/env python3
"""Decision latency: legacy YAML priority engine vs PSL deny-overrides engine.

Both engines are the real PDP policy engines (registry resolution, policy evaluation,
response construction) fed the SAME prepared VerifiedSecurityContext (stub verifier, as in
the differential report), so the measured difference is the policy representation and
evaluation alone; signature / evidence verification is identical code for both and is not
included. Requests: a stratified slice of the differential corpus. Each round times every
request on both engines; the order of the engines alternates between rounds.

    python scripts/psl_performance_report.py [--native-out <native bootstrap output dir>]
"""
from __future__ import annotations

import argparse
import importlib.util
import itertools
import json
import os
import platform
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
BACKPLANE = ROOT.parents[1]                  # repository root
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(BACKPLANE))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


diff = _load("psl_differential_report")

from zt_pdp.models import PDPRequest, RiskLevel, VerifiedSecurityContext  # noqa: E402

RISKS = ("low", "high")
AUTHS = (1, 2)
APPROVALS = ((False, False), (True, True))


def corpus(legacy_dir: Path, psl_dir: Path, config: Path) -> list[tuple[PDPRequest, VerifiedSecurityContext]]:
    ident = yaml.safe_load((config / "identities.yaml").read_text(encoding="utf-8"))
    res = yaml.safe_load((config / "resources.yaml").read_text(encoding="utf-8"))
    subjects = ident.get("identities", ident)
    resources = res.get("resources", res)
    out = []
    for s, r, wf in itertools.product(subjects, resources, diff.workflows(legacy_dir, psl_dir)):
        for action in r["actions"]:
            req = PDPRequest.model_validate({
                "request_id": "perf", "trace_id": "perf",
                "subject": {"canonical_id": s["canonical_id"], "runtime_id": s["id"], "identity_evidence": {}},
                "resource": {"canonical_id": r["canonical_id"], "runtime_id": r["id"]},
                "action": action,
                "context": {"workflow_id": wf or None, "risk": "low", "timestamp": diff.TIMES["business_hours"],
                            "environment": "test"},
                "parameters": {}})
            for risk, auth, (appr, sec), tname in itertools.product(RISKS, AUTHS, APPROVALS, tuple(diff.TIMES)):
                out.append((req, VerifiedSecurityContext(
                    decision_time=diff.TIMES[tname], identity_verified=True, identity_issuer="perf", request_jti="j",
                    request_nonce="n", identity_version="1", risk_verified=True, risk_issuer="perf",
                    risk_score=diff.RISK_SCORE[risk], risk_level=RiskLevel(risk), risk_version="1",
                    auth_verified=True, auth_issuer="perf", auth_strength=auth, workflow_verified=bool(wf),
                    approval_valid=appr, secondary_authorization_valid=sec)))
    return out


def _timed(engine: Any, sv: Any, reqs: list) -> list[int]:
    ts = []
    pc = time.perf_counter_ns
    for req, ctx in reqs:
        sv.ctx = ctx
        t = pc()
        engine.evaluate(req)
        ts.append(pc() - t)
    return ts


def _stats(ns: list[int]) -> dict[str, float]:
    s = sorted(ns)
    q = lambda p: s[min(len(s) - 1, int(p * len(s)))] / 1e3  # noqa: E731
    return {"mean_us": round(statistics.fmean(s) / 1e3, 2), "p50_us": round(q(0.50), 2), "p95_us": round(q(0.95), 2),
            "p99_us": round(q(0.99), 2), "max_us": round(s[-1] / 1e3, 1),
            "decisions_per_s": round(len(s) / (sum(s) / 1e9))}


def measure(label: str, legacy_dir: Path, psl_dir: Path, config: Path, rounds: int) -> dict[str, Any]:
    legacy, new, sv_old, sv_new = diff.build_engines(legacy_dir, psl_dir, config)
    reqs = corpus(legacy_dir, psl_dir, config)
    _timed(legacy, sv_old, reqs[:2000])                    # warm-up
    _timed(new, sv_new, reqs[:2000])
    lt: list[int] = []
    pt: list[int] = []
    for i in range(rounds):
        if i % 2 == 0:
            lt += _timed(legacy, sv_old, reqs)
            pt += _timed(new, sv_new, reqs)
        else:
            pt += _timed(new, sv_new, reqs)
            lt += _timed(legacy, sv_old, reqs)
    sl, sp = _stats(lt), _stats(pt)
    n_legacy = sum(len(b.get("policies", [])) for b in
                   (yaml.safe_load(p.read_text(encoding="utf-8")) or {} for p in legacy_dir.glob("*.yaml")))
    return {"label": label, "requests": len(reqs), "rounds": rounds, "samples_per_engine": len(lt),
            "legacy_policies": n_legacy,
            "psl_rules": len([r for r in new.bundle.policy_set.rules if r.scope == "pdp_request"]),
            "legacy": sl, "psl": sp,
            "psl_vs_legacy_mean": round(sp["mean_us"] / sl["mean_us"], 3),
            "psl_vs_legacy_p99": round(sp["p99_us"] / sl["p99_us"], 3)}


def to_markdown(parts: list[dict[str, Any]], env: dict[str, Any]) -> str:
    lines = ["# Decision latency: legacy YAML engine vs PSL engine", "",
             "Generated by `packages/zt-pdp/scripts/psl_performance_report.py`. Both engines are the real "
             "PDP policy engines and receive the same prepared verified security context, so the numbers compare policy "
             "representation and evaluation only (evidence / signature verification and decision signing are the same "
             "code for both and are excluded). Each round times every request on both engines; the engine order "
             "alternates between rounds.", "",
             f"Host: {env['platform']}, Python {env['python']}, {env['cpus']} logical CPUs; generated {env['generated']}.",
             ""]
    for p in parts:
        lines += [f"## {p['label']}", "",
                  f"* {p['requests']:,} requests x {p['rounds']} rounds = {p['samples_per_engine']:,} decisions per engine",
                  f"* legacy: {p['legacy_policies']} YAML policies; PSL: {p['psl_rules']} compiled rules in scope "
                  f"`pdp_request` (incl. default deny)", "",
                  "| engine | mean us | p50 us | p95 us | p99 us | max us | decisions/s |", "|---|---|---|---|---|---|---|"]
        for k in ("legacy", "psl"):
            s = p[k]
            lines.append(f"| {k} | {s['mean_us']} | {s['p50_us']} | {s['p95_us']} | {s['p99_us']} | {s['max_us']} | "
                         f"{s['decisions_per_s']:,} |")
        lines += ["", f"PSL / legacy: mean x{p['psl_vs_legacy_mean']}, p99 x{p['psl_vs_legacy_p99']}.", ""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--native-out", default=None, help="native runtime bootstrap output dir (adds the native store)")
    ap.add_argument("--out-md", default=str(BACKPLANE / "docs" / "PSL_PERFORMANCE_REPORT.md"))
    ap.add_argument("--out-json", default=str(BACKPLANE / "docs" / "psl_performance.json"))
    ns = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        same_content = diff.store_without(ROOT / "policy_store", ("intent.psl", "identity.psl"), Path(tmp))
        parts = [measure("PDP policies, same content (PSL store without the new intent / identity rules)",
                         ROOT / "legacy_policy_store", same_content, ROOT / "config", ns.rounds)]
    parts.append(measure("PDP policy store as deployed (PSL incl. intent and identity rules)",
                         ROOT / "legacy_policy_store", ROOT / "policy_store", ROOT / "config", ns.rounds))
    if ns.native_out:
        nd = _load("psl_native_differential")
        out = Path(ns.native_out)
        with tempfile.TemporaryDirectory() as tmp:
            legacy = Path(tmp) / "legacy_native_store"
            nd.build_legacy_native_store(legacy, out)
            parts.append(measure("Native MAS runtime store (PDP + generated least-privilege policies)", legacy,
                                 out / "pdp_policy_store", out / "pdp_config", ns.rounds))
    env = {"platform": platform.platform(), "python": platform.python_version(), "cpus": os.cpu_count(),
           "generated": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    Path(ns.out_json).write_text(json.dumps({"environment": env, "parts": parts}, indent=1) + "\n", encoding="utf-8")
    Path(ns.out_md).write_text(to_markdown(parts, env), encoding="utf-8")
    for p in parts:
        print(p["label"], json.dumps({"legacy": p["legacy"], "psl": p["psl"], "ratio_mean": p["psl_vs_legacy_mean"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
