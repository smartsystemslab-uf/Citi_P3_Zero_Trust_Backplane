"""Post-run verification of business side effects and audit trails.

Runs in the `ops` helper container (read-only queries). Reports the live databases'
synthetic rows, the Backplane audit by event type/decision, the PDP decision log's hash
chain and the gateway PSL audit (pre-execution / outcome correlation).
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from collections import Counter
from pathlib import Path

from .backplane_adapter import BACKPLANE_ROOT

GOLDEN_BALANCE = 20000 * 50000.0
OUT = Path("/var/lib/zt-gateway/output")
AUDIT = OUT / "native_mas_audit.jsonl"
DECISIONS = OUT / "task4_decision_log.jsonl"
PSL_AUDIT = OUT / "psl_audit.jsonl"
CORR_FIELDS = ("attempt_id", "request_id", "agent", "workload", "tool", "args_sha256", "workflow_run_id",
               "permit_id", "auth_mode")


def ro(path: str) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", default=None, help="directory to store audit excerpts")
    ns = ap.parse_args()
    out: dict = {}
    adk = ro("/var/lib/bankadk/banking.db")
    out["eod_batches_by_status"] = dict(adk.execute(
        "SELECT status, COUNT(*) FROM eod_batches WHERE batch_id LIKE 'EOD-B-%' OR batch_id LIKE 'EOD-M-%' "
        "OR batch_id LIKE 'EOD-N-%' GROUP BY status"))
    out["reports"] = adk.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    out["exceptions"] = adk.execute("SELECT COUNT(*) FROM exceptions").fetchone()[0]
    out["manual_reviews"] = adk.execute("SELECT COUNT(*) FROM manual_reviews").fetchone()[0]
    bank = ro("/var/lib/bank/citi_banking.db")
    out["new_transactions_by_status"] = dict(bank.execute(
        "SELECT status, COUNT(*) FROM transactions WHERE transaction_id LIKE 'TX-%' GROUP BY status"))
    bal = bank.execute("SELECT SUM(balance) FROM accounts WHERE account_id LIKE 'ACC-B%'").fetchone()[0]
    dest = bank.execute("SELECT SUM(balance) FROM accounts WHERE account_id LIKE 'ACC-D%'").fetchone()[0]
    out["source_debited_usd"] = round(GOLDEN_BALANCE - bal, 2)
    out["destination_credited_usd"] = round(dest, 2)

    counts: Counter = Counter()
    gateway_checks: Counter = Counter()
    if AUDIT.exists():
        with AUDIT.open(encoding="utf-8") as fh:
            for line in fh:
                ev = json.loads(line)
                if ev.get("event_type") == "GATEWAY_PSL_CHECK":
                    gateway_checks[f"{ev.get('scope')}:{ev.get('outcome')}"] += 1
                elif "allowed" in ev:
                    counts[f"{ev['event_type']}:{'allow' if ev['allowed'] else 'deny'}:{ev.get('reason', '')[:60]}"] += 1
                else:
                    counts[ev["event_type"]] += 1
    out["native_audit_counts"] = dict(counts)
    out["gateway_psl_checks"] = dict(gateway_checks)

    chain_ok = None
    n_decisions = 0
    decisions: Counter = Counter()
    if DECISIONS.exists():
        sys.path.insert(0, str(BACKPLANE_ROOT / "zero_trust_pdp_task4_secure" / "src"))
        from zt_backplane.audit import ChainedAuditLogger
        chain_ok = bool(ChainedAuditLogger(DECISIONS).verify_chain())
        with DECISIONS.open(encoding="utf-8") as fh:
            for line in fh:
                n_decisions += 1
                decisions[json.loads(line)["decision"]] += 1
    out["pdp_decision_log"] = {"records": n_decisions, "hash_chain_valid": chain_ok, "by_decision": dict(decisions)}

    if PSL_AUDIT.exists():
        out["psl_audit"] = psl_audit_summary()

    if ns.archive:
        dest_dir = Path(ns.archive)
        dest_dir.mkdir(parents=True, exist_ok=True)
        for src in (AUDIT, DECISIONS):
            if not src.exists():
                continue
            lines = src.read_text(encoding="utf-8").splitlines()
            keep = lines if len(lines) <= 400 else lines[:200] + lines[-200:]
            (dest_dir / (src.stem + ".excerpt.jsonl")).write_text("\n".join(keep) + "\n", encoding="utf-8")
        if PSL_AUDIT.exists():
            (dest_dir / "psl_audit.jsonl").write_text(PSL_AUDIT.read_text(encoding="utf-8"), encoding="utf-8")
        os.system(f"chmod -R a+rwX {dest_dir}")
    print(json.dumps(out, sort_keys=True))


def psl_audit_summary() -> dict:
    """Gateway PSL audit: outcomes per layer/tool and correlation integrity (pre-execution
    record, outcome record and the Backplane audit must refer to the same request)."""
    recs = [json.loads(x) for x in PSL_AUDIT.read_text(encoding="utf-8").splitlines() if x.strip()]
    pre = {r["attempt_id"]: r for r in recs if r.get("phase") == "pre_execution"}
    outs = [r for r in recs if r.get("phase") == "outcome"]
    native_permits = set()
    if AUDIT.exists():
        for line in AUDIT.read_text(encoding="utf-8").splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("event_type") == "TOOL_AUTHORIZATION" and e.get("permit_id"):
                native_permits.add(e["permit_id"])
    executed = [r for r in outs if r.get("outcome") in ("succeeded", "failed")]
    corr_ok = sum(1 for r in executed if r["attempt_id"] in pre
                  and all(pre[r["attempt_id"]].get(f) == r.get(f) for f in CORR_FIELDS))
    permit_in_native = sum(1 for r in executed if r.get("permit_id") in native_permits)
    viol: Counter = Counter()
    for r in outs:
        for v in r.get("psl_violations") or []:
            viol[v["property_id"]] += 1
    return {
        "records": len(recs), "pre_execution": len(pre), "outcomes": len(outs),
        "outcomes_by_result": dict(Counter(r.get("outcome") for r in outs)),
        "denials_by_layer": dict(Counter(r.get("layer") for r in outs if r.get("outcome") == "denied")),
        "executed_by_tool": dict(Counter(r.get("tool") for r in executed)),
        "executed_with_correlated_pre_record": corr_ok, "executed": len(executed),
        "executed_permit_in_native_audit": permit_in_native,
        "pre_without_outcome": len(set(pre) - {r["attempt_id"] for r in outs}),
        "violations_by_property": dict(viol),
    }


if __name__ == "__main__":
    main()
