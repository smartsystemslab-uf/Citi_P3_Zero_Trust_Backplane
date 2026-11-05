"""Verification of the gateway's audit trails (host side, on runtime/state/gateway).

* zt-adk audit (``audit.jsonl``): hash chain, events by type and decision
* PDP decision log (``pdp_decisions.jsonl``): hash chain, decisions by outcome
* gateway PSL audit (``psl_audit.jsonl``): every executed tool call has a correlated pre-execution
  record (same attempt, request, agent, workload, tool, argument digest, run, permit), its permit
  appears in the zt-adk audit, outcomes by layer and the monitors' violations

    python -m zt_distributed.verify_state runtime/state/gateway
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

CORR_FIELDS = ("attempt_id", "request_id", "agent", "workload", "tool", "args_sha256", "workflow_run_id",
               "permit_id", "auth_mode")


def _lines(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def verify(state_dir: Path) -> dict[str, Any]:
    from zt_adk.audit import verify_chain
    from zt_backplane.audit import ChainedAuditLogger

    out: dict[str, Any] = {}
    audit_path = state_dir / "audit.jsonl"
    recs = _lines(audit_path)
    out["audit"] = {"chain": verify_chain(audit_path) if audit_path.exists() else None,
                    "by_event": dict(Counter(r["event"] for r in recs)),
                    "denials_by_event": dict(Counter(r["event"] for r in recs if r.get("allowed") is False))}
    dec_path = state_dir / "pdp_decisions.jsonl"
    decisions = _lines(dec_path)
    out["pdp_decision_log"] = {"records": len(decisions),
                               "hash_chain_valid": bool(ChainedAuditLogger(dec_path).verify_chain())
                               if dec_path.exists() else None,
                               "by_decision": dict(Counter(d.get("decision") for d in decisions))}
    psl = _lines(state_dir / "psl_audit.jsonl")
    pre = {r["attempt_id"]: r for r in psl if r.get("phase") == "pre_execution"}
    outs = [r for r in psl if r.get("phase") == "outcome"]
    executed = [r for r in outs if r.get("outcome") in ("succeeded", "failed")]
    permits = {r.get("permit_id") for r in recs if r.get("event") == "TOOL_AUTHORIZATION" and r.get("permit_id")}
    viol: Counter = Counter()
    for r in outs:
        for v in r.get("psl_violations") or []:
            viol[v["property_id"]] += 1
    out["psl_audit"] = {
        "records": len(psl), "pre_execution": len(pre), "outcomes": len(outs), "executed": len(executed),
        "outcomes_by_result": dict(Counter(r.get("outcome") for r in outs)),
        "denials_by_layer": dict(Counter(r.get("layer") for r in outs if r.get("outcome") == "denied")),
        "executed_by_tool": dict(Counter(r.get("tool") for r in executed)),
        "executed_with_correlated_pre_record": sum(
            1 for r in executed if r["attempt_id"] in pre and all(pre[r["attempt_id"]].get(f) == r.get(f)
                                                                  for f in CORR_FIELDS)),
        "executed_permit_in_audit": sum(1 for r in executed if r.get("permit_id") in permits),
        "pre_without_outcome": len(set(pre) - {r["attempt_id"] for r in outs}),
        "violations_by_property": dict(viol),
    }
    a, p = out["audit"]["chain"], out["psl_audit"]
    out["ok"] = bool((a is None or a.get("ok")) and out["pdp_decision_log"]["hash_chain_valid"] is not False
                     and p["executed_with_correlated_pre_record"] == p["executed"]
                     and p["executed_permit_in_audit"] == p["executed"] and p["pre_without_outcome"] == 0)
    return out


def main() -> int:
    state = Path(sys.argv[1] if len(sys.argv) > 1 else "runtime/state/gateway")
    result = verify(state)
    print(json.dumps(result, indent=1, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
