"""Shared helpers for the end-to-end functional tests (host side, Docker deployment)."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from scripts import stack
from zt_distributed import catalog

ROOT = Path(__file__).resolve().parents[2]             # distributed_runtime/
SESSION = time.strftime("%Y%m%dT%H%M%S")
OUT = ROOT / "results" / "functional" / SESSION
EVIDENCE: dict[str, Any] = {"session": SESSION, "tests": {}}


def record(test: str, **data: Any) -> None:
    EVIDENCE["tests"].setdefault(test, {}).update(data)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "functional_evidence.json").write_text(json.dumps(EVIDENCE, indent=1, default=str), encoding="utf-8")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


class Ctx:
    def __init__(self, label: str = "b", **start_kwargs: Any) -> None:
        self.label = label
        self.info = stack.start(**start_kwargs)
        self.env = self.info["env_for_runs"]
        self.n = 0

    def run(self, name: str, scenario: str, *, count: int = 2, fresh: bool = True,
            extra: list[str] | None = None, offset: int = 0) -> dict[str, Any]:
        """One ingress burst through the gateway; returns client results, gateway spans,
        gateway stats and the verified state of the run."""
        self.n += 1
        rid = f"{self.label}-{self.n:02d}-{name}"
        d = OUT / self.label / rid
        stack.rotate_live(d / "pre", wait_s=0.2)
        if fresh:
            stack.restart_gateway(self.env)
        args = ["--scenario", scenario, "--count", str(count), "--offset", str(offset),
                f"--run-tag={rid[-12:]}"] + (extra or [])
        client = stack.ingress(*args)
        gw_stats = stack.http_local("zt-gateway", "/stats")
        stack.rotate_live(d)
        state = stack.verify_state(d / "audit")
        d.mkdir(parents=True, exist_ok=True)
        (d / "client.json").write_text(json.dumps(client, indent=1, default=str))
        (d / "state.json").write_text(json.dumps(state, indent=1))
        (d / "gateway_stats.json").write_text(json.dumps(gw_stats, indent=1))
        return {"client": client, "results": client["results"], "gw": read_jsonl(d / "zt-gateway.spans.jsonl"),
                "state": state, "dir": d, "gw_stats": gw_stats, "psl": gw_stats.get("psl")}

    def health(self, agent_service: str) -> dict[str, Any]:
        return stack.http_local(agent_service, "/health")


def svc(agent_id: str) -> str:
    return catalog.AGENTS[agent_id].name


def tool_spans(gw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [g for g in gw if g.get("ep") == "mcp" and g.get("rpc_method") == "tools/call"]


def rejected_spans(gw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [g for g in gw if g.get("ep") == "mcp" and g.get("status") == 401]


def assert_psl_clean(r: dict[str, Any], *, executions: int | None = None,
                     denial_layers: set[str] | None = None) -> dict[str, Any]:
    """The gateway PSL audit of a run: every executed call has a correlated pre-execution
    record and an outcome record, its permit is in the Backplane audit, and no monitor
    reported a violation (denials only from the expected layers)."""
    pa = r["state"].get("psl_audit") or {}
    assert pa, "no PSL audit written"
    assert pa["pre_without_outcome"] == 0, pa
    assert pa["executed_with_correlated_pre_record"] == pa["executed"], pa
    assert pa["executed_permit_in_native_audit"] == pa["executed"], pa
    assert not pa["violations_by_property"], pa["violations_by_property"]
    if executions is not None:
        assert pa["executed"] == executions, pa
    if denial_layers is not None:
        assert set(pa["denials_by_layer"]) <= denial_layers, pa["denials_by_layer"]
    return {"audit": pa, "monitor": {k: v for k, v in (r["psl"] or {}).items() if k in ("metrics", "counters")}}
