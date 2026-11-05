"""Shared helpers of the end-to-end tests (host side, Docker deployment of the example service desk)."""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from scripts import stack

ROOT = Path(__file__).resolve().parents[2]             # distributed_runtime/
SESSION = time.strftime("%Y%m%dT%H%M%S")
OUT = ROOT / "results" / "functional" / SESSION
EVIDENCE: dict[str, Any] = {"session": SESSION, "tests": {}}


def record(test: str, **data: Any) -> None:
    EVIDENCE["tests"].setdefault(test, {}).update(data)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "functional_evidence.json").write_text(json.dumps(EVIDENCE, indent=1, default=str), encoding="utf-8")


def converse(*messages: str, role: str = "employee", session_id: str | None = None,
             extra: list[str] | None = None) -> list[dict[str, Any]]:
    args: list[str] = []
    for m in messages:
        args += ["--message", m]
    if role:
        args += ["--role", role]
    if session_id:
        args += ["--session-id", session_id]
    return stack.ingress(*(args + (extra or [])))["results"]


def gateway_audit() -> list[dict[str, Any]]:
    p = stack.STATE / "gateway" / "audit.jsonl"
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()] if p.exists() else []


class Background:
    """A conversation that runs in the background (e.g. one that waits for an approval)."""

    def __init__(self, *messages: str, role: str = "employee") -> None:
        self.result: list[dict[str, Any]] | None = None
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._run, args=(messages, role), daemon=True)
        self.thread.start()

    def _run(self, messages: tuple[str, ...], role: str) -> None:
        try:
            self.result = converse(*messages, role=role)
        except BaseException as exc:  # noqa: BLE001
            self.error = exc

    def join(self, timeout: float = 300) -> list[dict[str, Any]]:
        self.thread.join(timeout)
        if self.error:
            raise self.error
        assert self.result is not None, "conversation did not finish"
        return self.result


def probe(agent_workload: str, *args: str) -> dict[str, Any]:
    """Run zt_distributed.probe inside an agent's workload as that workload's user."""
    dep = stack.deployment()
    w = dep.workload_by_name(agent_workload)
    out = stack.dexec(agent_workload, "python", "-m", "zt_distributed.probe", *args, user=f"{w.uid}:{w.uid}",
                      timeout=120)
    return json.loads([ln for ln in out.splitlines() if ln.startswith("{")][-1])


def assert_psl_clean(state: dict[str, Any], *, expected_violations: set[str] = frozenset()) -> dict[str, Any]:
    """Every executed call has a correlated pre-execution and outcome record and a permit in the
    audit; monitor violations only where a test provoked them (refused admissions)."""
    pa = state["psl_audit"]
    assert pa["pre_without_outcome"] == 0, pa
    assert pa["executed_with_correlated_pre_record"] == pa["executed"], pa
    assert pa["executed_permit_in_audit"] == pa["executed"], pa
    assert set(pa["violations_by_property"]) <= set(expected_violations), pa["violations_by_property"]
    return pa


def python() -> str:
    return sys.executable


def run_cmd(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True)
