"""Runtime execution of the generated PSL monitors.

* PropertyMachine -- executes one generated table (letter lookup + transition).
* MonitorRuntime  -- parametric slicing: one monitor instance (a vector of
  property states) per scope key; per-slice locks; atomic "check and commit"
  for controllable events (admission); explicit capacity limits (a new slice
  that does not fit is REJECTED, live state is never evicted); closing a scope
  computes the neutral-semantics close verdicts.

Verdicts: S = satisfied (good prefix), P = pending, V = violated (bad prefix).
"""
from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

SATISFIED, PENDING, VIOLATED = "S", "P", "V"


class MonitorStale(RuntimeError):
    pass


class CapacityExceeded(RuntimeError):
    def __init__(self, scope: str, limit: int) -> None:
        super().__init__(f"PSL monitor capacity exhausted for scope {scope} (limit {limit})")
        self.scope = scope
        self.limit = limit


class PropertyMachine:
    __slots__ = ("pid", "scope", "source", "psl_file", "line", "delta", "verdict", "close", "letter_of",
                 "data_for_event", "initial", "vunit")

    def __init__(self, d: Mapping[str, Any]) -> None:
        self.pid: str = d["property_id"]
        self.scope: str = d["scope"]
        self.vunit: str = d["vunit"]
        self.source: str = d["source"]
        self.psl_file: str = d["psl_file"]
        self.line: int = d["line"]
        self.delta: list[list[int]] = d["delta"]
        self.verdict: str = d["verdict"]
        self.close: list[int] = d["close"]
        self.initial: int = d["initial"]
        self.data_for_event: dict[str, list[str]] = d["data_for_event"]
        # event -> tuple(data bits) -> letter
        self.letter_of: dict[str, dict[tuple, int]] = {}
        for ev, table in d["letter_of"].items():
            out: dict[tuple, int] = {}
            for k, li in table.items():
                bits = tuple(int(c) for c in k)
                out[bits] = li
            self.letter_of[ev] = out

    def letter(self, event: str, data: Mapping[str, bool]) -> int:
        try:
            table = self.letter_of[event]
        except KeyError as exc:
            raise KeyError(f"event {event!r} is not in scope {self.scope}") from exc
        bits = tuple(1 if data.get(d) else 0 for d in self.data_for_event[event])
        return table[bits]

    def step(self, state: int, event: str, data: Mapping[str, bool]) -> int:
        return self.delta[state][self.letter(event, data)]


def runtime_data(policy_set: Any, runtime: str, scopes: Iterable[str] | None = None) -> dict[str, Any]:
    """Monitor tables of the temporal rules of ``policy_set`` evaluated by ``runtime``
    (optionally only those of ``scopes``)."""
    from .compiler import monitor_to_dict
    wanted = set(scopes) if scopes is not None else None
    mons = [monitor_to_dict(r.monitor) for r in policy_set.rules
            if r.kind == "temporal" and runtime in r.runtimes and r.monitor is not None and not r.disabled
            and (wanted is None or r.scope in wanted)]
    return {"mode": runtime, "source_sha256": policy_set.digest, "monitors": mons}


@dataclass
class Slice:
    scope: str
    key: tuple
    states: list[int]
    lock: threading.Lock = field(default_factory=threading.Lock)
    created: float = field(default_factory=time.monotonic)
    steps: int = 0
    trace: list[tuple[str, tuple]] | None = None
    closed: bool = False


@dataclass
class Violation:
    property_id: str
    scope: str
    key: tuple
    event: str
    when: str            # "admission" (prevented) | "step" (detected) | "close" (detected at close)
    source: str


@dataclass
class StepResult:
    ok: bool
    violations: list[Violation]
    lock_wait_ns: int = 0
    check_ns: int = 0


class MonitorRuntime:
    """Executes the temporal rules of a policy set. Events carry field values; the
    scope binder turns them into the data APs each machine reads at that event
    (APs of fields not defined at the event are false)."""

    @classmethod
    def from_policy_set(cls, policy_set: Any, runtime: str, *, scopes: Iterable[str] | None = None,
                        **kw: Any) -> "MonitorRuntime":
        rt = cls(runtime_data(policy_set, runtime, scopes), **kw)
        rt.attach_catalog(policy_set)
        return rt

    def attach_catalog(self, policy_set: Any) -> None:
        """One binder per (scope, event): it computes exactly the data APs the
        machines read at that event (``data_for_event``)."""
        from .fields import Binder
        self._binders: dict[str, dict[str, Any]] = {}
        for scope, machines in self.machines.items():
            sc = policy_set.catalog.scopes[scope]
            per_event = {}
            for ev in sc.events:
                names = sorted({d for m in machines for d in m.data_for_event.get(ev, [])})
                per_event[ev] = Binder(sc, [_atom_from_ap(n) for n in names])
            self._binders[scope] = per_event

    def bind(self, scope: str, event: str, fields: Mapping[str, Any]) -> dict[str, bool]:
        try:
            binder = self._binders[scope][event]
        except (AttributeError, KeyError) as exc:
            raise KeyError(f"event {event!r} is not in scope {scope} (or no catalogue attached)") from exc
        return binder.bind(event, fields)

    def __init__(self, data: Mapping[str, Any], *, capacity: Mapping[str, int] | None = None,
                 keep_traces: bool = False) -> None:
        self.mode = data["mode"]
        self.source_sha256 = data["source_sha256"]
        self.machines: dict[str, list[PropertyMachine]] = {}
        for d in data["monitors"]:
            m = PropertyMachine(d)
            self.machines.setdefault(m.scope, []).append(m)
        self.capacity = dict(capacity or {})
        self.slices: dict[str, dict[tuple, Slice]] = {s: {} for s in self.machines}
        self._table_lock = threading.Lock()
        self._metrics_lock = threading.Lock()     # observe/admit run on the event loop and in tool threads
        self.keep_traces = keep_traces
        self.metrics: dict[str, int] = {"steps": 0, "admissions": 0, "admission_denied": 0, "violations_detected": 0,
                                        "close_violations": 0, "capacity_rejections": 0, "lock_wait_ns": 0,
                                        "check_ns": 0, "slices_created": 0, "slices_closed": 0}
        self.max_live: dict[str, int] = {s: 0 for s in self.machines}

    # -- slices -------------------------------------------------------------
    def get_slice(self, scope: str, key: tuple, *, create: bool = True) -> Slice | None:
        table = self.slices[scope]
        s = table.get(key)
        if s is not None or not create:
            return s
        with self._table_lock:
            s = table.get(key)
            if s is None:
                limit = self.capacity.get(scope)
                if limit is not None and len(table) >= limit:
                    self.metrics["capacity_rejections"] += 1
                    raise CapacityExceeded(scope, limit)
                s = Slice(scope, key, [m.initial for m in self.machines[scope]],
                          trace=[] if self.keep_traces else None)
                table[key] = s
                self.metrics["slices_created"] += 1
                if len(table) > self.max_live[scope]:
                    self.max_live[scope] = len(table)
        return s

    def live_counts(self) -> dict[str, int]:
        return {s: len(t) for s, t in self.slices.items()}

    # -- stepping -----------------------------------------------------------
    def _advance(self, sl: Slice, event: str, data: Mapping[str, bool]) -> tuple[list[int], list[PropertyMachine]]:
        new = []
        newly_violated = []
        for m, st in zip(self.machines[sl.scope], sl.states):
            nxt = m.step(st, event, data)
            new.append(nxt)
            if m.verdict[nxt] == VIOLATED and m.verdict[st] != VIOLATED:
                newly_violated.append(m)
        return new, newly_violated

    def _add(self, **inc: int) -> None:
        with self._metrics_lock:
            for k, v in inc.items():
                self.metrics[k] += v

    def observe(self, targets: Iterable[tuple[str, tuple, str, Mapping[str, bool]]]) -> StepResult:
        """Record observed events (not preventable). Violations are DETECTED and reported."""
        viols: list[Violation] = []
        lw = ck = 0
        for scope, key, event, data in targets:
            sl = self.get_slice(scope, key)
            assert sl is not None
            t0 = time.perf_counter_ns()
            with sl.lock:
                t1 = time.perf_counter_ns()
                new, bad = self._advance(sl, event, data)
                sl.states = new
                sl.steps += 1
                if sl.trace is not None:
                    sl.trace.append((event, tuple(sorted(k for k, v in data.items() if v))))
                t2 = time.perf_counter_ns()
            lw += t1 - t0
            ck += t2 - t1
            for m in bad:
                viols.append(Violation(m.pid, scope, key, event, "step", m.source))
        self._add(steps=1, lock_wait_ns=lw, check_ns=ck, violations_detected=len(viols))
        return StepResult(not viols, viols, lw, ck)

    def admit(self, targets: list[tuple[str, tuple, str, Mapping[str, bool]]]) -> StepResult:
        """Controllable event (execution admission): check all target slices and commit
        ONLY if no property would be violated. Locks of all target slices are taken in a
        canonical order and held only for the in-memory check + commit (no I/O)."""
        sls = []
        for scope, key, event, data in targets:
            sl = self.get_slice(scope, key)
            assert sl is not None
            sls.append((sl, event, data))
        order = sorted(range(len(sls)), key=lambda i: (sls[i][0].scope, repr(sls[i][0].key)))
        t0 = time.perf_counter_ns()
        for i in order:
            sls[i][0].lock.acquire()
        t1 = time.perf_counter_ns()
        try:
            planned = []
            viols: list[Violation] = []
            for sl, event, data in sls:
                new, bad = self._advance(sl, event, data)
                planned.append(new)
                for m in bad:
                    viols.append(Violation(m.pid, sl.scope, sl.key, event, "admission", m.source))
            if not viols:
                for (sl, event, data), new in zip(sls, planned):
                    sl.states = new
                    sl.steps += 1
                    if sl.trace is not None:
                        sl.trace.append((event, tuple(sorted(k for k, v in data.items() if v))))
            t2 = time.perf_counter_ns()
        finally:
            for i in order:
                sls[i][0].lock.release()
        self._add(admissions=1, admission_denied=1 if viols else 0, lock_wait_ns=t1 - t0, check_ns=t2 - t1)
        return StepResult(not viols, viols, t1 - t0, t2 - t1)

    def verdicts(self, scope: str, key: tuple) -> dict[str, str]:
        sl = self.slices[scope].get(key)
        if sl is None:
            return {}
        return {m.pid: m.verdict[st] for m, st in zip(self.machines[scope], sl.states)}

    def close(self, scope: str, key: tuple) -> list[Violation]:
        """Close a scope: final verdicts under neutral finite-path semantics; drop the slice."""
        with self._table_lock:
            sl = self.slices[scope].pop(key, None)
        if sl is None:
            return []
        out = []
        with sl.lock:
            sl.closed = True
            for m, st in zip(self.machines[scope], sl.states):
                if m.verdict[st] == VIOLATED:
                    continue                      # already reported when it happened
                if not m.close[st]:
                    out.append(Violation(m.pid, scope, key, "<close>", "close", m.source))
        self._add(slices_closed=1, close_violations=len(out))
        return out

    def close_where(self, scope: str, pred) -> list[Violation]:
        keys = [k for k in list(self.slices[scope]) if pred(k)]
        out: list[Violation] = []
        for k in keys:
            out += self.close(scope, k)
        return out

    def snapshot(self) -> dict[str, Any]:
        return {"mode": self.mode, "source_sha256": self.source_sha256[:16], "live": self.live_counts(),
                "max_live": dict(self.max_live), "capacity": self.capacity, "metrics": dict(self.metrics)}


def _atom_from_ap(name: str):
    """Inverse of BCmp.ap for data AP names used by monitors."""
    from .ast import BAtom, BCmp, CMP_OPS
    parts = name.split(" ", 2)
    if len(parts) == 3 and parts[1] in CMP_OPS:
        fld, op, lit = parts
        if lit.startswith('"'):
            val: Any = lit[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        elif lit in ("true", "false"):
            val = lit == "true"
        else:
            val = int(lit)
        return BCmp(fld, op, val)
    return BAtom(name)


def args_digest(args: Mapping[str, Any]) -> str:
    import json
    return hashlib.sha256(json.dumps(args, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
