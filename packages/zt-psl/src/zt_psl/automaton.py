"""Property -> monitor automaton.

1. Alphabet. A scope's trace is a sequence of trusted events, exactly one event
   per step ("event-driven sampling"). Atomic propositions (APs) are the event
   names (true only at a step whose event is that name) and data APs (booleans
   computed by the PEP from trusted checks; defined only for the events listed
   in the event model, false otherwise). The letters of a property are the
   distinct valuations of the APs it uses over all events of its scope.

2. States. Formula progression from the desugared property (psl.core.progress),
   with ACI normalisation, explored breadth-first over the letters. The set of
   residual formulas is finite for the supported subset.

3. Verdicts per state (LTL3-style, see PSL_SUPPORTED_SUBSET.md section 3):
     VIOLATED  -- no infinite continuation satisfies the property (bad prefix)
     SATISFIED -- every infinite continuation satisfies it (good prefix)
     PENDING   -- otherwise.
   Computed exactly on the progression graph read as a generalised Buechi
   automaton whose acceptance sets are "strong obligation o is absent or
   discharged" (strong until / eventually! / before!).
   CLOSE value per state: neutral finite-path semantics when the scope is closed
   (weak operators hold, unmet strong obligations fail).

4. Minimisation (Moore partition refinement on (verdict, close)).
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any

from .ast import Core, FF, TT
from .core import core_aps, end_value, progress, strong_obligations

VIOLATED, SATISFIED, PENDING = "V", "S", "P"


@dataclass
class EventModelScope:
    name: str
    events: dict[str, list[str]]           # event -> data APs defined at that event
    data_aps: set[str]

    def all_aps(self) -> set[str]:
        return set(self.events) | self.data_aps


@dataclass
class Monitor:
    property_id: str
    vunit: str
    scope: str
    source: str
    psl_file: str
    line: int
    core_text: str
    aps: list[str]
    letters: list[dict[str, bool]]
    letter_of: dict[str, dict[str, int]]   # event -> bit string over data_for_event[event] -> letter
    data_for_event: dict[str, list[str]]   # event -> used data APs (order of letter_of keys)
    initial: int
    delta: list[list[int]]                 # [state][letter] -> state
    verdict: list[str]
    close: list[bool]
    residuals: list[str]
    raw_states: int = 0
    stats: dict[str, Any] = field(default_factory=dict)


def letters_for(scope: EventModelScope, used: set[str]) -> tuple[list[dict[str, bool]], dict[str, dict[str, int]],
                                                                  dict[str, list[str]]]:
    used_events = [e for e in scope.events if e in used]
    letters: list[dict[str, bool]] = []
    index: dict[tuple, int] = {}
    letter_of: dict[str, dict[str, int]] = {}
    data_for_event: dict[str, list[str]] = {}
    for ev in sorted(scope.events):
        dused = sorted(d for d in scope.events[ev] if d in used)
        data_for_event[ev] = dused
        letter_of[ev] = {}
        for bits in itertools.product((False, True), repeat=len(dused)):
            val = {e: (e == ev) for e in used_events}
            val.update({d: False for d in used if d in scope.data_aps})
            val.update(dict(zip(dused, bits)))
            k = tuple(sorted(val.items()))
            if k not in index:
                index[k] = len(letters)
                letters.append(val)
            letter_of[ev]["".join("1" if b else "0" for b in bits)] = index[k]     # bits in data_for_event order
    return letters, letter_of, data_for_event


def _sccs(n: int, succ: list[list[int]]) -> list[list[int]]:
    index = [-1] * n
    low = [0] * n
    on = [False] * n
    stack: list[int] = []
    out: list[list[int]] = []
    counter = 0
    for root in range(n):
        if index[root] != -1:
            continue
        work = [(root, 0)]
        while work:
            v, pi = work.pop()
            if pi == 0:
                index[v] = low[v] = counter
                counter += 1
                stack.append(v)
                on[v] = True
            recurse = False
            for i in range(pi, len(succ[v])):
                w = succ[v][i]
                if index[w] == -1:
                    work.append((v, i + 1))
                    work.append((w, 0))
                    recurse = True
                    break
                if on[w]:
                    low[v] = min(low[v], index[w])
            if recurse:
                continue
            if low[v] == index[v]:
                comp = []
                while True:
                    w = stack.pop()
                    on[w] = False
                    comp.append(w)
                    if w == v:
                        break
                out.append(comp)
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[v])
    return out


def _reach(starts: list[int], succ: list[list[int]]) -> set[int]:
    seen = set(starts)
    todo = list(starts)
    while todo:
        v = todo.pop()
        for w in succ[v]:
            if w not in seen:
                seen.add(w)
                todo.append(w)
    return seen


def build(property_id: str, vunit: str, scope: EventModelScope, core: Core, *, source: str, psl_file: str,
          line: int, max_states: int = 5000) -> Monitor:
    used = set(core_aps(core))
    unknown = used - scope.all_aps()
    if unknown:
        raise ValueError(f"{property_id}: atomic propositions not declared in scope '{scope.name}': {sorted(unknown)}")
    letters, letter_of, data_for_event = letters_for(scope, used)

    # --- progression graph -------------------------------------------------
    states: list[Core] = [core]
    ids: dict[tuple, int] = {core.key(): 0}
    delta: list[list[int]] = []
    disch: list[list[set[tuple]]] = []        # per state, per letter: strong obligations discharged
    i = 0
    while i < len(states):
        f = states[i]
        row, drow = [], []
        obl = strong_obligations(f)
        for val in letters:
            g = progress(f, val)
            k = g.key()
            if k not in ids:
                if len(states) >= max_states:
                    raise ValueError(f"{property_id}: more than {max_states} monitor states")
                ids[k] = len(states)
                states.append(g)
            row.append(ids[k])
            drow.append({o.key() for o in obl if isinstance(progress(o, val), TT)})
        delta.append(row)
        disch.append(drow)
        i += 1
    n = len(states)
    succ = [sorted(set(r)) for r in delta]
    obls = [{o.key() for o in strong_obligations(f)} for f in states]
    is_ff = [isinstance(f, FF) for f in states]

    # --- satisfiability (exists accepted infinite run) ----------------------
    accepting_scc_nodes: set[int] = set()
    for comp in _sccs(n, succ):
        cs = set(comp)
        if any(is_ff[v] for v in comp):
            continue
        internal = [(v, li) for v in comp for li, w in enumerate(delta[v]) if w in cs]
        if not internal:
            continue
        need = set().union(*(obls[v] for v in comp))
        ok = all(any((o not in obls[v]) or (o in disch[v][li]) for v, li in internal) for o in need)
        if ok:
            accepting_scc_nodes |= cs
    # SAT(q): q reaches an accepting SCC
    pred: list[list[int]] = [[] for _ in range(n)]
    for v in range(n):
        for w in succ[v]:
            pred[w].append(v)
    sat = _reach(list(accepting_scc_nodes), pred)

    # --- validity (every infinite run accepted) ----------------------------
    reaches_ff = _reach([v for v in range(n) if is_ff[v]], pred)
    bad_cycle_nodes: set[int] = set()
    all_obls = set().union(*obls) if obls else set()
    for o in all_obls:
        sub: list[list[int]] = [[] for _ in range(n)]
        for v in range(n):
            if o not in obls[v]:
                continue
            for li, w in enumerate(delta[v]):
                if o not in disch[v][li] and not is_ff[w] and o in obls[w]:
                    sub[v].append(w)
        for comp in _sccs(n, sub):
            cs = set(comp)
            if any(w in cs for v in comp for w in sub[v]):
                bad_cycle_nodes |= cs
    reaches_bad_cycle = _reach(list(bad_cycle_nodes), pred)
    verdict = []
    for v in range(n):
        if v not in sat:
            verdict.append(VIOLATED)
        elif v not in reaches_ff and v not in reaches_bad_cycle:
            verdict.append(SATISFIED)
        else:
            verdict.append(PENDING)
    close = [end_value(f) for f in states]

    # --- Moore minimisation ------------------------------------------------
    block = {v: (verdict[v], close[v]) for v in range(n)}
    while True:
        sig = {v: (block[v], tuple(block[w] for w in delta[v])) for v in range(n)}
        names: dict[tuple, int] = {}
        new = {v: names.setdefault(sig[v], len(names)) for v in range(n)}
        if len(set(new.values())) == len(set(block.values())):
            block = new
            break
        block = new
    # renumber so that the initial state is 0 and order follows BFS
    order: dict[int, int] = {}
    todo = [block[0]]
    rep: dict[int, int] = {}
    for v in range(n):
        rep.setdefault(block[v], v)
    while todo:
        b = todo.pop(0)
        if b in order:
            continue
        order[b] = len(order)
        for w in delta[rep[b]]:
            if block[w] not in order:
                todo.append(block[w])
    m = len(order)
    mdelta = [[0] * len(letters) for _ in range(m)]
    mverdict = [""] * m
    mclose = [False] * m
    mres = [""] * m
    for b, idx in order.items():
        v = rep[b]
        mverdict[idx] = verdict[v]
        mclose[idx] = close[v]
        mres[idx] = str(states[v])
        for li, w in enumerate(delta[v]):
            mdelta[idx][li] = order[block[w]]
    return Monitor(property_id=property_id, vunit=vunit, scope=scope.name, source=source, psl_file=psl_file,
                   line=line, core_text=str(core), aps=sorted(used), letters=letters, letter_of=letter_of,
                   data_for_event=data_for_event, initial=0, delta=mdelta, verdict=mverdict, close=mclose,
                   residuals=mres, raw_states=n,
                   stats={"letters": len(letters), "raw_states": n, "states": m})
