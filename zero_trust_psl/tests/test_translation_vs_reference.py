"""Phase 1b: the generated monitors agree with the independent reference interpreter.

* CLOSE verdicts (neutral finite-path semantics) must be identical on every trace.
* Step verdicts (LTL3): VIOLATED => no lasso extension of the trace satisfies the
  property; SATISFIED => every lasso extension satisfies it; PENDING => at least one
  satisfying and one violating extension exist (searched over a bounded lasso set;
  traces where the bounded search finds only one kind are counted as inconclusive and
  must stay rare).
Randomly generated subset formulas are checked, also over comparison atoms
(Boolean-layer extension); the Backplane's own temporal policies are checked in
test_backplane_policies.py.
"""
from __future__ import annotations

import itertools
import random

import pytest

from zt_psl.automaton import EventModelScope
from zt_psl.compiler import compile_sources
from zt_psl.parser import parse
from zt_psl.reference import holds_finite, holds_lasso, scope_alphabet, surface_aps

RNG_SEED = 20261007


def run_dfa(m, letters_seq):
    st = m.initial
    verdicts = []
    for li in letters_seq:
        st = m.delta[st][li]
        verdicts.append(m.verdict[st])
    return st, verdicts


def check_monitor(m, surface, scope: EventModelScope, rng: random.Random, *, exhaustive_len: int,
                  random_traces: int, max_len: int, ltl3_traces: int, lasso_samples: int) -> dict:
    letters = m.letters
    used = set(m.aps)
    ref_alpha = scope_alphabet(scope.events, used)
    assert sorted(map(lambda d: tuple(sorted(d.items())), ref_alpha)) == \
        sorted(map(lambda d: tuple(sorted(d.items())), letters)), "alphabet mismatch"
    n = len(letters)
    traces = [list(t) for L in range(exhaustive_len + 1) for t in itertools.product(range(n), repeat=L)]
    traces += [[rng.randrange(n) for _ in range(rng.randint(exhaustive_len + 1, max_len))]
               for _ in range(random_traces)]
    stats = {"traces": len(traces), "ltl3_checked": 0, "inconclusive": 0}
    for t in traces:
        st, _ = run_dfa(m, t)
        word = [letters[i] for i in t]
        ref_close = holds_finite(surface, word, 0, alphabet=letters)
        assert bool(m.close[st]) == ref_close, (m.property_id, m.source, [letters[i] for i in t], m.close[st], ref_close)
    sample = rng.sample(traces, min(ltl3_traces, len(traces)))
    small = [([], [letters[a]]) for a in range(n)] + [([letters[a]], [letters[b]]) for a in range(n) for b in range(n)]
    for t in sample:
        st, _ = run_dfa(m, t)
        word = [letters[i] for i in t]
        exts = list(small)
        for _ in range(lasso_samples):
            x = [letters[rng.randrange(n)] for _ in range(rng.randint(0, 3))]
            y = [letters[rng.randrange(n)] for _ in range(rng.randint(1, 3))]
            exts.append((x, y))
        acc = sum(1 for x, y in exts if holds_lasso(surface, word + x, y, alphabet=letters))
        rej = len(exts) - acc
        v = m.verdict[st]
        stats["ltl3_checked"] += 1
        if v == "V":
            assert acc == 0, (m.property_id, word, "VIOLATED but an extension satisfies")
        elif v == "S":
            assert rej == 0, (m.property_id, word, "SATISFIED but an extension violates")
        else:
            if acc == 0 or rej == 0:
                stats["inconclusive"] += 1
    return stats


# ---------------------------------------------------------------------------
# random formulas of the supported subset
# ---------------------------------------------------------------------------
TOY = EventModelScope("toy", {"a": ["d"], "b": [], "c": []}, {"d"})
ATOMS = ["a", "b", "c", "d", "!a", "!b", "(a && d)", "(b || c)", "(a && !d)", "true"]


def rbool(rng):
    return rng.choice(ATOMS)


def rsere(rng, depth):
    if depth <= 0 or rng.random() < 0.35:
        return rbool(rng)
    k = rng.random()
    if k < 0.3:
        return f"{rsere(rng, depth - 1)} ; {rsere(rng, depth - 1)}"
    if k < 0.4:
        return f"{{{rsere(rng, depth - 1)}}} | {{{rsere(rng, depth - 1)}}}"
    if k < 0.5:
        return f"{rbool(rng)} : {rbool(rng)}"
    if k < 0.65:
        return f"({rbool(rng)})[*]"
    if k < 0.75:
        return f"{rbool(rng)}[+]"
    if k < 0.85:
        lo = rng.randint(0, 2)
        return f"{rbool(rng)}[*{lo}:{lo + rng.randint(0, 2)}]"
    return f"{rng.choice(['a', 'b', 'c'])}[->{rng.randint(1, 2)}]"


def nonempty_sere(rng, depth):
    return f"{rbool(rng)} ; {rsere(rng, depth)}" if rng.random() < 0.5 else f"{rsere(rng, depth)} ; {rbool(rng)}"


def rprop(rng, depth):
    if depth <= 0:
        return rbool(rng)
    k = rng.random()
    if k < 0.12:
        return f"always ({rprop(rng, depth - 1)})"
    if k < 0.22:
        return f"never {{{nonempty_sere(rng, 2)}}}"
    if k < 0.28:
        return f"never ({rbool(rng)})"
    if k < 0.36:
        return f"next ({rprop(rng, depth - 1)})"
    if k < 0.40:
        return f"next! {rbool(rng)}"
    if k < 0.45:
        return f"next[{rng.randint(0, 2)}] ({rprop(rng, depth - 1)})"
    if k < 0.52:
        return f"eventually! {rbool(rng)}"
    if k < 0.62:
        op = rng.choice(["until", "until!"])
        return f"({rprop(rng, depth - 1)}) {op} {rbool(rng)}"
    if k < 0.66:
        op = rng.choice(["until_", "until!_"])
        return f"{rbool(rng)} {op} {rbool(rng)}"
    if k < 0.74:
        op = rng.choice(["before", "before!", "before_", "before!_"])
        return f"{rbool(rng)} {op} {rbool(rng)}"
    if k < 0.84:
        op = rng.choice(["|->", "|=>"])
        return f"{{{nonempty_sere(rng, 2)}}} {op} ({rprop(rng, depth - 1)})"
    if k < 0.90:
        return f"({rprop(rng, depth - 1)}) && ({rprop(rng, depth - 1)})"
    if k < 0.95:
        return f"{rbool(rng)} || ({rprop(rng, depth - 1)})"
    return f"{rbool(rng)} -> ({rprop(rng, depth - 1)})"


def test_random_subset_formulas_match_reference():
    rng = random.Random(RNG_SEED + 1)
    checked = 0
    total = {"traces": 0, "ltl3_checked": 0, "inconclusive": 0}
    while checked < 400:
        text = rprop(rng, rng.randint(1, 3))
        src = f"vunit r (toy) {{ p: assert {text}; }}"
        (m,) = compile_sources([("rand.psl", src)], {"toy": TOY})
        (vu,) = parse(src, "rand.psl")
        s = check_monitor(m, vu.assertions[0].prop, TOY, rng, exhaustive_len=4, random_traces=80, max_len=10,
                          ltl3_traces=12, lasso_samples=25)
        for k in total:
            total[k] += s[k]
        checked += 1
    print("random formulas", checked, total)
    assert total["inconclusive"] <= 0.05 * total["ltl3_checked"]


# random formulas whose atoms include comparisons (the Boolean-layer extension):
# comparisons are data APs of event 'a', exactly like 'd'
CMP_TOY = EventModelScope("toy", {"a": ["d", 'x == "v"', "n >= 2"], "b": [], "c": []}, {"d", 'x == "v"', "n >= 2"})
CMP_ATOMS = ["a", "b", "c", "d", 'x == "v"', "n >= 2", '!(x == "v")', '(a && n >= 2)', '(x == "v" || b)', "true"]


def test_random_formulas_with_comparisons_match_reference():
    global ATOMS
    saved = ATOMS
    ATOMS = CMP_ATOMS
    try:
        rng = random.Random(RNG_SEED + 2)
        total = {"traces": 0, "ltl3_checked": 0, "inconclusive": 0}
        for _ in range(150):
            text = rprop(rng, rng.randint(1, 3))
            src = f"vunit r (toy) {{ p: assert {text}; }}"
            (m,) = compile_sources([("rand.psl", src)], {"toy": CMP_TOY})
            (vu,) = parse(src, "rand.psl")
            s = check_monitor(m, vu.assertions[0].prop, CMP_TOY, rng, exhaustive_len=3, random_traces=60,
                              max_len=9, ltl3_traces=10, lasso_samples=20)
            for k in total:
                total[k] += s[k]
        print("random formulas with comparisons", total)
        assert total["inconclusive"] <= 0.05 * total["ltl3_checked"]
    finally:
        ATOMS = saved
