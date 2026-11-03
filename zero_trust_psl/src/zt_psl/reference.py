"""Independent reference interpreter (test oracle).

Evaluates the SURFACE syntax produced by the parser directly by the semantic
definitions -- it does not use psl.core (desugaring, SERE derivatives,
progression) or psl.automaton. Two models:

* finite complete traces (neutral semantics, used for the CLOSE verdict);
* infinite ultimately-periodic ("lasso") words p . l^omega (used to cross-check
  the LTL3 verdicts: bad prefix => no lasso extension satisfies; good prefix =>
  every lasso extension satisfies; pending => both kinds exist).

SERE matching enumerates match end points explicitly. On lasso words
unbounded repetitions are explored up to a horizon of K loop unrollings
(default 8), which is exact for the properties of this project (their SEREs
contain a single unbounded repetition between two events) and is a documented
bound otherwise. Weak SERE properties ({r} alone) use a bounded viability
search (extensions up to length 6).
"""
from __future__ import annotations

import itertools
from functools import lru_cache
from typing import Callable, Sequence

from .ast import (BExpr, SBinary, SBool, SNode, SSBool, SSCat, SSere, SSereProp, SSFusion, SSOr, SSRep, SSuffix,
                  SUnary)

Letter = dict
WordFn = Callable[[int], Letter]


def _is_bool(n: SNode) -> bool:
    if isinstance(n, SBool):
        return True
    if isinstance(n, SUnary) and n.op == "!":
        return _is_bool(n.arg)
    if isinstance(n, SBinary) and n.op in ("&&", "||", "->", "<->"):
        return _is_bool(n.left) and _is_bool(n.right)
    return False


def _beval(n: SNode, letter: Letter) -> bool:
    if isinstance(n, SBool):
        return n.expr.eval(letter)
    if isinstance(n, SUnary) and n.op == "!":
        return not _beval(n.arg, letter)
    if isinstance(n, SBinary):
        a, b = _beval(n.left, letter), _beval(n.right, letter)
        return {"&&": a and b, "||": a or b, "->": (not a) or b, "<->": a == b}[n.op]
    raise TypeError(n)


# ---------------------------------------------------------------------------
# SERE match end points (inclusive end index; start-1 = empty match)
# ---------------------------------------------------------------------------
def sere_ends(r: SSere, start: int, letter: WordFn, horizon: int) -> frozenset[int]:
    if isinstance(r, SSBool):
        return frozenset({start}) if start < horizon and r.expr.eval(letter(start)) else frozenset()
    if isinstance(r, SSCat):
        out: set[int] = set()
        for k in sere_ends(r.left, start, letter, horizon):
            out |= sere_ends(r.right, k + 1, letter, horizon)
        return frozenset(out)
    if isinstance(r, SSFusion):
        out = set()
        for k in sere_ends(r.left, start, letter, horizon):
            if k >= start:                                   # left part non-empty
                out |= {e for e in sere_ends(r.right, k, letter, horizon) if e >= k}
        return frozenset(out)
    if isinstance(r, SSOr):
        return sere_ends(r.left, start, letter, horizon) | sere_ends(r.right, start, letter, horizon)
    if isinstance(r, SSRep):
        if r.kind == "goto":
            b = r.arg.expr  # type: ignore[union-attr]
            ends = {start - 1}
            for _ in range(r.lo):
                nxt: set[int] = set()
                for k in ends:
                    j = k + 1
                    while j < horizon:
                        if b.eval(letter(j)):
                            nxt.add(j)
                            break
                        j += 1
                ends = nxt
            return frozenset(ends)
        body = r.arg

        def one(k: int) -> frozenset[int]:
            if body is None:
                return frozenset({k + 1}) if k + 1 < horizon else frozenset()
            return sere_ends(body, k + 1, letter, horizon)
        if r.hi is not None:
            result: set[int] = set()
            frontier = {start - 1}
            for n in range(r.hi + 1):
                if n >= r.lo:
                    result |= frontier
                nxt: set[int] = set()
                for k in frontier:
                    nxt |= one(k)
                frontier = nxt
            return frozenset(result)
        frontier = {start - 1}
        for _ in range(r.lo):                      # exactly lo repetitions first
            nxt = set()
            for k in frontier:
                nxt |= one(k)
            frontier = nxt
        closure = set(frontier)                    # then zero or more further repetitions
        todo = list(frontier)
        while todo:
            k = todo.pop()
            for e in one(k):
                if e not in closure:
                    closure.add(e)
                    todo.append(e)
        result = closure
        return frozenset(result)
    raise TypeError(r)


# ---------------------------------------------------------------------------
# finite complete traces (neutral semantics)
# ---------------------------------------------------------------------------
def holds_finite(n: SNode, w: Sequence[Letter], i: int = 0, alphabet: Sequence[Letter] | None = None) -> bool:
    L = len(w)
    letter = (lambda k: w[k])

    def ev(n: SNode, i: int) -> bool:
        if _is_bool(n):
            return i < L and _beval(n, w[i])
        if isinstance(n, SUnary):
            if n.op == "always":
                return all(ev(n.arg, j) for j in range(i, L))
            if n.op == "never":
                if _is_bool(n.arg):
                    return all(not _beval(n.arg, w[j]) for j in range(i, L))
                r = n.arg.sere  # type: ignore[union-attr]
                return all(not [k for k in sere_ends(r, j, letter, L) if k >= j] for j in range(i, L))
            if n.op in ("next", "next!"):
                if n.count == 0:
                    return ev(n.arg, i)              # next[0] p == p
                j = i + n.count
                if j >= L:
                    return n.op == "next"            # no such position: weak holds, strong fails
                return ev(n.arg, j)
            if n.op == "eventually!":
                return any(ev(n.arg, j) for j in range(i, L))
        if isinstance(n, SBinary):
            op = n.op
            if op == "&&":
                return ev(n.left, i) and ev(n.right, i)
            if op == "||":
                return ev(n.left, i) or ev(n.right, i)
            if op == "->":
                if i >= L:
                    return True                      # vacuous: no letter to satisfy the antecedent
                return (not ev(n.left, i)) or ev(n.right, i)
            if op.startswith("until"):
                strong, incl = "!" in op, op.endswith("_")
                for j in range(i, L):
                    if ev(n.right, j) and (not incl or ev(n.left, j)):
                        return all(ev(n.left, k) for k in range(i, j))
                    if not ev(n.left, j):
                        return False
                return not strong
            if op.startswith("before"):
                strong, incl = "!" in op, op.endswith("_")
                for j in range(i, L):
                    a, b = ev(n.left, j), ev(n.right, j)
                    if a and (incl or not b):
                        return True
                    if a or b:
                        return False
                return not strong
        if isinstance(n, SSuffix):
            ends = [k for k in sere_ends(n.sere, i, letter, L) if k >= i]
            off = 1 if n.op == "|=>" else 0
            for k in ends:
                j = k + off
                if j >= L:
                    continue                         # weak at the end of a complete path
                if not ev(n.prop, j):
                    return False
            return True
        if isinstance(n, SSereProp):
            if [k for k in sere_ends(n.sere, i, letter, L) if k >= i]:
                return True
            return _viable(n.sere, w[i:], alphabet or [])
        raise TypeError(n)

    return ev(n, i)


def _viable(r: SSere, rest: Sequence[Letter], alphabet: Sequence[Letter], depth: int = 6) -> bool:
    for m in range(0, depth + 1):
        for ext in itertools.product(alphabet, repeat=m):
            w = list(rest) + list(ext)
            if [k for k in sere_ends(r, 0, lambda q: w[q], len(w)) if k >= 0]:
                return True
    return False


# ---------------------------------------------------------------------------
# infinite lasso words p . l^omega
# ---------------------------------------------------------------------------
def holds_lasso(n: SNode, prefix: Sequence[Letter], loop: Sequence[Letter], K: int = 8,
                alphabet: Sequence[Letter] | None = None) -> bool:
    P, Lp = len(prefix), len(loop)
    N = P + Lp

    def canon(j: int) -> int:
        return j if j < N else P + (j - P) % Lp

    def letter(j: int) -> Letter:
        c = canon(j)
        return prefix[c] if c < P else loop[c - P]

    window = N + Lp            # every canonical position reachable from i appears in [i, i+window)

    @lru_cache(maxsize=None)
    def ev(n: SNode, i: int) -> bool:
        i = canon(i)
        if _is_bool(n):
            return _beval(n, letter(i))
        if isinstance(n, SUnary):
            if n.op == "always":
                return all(ev(n.arg, j) for j in range(i, i + window))
            if n.op == "never":
                if _is_bool(n.arg):
                    return all(not _beval(n.arg, letter(j)) for j in range(i, i + window))
                r = n.arg.sere  # type: ignore[union-attr]
                H = i + window + N * K
                return all(not [k for k in sere_ends(r, j, letter, H) if k >= j] for j in range(i, i + window))
            if n.op in ("next", "next!"):
                return ev(n.arg, i + n.count)
            if n.op == "eventually!":
                return any(ev(n.arg, j) for j in range(i, i + window))
        if isinstance(n, SBinary):
            op = n.op
            if op == "&&":
                return ev(n.left, i) and ev(n.right, i)
            if op == "||":
                return ev(n.left, i) or ev(n.right, i)
            if op == "->":
                return (not ev(n.left, i)) or ev(n.right, i)
            if op.startswith("until"):
                strong, incl = "!" in op, op.endswith("_")
                for j in range(i, i + window):
                    if ev(n.right, j) and (not incl or ev(n.left, j)):
                        return True
                    if not ev(n.left, j):
                        return False
                return not strong                    # left holds forever, right never
            if op.startswith("before"):
                strong, incl = "!" in op, op.endswith("_")
                for j in range(i, i + window):
                    a, b = ev(n.left, j), ev(n.right, j)
                    if a and (incl or not b):
                        return True
                    if a or b:
                        return False
                return not strong
        if isinstance(n, SSuffix):
            H = i + window + N * K
            off = 1 if n.op == "|=>" else 0
            for k in sere_ends(n.sere, i, letter, H):
                if k >= i and not ev(n.prop, k + off):
                    return False
            return True
        if isinstance(n, SSereProp):
            H = i + window + N * K
            return bool([k for k in sere_ends(n.sere, i, letter, H) if k >= i])
        raise TypeError(n)

    return ev(n, 0)


# ---------------------------------------------------------------------------
# verdicts used by the tests
# ---------------------------------------------------------------------------
def lasso_extensions(alphabet: Sequence[Letter], max_x: int = 2, max_y: int = 2):
    for nx in range(max_x + 1):
        for x in itertools.product(alphabet, repeat=nx):
            for ny in range(1, max_y + 1):
                for y in itertools.product(alphabet, repeat=ny):
                    yield list(x), list(y)


def ltl3_reference(n: SNode, trace: Sequence[Letter], alphabet: Sequence[Letter]) -> tuple[int, int]:
    """(#accepted, #rejected) lasso extensions of `trace` (bounded enumeration)."""
    acc = rej = 0
    for x, y in lasso_extensions(alphabet):
        if holds_lasso(n, list(trace) + x, y, alphabet=alphabet):
            acc += 1
        else:
            rej += 1
    return acc, rej


def scope_alphabet(events: dict[str, list[str]], used: set[str]) -> list[Letter]:
    """All distinct valuations of `used` APs, one event per step (independent of psl.automaton)."""
    out: list[Letter] = []
    seen = set()
    data_all = {d for ds in events.values() for d in ds}
    for ev, ds in events.items():
        dused = [d for d in ds if d in used]
        for bits in itertools.product((False, True), repeat=len(dused)):
            v = {e: (e == ev) for e in events if e in used}
            v.update({d: False for d in data_all if d in used})
            v.update(dict(zip(dused, bits)))
            k = tuple(sorted(v.items()))
            if k not in seen:
                seen.add(k)
                out.append(v)
    return out


def surface_aps(n) -> set[str]:
    out: set[str] = set()

    def b(e: BExpr):
        out.update(e.aps())

    def s(r):
        if isinstance(r, SSBool):
            b(r.expr)
        elif isinstance(r, (SSCat, SSFusion, SSOr)):
            s(r.left)
            s(r.right)
        elif isinstance(r, SSRep) and r.arg is not None:
            s(r.arg)

    def f(x):
        if isinstance(x, SBool):
            b(x.expr)
        elif isinstance(x, SUnary):
            f(x.arg)
        elif isinstance(x, SBinary):
            f(x.left)
            f(x.right)
        elif isinstance(x, SSuffix):
            s(x.sere)
            f(x.prop)
        elif isinstance(x, SSereProp):
            s(x.sere)
    f(n)
    return out
