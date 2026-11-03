"""Deny-overrides decisions over the request rules of a compiled PSL policy set.

For one authorization request (one ``authz_request`` step) with verified field
values:

1. every ``@permit`` property is evaluated; the ones that hold are the
   *permissions* of the request (their obligations are collected);
2. every constraint and the generated default-deny rule is evaluated; a rule
   whose body is false is *violated*;
3. outcome = the strictest ``@on_violation`` among the violated rules
   (DENY > REAUTHENTICATE > MANUAL_REVIEW); with no blocking violation: ALLOW, or
   ALLOW_WITH_OBLIGATIONS when obligations apply -- those of the permissions that
   hold, of implication constraints ``always (A -> C)`` whose A holds, and
   ``anomaly_flag(rule=ID)`` for every violated FLAG rule (FLAG never blocks).

There are no priorities: adding a rule can only make a decision stricter.
A field a rule needs but the caller did not supply raises ``UnboundField``;
callers must treat that as DENY (fail closed).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from .ast import BAnd, BAtom, BCmp, BConst, BExpr, BIff, BImp, BNot, BOr
from .compiler import CompiledPolicySet, CompiledRule, Obligation
from .fields import Binder, atoms_of

SEVERITY = {"DENY": 3, "REAUTHENTICATE": 2, "MANUAL_REVIEW": 1, "FLAG": 0}
Pred = Callable[[Mapping[str, bool]], bool]


def compile_bool(b: BExpr) -> Pred:
    """Closure evaluator for a Boolean expression over an AP valuation
    (and/or chains flattened; no eval, no recursion depth proportional to size)."""
    if isinstance(b, BConst):
        val = b.value
        return lambda v: val
    if isinstance(b, BAtom):
        n = b.name
        return lambda v: v[n]
    if isinstance(b, BCmp):
        n = b.ap
        return lambda v: v[n]
    if isinstance(b, BNot):
        f = compile_bool(b.arg)
        return lambda v: not f(v)
    if isinstance(b, (BAnd, BOr)):
        kind = type(b)
        parts: list[BExpr] = []
        stack = [b]
        while stack:
            x = stack.pop()
            if type(x) is kind:
                stack.append(x.right)        # type: ignore[union-attr]
                stack.append(x.left)         # type: ignore[union-attr]
            else:
                parts.append(x)
        fs = tuple(compile_bool(p) for p in parts)
        if kind is BAnd:
            return lambda v: all(f(v) for f in fs)
        return lambda v: any(f(v) for f in fs)
    if isinstance(b, BImp):
        l, r = compile_bool(b.left), compile_bool(b.right)
        return lambda v: (not l(v)) or r(v)
    if isinstance(b, BIff):
        l, r = compile_bool(b.left), compile_bool(b.right)
        return lambda v: l(v) == r(v)
    raise TypeError(f"not a boolean expression: {b!r}")


@dataclass(frozen=True)
class RuleRef:
    rule_id: str
    kind: str
    on_violation: str
    psl_file: str
    line: int


@dataclass
class PolicyDecision:
    outcome: str                                   # ALLOW | ALLOW_WITH_OBLIGATIONS | DENY | REAUTHENTICATE | MANUAL_REVIEW
    violated: list[RuleRef] = field(default_factory=list)      # blocking violations
    permits: list[RuleRef] = field(default_factory=list)
    flagged: list[RuleRef] = field(default_factory=list)       # violated FLAG rules (non-blocking)
    obligations: list[Obligation] = field(default_factory=list)
    eval_ns: int = 0

    @property
    def allowed(self) -> bool:
        return self.outcome in ("ALLOW", "ALLOW_WITH_OBLIGATIONS")

    def reason(self) -> str:
        if self.allowed:
            return "psl_permit:" + ",".join(p.rule_id for p in self.permits)
        return "psl_violation:" + ",".join(v.rule_id for v in self.violated)


class RequestPolicyEngine:
    def __init__(self, policy_set: CompiledPolicySet, *, scope: str = "pdp_request", runtime: str = "pdp") -> None:
        sc = policy_set.catalog.scopes.get(scope)
        if sc is None or sc.kind != "request":
            raise ValueError(f"{scope!r} is not a request scope of the policy set's field catalogue")
        self.policy_set = policy_set
        self.scope = sc
        self.event = next(iter(sc.events))
        self.runtime = runtime
        rules = policy_set.for_scope(scope, runtime)
        # the default-deny rule must range over the permissions of THIS runtime
        permits = [r for r in rules if r.kind == "permit"]
        self.permits: list[tuple[CompiledRule, Pred, RuleRef]] = [
            (r, compile_bool(r.expr), _ref(r)) for r in permits]                      # type: ignore[arg-type]
        self.constraints: list[tuple[CompiledRule, Pred, RuleRef]] = [
            (r, compile_bool(r.expr), _ref(r)) for r in rules if r.kind == "constraint"]  # type: ignore[arg-type]
        self.applicable: list[tuple[CompiledRule, Pred]] = [
            (r, compile_bool(r.applies)) for r in rules if r.kind == "constraint" and r.applies is not None]
        dd = [r for r in rules if r.kind == "default_deny"]
        if sc.default_deny and len(dd) != 1:
            raise ValueError(f"policy set has {len(dd)} default-deny rules for scope {scope}")
        if not sc.default_deny and dd:
            raise ValueError(f"check-only scope {scope} must not have a default-deny rule")
        self.default_deny = _ref(dd[0]) if dd else None
        atoms: list[BExpr] = [BAtom(self.event)]
        for r, _, _ in self.permits + self.constraints:
            atoms += atoms_of(r.expr)                                                  # type: ignore[arg-type]
        self.binder = Binder(sc, list(dict.fromkeys(atoms)))
        self.fields_needed = self.binder.fields_needed
        # rule selection (sound: a skipped rule's condition is false for the request)
        self._permit_index = GuardIndex([r.expr for r, _, _ in self.permits])                       # type: ignore[misc]
        self._constraint_index = GuardIndex([_relevance(r.expr) for r, _, _ in self.constraints])    # type: ignore[arg-type]
        self._applies: dict[int, Pred] = {i: compile_bool(r.applies) for i, (r, _, _) in enumerate(self.constraints)
                                          if r.applies is not None}

    def decide(self, fields: Mapping[str, Any]) -> PolicyDecision:
        t0 = time.perf_counter_ns()
        v = self.binder.bind(self.event, fields)          # every field is read and type-checked
        pi = self._permit_index.candidates(self.binder, fields)
        ci = self._constraint_index.candidates(self.binder, fields)
        permits = [ref for r, f, ref in (self.permits[i] for i in pi) if f(v)]
        failed = [ref for r, f, ref in (self.constraints[i] for i in ci) if not f(v)]
        violated = [x for x in failed if x.on_violation != "FLAG"]
        flagged = [x for x in failed if x.on_violation == "FLAG"]
        if self.default_deny is not None and not permits:
            violated.insert(0, self.default_deny)
        if violated:
            outcome = max(violated, key=lambda x: SEVERITY[x.on_violation]).on_violation
            obligations: list[Obligation] = []
        else:
            held = set(permits)
            obl = [o for r, f, ref in self.permits if ref in held for o in r.obligations]
            ap = self._applies                                 # A false => A -> C not applicable
            obl += [o for i in ci if i in ap and ap[i](v) for o in self.constraints[i][0].obligations]
            obl += [Obligation("anomaly_flag", (("rule", x.rule_id),)) for x in flagged]
            obligations = list(dict.fromkeys(obl))
            outcome = "ALLOW_WITH_OBLIGATIONS" if obligations else "ALLOW"
        return PolicyDecision(outcome=outcome, violated=violated, permits=permits, flagged=flagged,
                              obligations=obligations, eval_ns=time.perf_counter_ns() - t0)


def _conjuncts(b: BExpr) -> list[BExpr]:
    out, stack = [], [b]
    while stack:
        x = stack.pop()
        if isinstance(x, BAnd):
            stack += [x.right, x.left]
        else:
            out.append(x)
    return out


def _relevance(b: BExpr) -> BExpr | None:
    """A condition that must hold for a constraint to be violable: the antecedent A of
    ``A -> C`` (false A: the rule holds vacuously) or Y of ``!Y`` (``never Y``)."""
    if isinstance(b, BImp):
        return b.left
    if isinstance(b, BNot):
        return b.arg
    return None


class GuardIndex:
    """Selects the rules that can matter for a request without evaluating the others.

    A rule is indexed under one *guard*: an equality ``field == literal`` in the top-level
    conjunction of its relevance condition (a permit's whole expression; a constraint's
    antecedent or ``never`` body). If the request's value of that field differs, the
    condition is false -- a permit cannot hold, a constraint cannot be violated, an
    implication's obligations do not apply -- so skipping the rule never changes a
    decision. Rules without such a guard are always evaluated. A rule's guard field is the
    one shared by the most rules (fewest lookups per request). Candidates keep the original
    rule order. Equality follows the binder: same value AND same type (True is not 1)."""

    def __init__(self, conditions: list[BExpr | None]) -> None:
        guards = [{(p.field, type(p.value), p.value) for p in _conjuncts(c) if isinstance(p, BCmp) and p.op == "=="}
                  if c is not None else set() for c in conditions]
        freq: dict[str, int] = {}
        for g in guards:
            for f in {x[0] for x in g}:
                freq[f] = freq.get(f, 0) + 1
        self.always: list[int] = []
        self.by_field: dict[str, dict[tuple[type, Any], list[int]]] = {}
        for i, g in enumerate(guards):
            if not g:
                self.always.append(i)
                continue
            fld, typ, lit = max(g, key=lambda x: (freq[x[0]], x[0], repr(x[2])))
            self.by_field.setdefault(fld, {}).setdefault((typ, lit), []).append(i)

    def candidates(self, binder: Binder, fields: Mapping[str, Any]) -> list[int]:
        if not self.by_field:
            return self.always
        out = list(self.always)
        for fld, table in self.by_field.items():
            val = binder._get(fields, fld)
            hit = table.get((type(val), val))
            if hit:
                out += hit
        out.sort()
        return out


def _ref(r: CompiledRule) -> RuleRef:
    return RuleRef(r.rule_id, r.kind, r.on_violation, r.psl_file, r.line)
