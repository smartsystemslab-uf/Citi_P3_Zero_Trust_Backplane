"""The decision engine's guard index (rule selection) never changes a decision.

``RequestPolicyEngine.decide`` evaluates only the rules whose equality guard matches the
request; ``exhaustive`` below evaluates every rule, as the engine did before the index.
Both must return identical outcomes, violated / permitted / flagged rules and obligations
-- on the real Backplane store and on generated policy sets with random valuations."""
from __future__ import annotations

import random
from pathlib import Path

import pytest

from zt_psl import RequestPolicyEngine, compile_policy_set
from zt_psl.decision import SEVERITY, GuardIndex, _relevance
from zt_psl.compiler import Obligation
from zt_psl.fields import FieldCatalog

BACKPLANE = Path(__file__).resolve().parents[3]          # repository root
STORE = BACKPLANE / "packages/zt-pdp" / "policy_store"


def exhaustive(eng: RequestPolicyEngine, fields):
    v = eng.binder.bind(eng.event, fields)
    permits = [ref for r, f, ref in eng.permits if f(v)]
    failed = [ref for r, f, ref in eng.constraints if not f(v)]
    violated = [x for x in failed if x.on_violation != "FLAG"]
    flagged = [x for x in failed if x.on_violation == "FLAG"]
    if eng.default_deny is not None and not permits:
        violated.insert(0, eng.default_deny)
    if violated:
        return max(violated, key=lambda x: SEVERITY[x.on_violation]).on_violation, violated, permits, flagged, []
    held = set(permits)
    obl = [o for r, f, ref in eng.permits if ref in held for o in r.obligations]
    obl += [o for r, f in eng.applicable if f(v) for o in r.obligations]
    obl += [Obligation("anomaly_flag", (("rule", x.rule_id),)) for x in flagged]
    obl = list(dict.fromkeys(obl))
    return ("ALLOW_WITH_OBLIGATIONS" if obl else "ALLOW"), violated, permits, flagged, obl


def same(eng, fields):
    d = eng.decide(fields)
    assert (d.outcome, d.violated, d.permits, d.flagged, d.obligations) == exhaustive(eng, fields), fields


def _literals(eng):
    """Per field: the literals the rules compare it with (plus a value no rule uses)."""
    from zt_psl.ast import BCmp
    from zt_psl.fields import atoms_of
    lits: dict[str, set] = {}
    for r, _, _ in eng.permits + eng.constraints:
        for a in atoms_of(r.expr):
            if isinstance(a, BCmp):
                lits.setdefault(a.field, set()).add(a.value)
    return lits


def _random_fields(eng, lits, rng):
    sc = eng.scope
    out = {}
    for name in eng.fields_needed:
        spec = sc.spec(name)
        t = spec.type if spec is not None else "bool"
        if t == "bool":
            out[name] = rng.random() < 0.5
        elif t == "int":
            pool = sorted(x for x in lits.get(name, ()) if isinstance(x, int)) or [0]
            out[name] = rng.choice(pool + [pool[0] - 1, pool[-1] + 1])
        else:
            pool = sorted(str(x) for x in lits.get(name, ()))
            out[name] = rng.choice(pool + ["zz-unused"]) if pool and rng.random() < 0.9 else "zz-unused"
            if spec is not None and t == "enum":
                out[name] = rng.choice(list(spec.values))
    return out


@pytest.fixture(scope="module")
def store_set():
    files = sorted(STORE.glob("*.psl"))
    return compile_policy_set([(p.name, p.read_text(encoding="utf-8")) for p in files],
                              FieldCatalog.load(STORE / "policy_fields.yaml"))


@pytest.mark.parametrize("scope,runtime", [("pdp_request", "pdp"), ("gateway_input", "gateway"),
                                           ("gateway_output", "gateway"), ("gateway_tool", "gateway")])
def test_index_is_equivalent_on_the_real_store(store_set, scope, runtime):
    eng = RequestPolicyEngine(store_set, scope=scope, runtime=runtime)
    lits = _literals(eng)
    rng = random.Random(f"{scope}-1850")
    for _ in range(4000):
        same(eng, _random_fields(eng, lits, rng))


def test_real_store_rules_are_mostly_guarded(store_set):
    eng = RequestPolicyEngine(store_set)
    assert len(eng._permit_index.always) == 0                     # every permit names its subject/resource
    assert len(eng._constraint_index.always) <= 6, [eng.constraints[i][2].rule_id for i in eng._constraint_index.always]


CAT = {"catalog_version": 1, "scopes": {"s": {"kind": "request", "events": {"req": "*"}, "fields": {
    "a": {"type": "string", "source": "t"}, "b": {"type": "string", "source": "t"},
    "n": {"type": "int", "source": "t"}, "x": {"type": "bool", "source": "t"}, "y": {"type": "bool", "source": "t"}}}}}


def _gen_cond(rng, depth=0):
    k = rng.random()
    if depth > 2 or k < 0.35:
        return rng.choice(['a == "p"', 'a == "q"', 'b == "p"', 'b != "q"', "n >= 2", "n == 1", "x", "!y", "true"])
    op = rng.choice([" && ", " && ", " || ", " -> "])
    return f"({_gen_cond(rng, depth + 1)}{op}{_gen_cond(rng, depth + 1)})"


def test_index_is_equivalent_on_generated_policy_sets():
    rng = random.Random(9421)
    for k in range(60):
        body = []
        for i in range(rng.randint(1, 6)):
            body.append(f"  // @permit\n  // @obligation o{i}\n  property p{i} = {_gen_cond(rng)};")
        for i in range(rng.randint(1, 6)):
            ov = rng.choice(["DENY", "MANUAL_REVIEW", "REAUTHENTICATE", "FLAG"])
            form = rng.choice(["always (req && {c} -> {d})", "never (req && {c})", "always (req -> {d})"])
            obl = "  // @obligation k\n" if form.startswith("always (req &&") else ""
            body.append(f"  // @on_violation {ov}\n{obl}  c{i}: assert " +
                        form.format(c=_gen_cond(rng), d=_gen_cond(rng)) + ";")
        ps = compile_policy_set([("g.psl", "vunit v (s) {\n" + "\n".join(body) + "\n}")], FieldCatalog(CAT))
        eng = RequestPolicyEngine(ps, scope="s")
        for a in ("p", "q", "r"):
            for b in ("p", "q", "r"):
                for n in (0, 1, 2):
                    for x in (False, True):
                        for y in (False, True):
                            same(eng, {"a": a, "b": b, "n": n, "x": x, "y": y})


def test_type_aware_lookup():
    from zt_psl.ast import BCmp
    idx = GuardIndex([BCmp("f", "==", 1)])
    class B:
        @staticmethod
        def _get(fields, name):
            return fields[name]
    assert idx.candidates(B, {"f": 1}) == [0]
    assert idx.candidates(B, {"f": True}) == []                 # True is not the integer 1
    assert _relevance(BCmp("f", "==", 1)) is None
