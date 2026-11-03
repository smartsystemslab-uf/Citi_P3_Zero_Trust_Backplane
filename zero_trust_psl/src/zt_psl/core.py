"""Desugaring to core form, simple-subset checks, SERE derivatives and formula
progression. Used by the compiler (psl.automaton). The reference interpreter
(psl.reference) does NOT use this module except for the desugared core AST.

Desugaring (IEEE 1850-2010 definitions, finite/infinite-path semantics):
  never b                 -> always !b
  never {r}               -> always ({r} |-> false)
  next[n] p / next! p     -> n nested weak / strong next
  eventually! b           -> true until! b
  p until b / until!      -> CUntil(p, b, weak / strong)           (non-inclusive)
  p until_ b / until!_    -> CUntil(p, p && b, weak / strong)      (inclusive)
  a before b / before!    -> CUntil(!a && !b, a && !b, weak/strong)
  a before_ b / before!_  -> CUntil(!a && !b, a, weak / strong)
  {r} |=> p               -> {r ; true} |-> p
  b -> p                  -> !b || p          (b boolean, simple subset)
"""
from __future__ import annotations

from functools import lru_cache
from typing import Mapping

from .ast import (BAnd, BAtom, BConst, BExpr, BIff, BImp, BNot, BOr, CAlways, CAnd, CB, CDefer, CImp, CNext, Core, COr, CSere,
                  CSuffix, CUntil, FF, SAlt, SAtom, SBinary, SBool, SCat, Sere, SEps, SFuse, SNode, SNull, SSBool,
                  SSCat, SSere, SSereProp, SSFusion, SSOr, SSRep, SStar, SSuffix, SUnary, TT)
from .parser import PSLError, PSLUnsupported

T_ = TT()
F_ = FF()


# ---------------------------------------------------------------------------
# boolean helpers
# ---------------------------------------------------------------------------
def b_and(a: BExpr, b: BExpr) -> BExpr:
    return BAnd(a, b)


def b_not(a: BExpr) -> BExpr:
    return a.arg if isinstance(a, BNot) else BNot(a)


def is_bool(n: SNode) -> bool:
    if isinstance(n, SBool):
        return True
    if isinstance(n, SUnary) and n.op == "!":
        return is_bool(n.arg)
    if isinstance(n, SBinary) and n.op in ("&&", "||", "->", "<->"):
        return is_bool(n.left) and is_bool(n.right)
    return False


def to_bool(n: SNode) -> BExpr:
    if isinstance(n, SBool):
        return n.expr
    if isinstance(n, SUnary) and n.op == "!":
        return BNot(to_bool(n.arg))
    if isinstance(n, SBinary):
        l, r = to_bool(n.left), to_bool(n.right)
        return {"&&": BAnd, "||": BOr, "->": BImp, "<->": BIff}[n.op](l, r)
    raise PSLError("internal: not a boolean")


# ---------------------------------------------------------------------------
# desugar + simple subset checks
# ---------------------------------------------------------------------------
def desugar(n: SNode) -> Core:
    if is_bool(n):
        return CB(to_bool(n))
    if isinstance(n, SUnary):
        op = n.op
        if op == "!":
            raise PSLUnsupported("negation of a non-boolean property is outside the PSL simple subset", n.pos)
        if op == "always":
            return CAlways(desugar(n.arg))
        if op == "never":
            if is_bool(n.arg):
                return CAlways(CB(BNot(to_bool(n.arg))))
            if isinstance(n.arg, SSereProp):
                return CAlways(CSuffix(_nonempty(sere_core(n.arg.sere), n.pos), F_))
            raise PSLUnsupported("operand of 'never' must be a boolean or a SERE (PSL simple subset)", n.pos)
        if op in ("next", "next!"):
            inner = desugar(n.arg)
            strong = op == "next!"
            if strong and not is_bool(n.arg):
                raise PSLUnsupported("next! is only supported with a boolean operand", n.pos)
            for _ in range(n.count):
                inner = CNext(inner, strong)
            return inner
        if op == "eventually!":
            if is_bool(n.arg):
                return CUntil(T_, CB(to_bool(n.arg)), True)
            raise PSLUnsupported("eventually! is only supported with a boolean operand "
                                 "(eventually! {r} is not implemented)", n.pos)
    if isinstance(n, SBinary):
        op = n.op
        if op == "&&":
            return mk_and([desugar(n.left), desugar(n.right)])
        if op == "||":
            if not (is_bool(n.left) or is_bool(n.right)):
                raise PSLUnsupported("at most one operand of '||' may be non-boolean (PSL simple subset)", n.pos)
            return mk_or([desugar(n.left), desugar(n.right)])
        if op == "->":
            if not is_bool(n.left):
                raise PSLUnsupported("left operand of '->' must be boolean (PSL simple subset)", n.pos)
            right = desugar(n.right)
            if isinstance(right, CB):
                return CB(BImp(to_bool(n.left), right.b))
            return CImp(to_bool(n.left), right)
        if op == "<->":
            raise PSLUnsupported("'<->' between non-boolean properties is outside the PSL simple subset", n.pos)
        if op in ("until", "until!", "until_", "until!_"):
            if not is_bool(n.right):
                raise PSLUnsupported(f"right operand of '{op}' must be boolean (PSL simple subset)", n.pos)
            strong = "!" in op
            right = CB(to_bool(n.right))
            if op.endswith("_"):
                if not is_bool(n.left):
                    raise PSLUnsupported(f"left operand of '{op}' must be boolean (PSL simple subset)", n.pos)
                left = CB(to_bool(n.left))
                return CUntil(left, CB(BAnd(to_bool(n.left), to_bool(n.right))), strong)
            return CUntil(desugar(n.left), right, strong)
        if op in ("before", "before!", "before_", "before!_"):
            if not (is_bool(n.left) and is_bool(n.right)):
                raise PSLUnsupported(f"both operands of '{op}' must be boolean (PSL simple subset)", n.pos)
            a, b = to_bool(n.left), to_bool(n.right)
            strong = "!" in op
            left = CB(BAnd(BNot(a), BNot(b)))
            right = CB(a) if op.endswith("_") else CB(BAnd(a, BNot(b)))
            return CUntil(left, right, strong)
    if isinstance(n, SSuffix):
        r = sere_core(n.sere)
        if n.op == "|=>":
            r = mk_cat([r, SAtom(BConst(True))])
        return CSuffix(_nonempty(r, n.pos), desugar(n.prop))
    if isinstance(n, SSereProp):
        raise PSLUnsupported("a SERE used as a stand-alone property ({r} / {r}!) is not supported; "
                             "use it under 'never' or as the antecedent of |-> / |=>", n.pos)
    raise PSLError(f"internal: cannot desugar {type(n).__name__}", getattr(n, "pos", None))


def _nonempty(r: Sere, pos) -> Sere:
    if nullable(r):
        raise PSLUnsupported("the antecedent SERE of a suffix implication / never must not match the empty word "
                             "(empty matches are not supported)", pos)
    return r


def sere_core(s: SSere) -> Sere:
    if isinstance(s, SSBool):
        return mk_atom(s.expr)
    if isinstance(s, SSCat):
        return mk_cat([sere_core(s.left), sere_core(s.right)])
    if isinstance(s, SSFusion):
        return mk_fuse(sere_core(s.left), sere_core(s.right))
    if isinstance(s, SSOr):
        return mk_alt([sere_core(s.left), sere_core(s.right)])
    if isinstance(s, SSRep):
        base = sere_core(s.arg) if s.arg is not None else SAtom(BConst(True))
        if s.kind == "goto":
            b = s.arg.expr  # type: ignore[union-attr]
            one = mk_cat([mk_star(mk_atom(BNot(b))), mk_atom(b)])
            return mk_cat([one] * s.lo)
        parts = [base] * s.lo
        if s.hi is None:
            parts.append(mk_star(base))
        else:
            opt = mk_alt([SEps(), base])
            parts += [opt] * (s.hi - s.lo)
        return mk_cat(parts) if parts else SEps()
    raise PSLError(f"internal: unsupported SERE node {type(s).__name__}")


# ---------------------------------------------------------------------------
# SERE constructors with normalisation (ACI for alternation)
# ---------------------------------------------------------------------------
def mk_atom(b: BExpr) -> Sere:
    if isinstance(b, BConst) and not b.value:
        return SNull()
    return SAtom(b)


def mk_cat(args: list[Sere]) -> Sere:
    flat: list[Sere] = []
    for a in args:
        if isinstance(a, SNull):
            return SNull()
        if isinstance(a, SEps):
            continue
        if isinstance(a, SCat):
            flat.extend(a.args)
        else:
            flat.append(a)
    if not flat:
        return SEps()
    if len(flat) == 1:
        return flat[0]
    return SCat(tuple(flat))


def mk_alt(args: list[Sere]) -> Sere:
    seen: dict[tuple, Sere] = {}
    for a in args:
        if isinstance(a, SNull):
            continue
        for x in (a.args if isinstance(a, SAlt) else (a,)):
            seen.setdefault(x.key(), x)
    if not seen:
        return SNull()
    if len(seen) == 1:
        return next(iter(seen.values()))
    return SAlt(tuple(seen[k] for k in sorted(seen)))


def mk_star(a: Sere) -> Sere:
    if isinstance(a, (SEps, SNull)):
        return SEps()
    if isinstance(a, SStar):
        return a
    return SStar(a)


def mk_fuse(a: Sere, b: Sere) -> Sere:
    if isinstance(a, SNull) or isinstance(b, SNull):
        return SNull()
    return SFuse(a, b)


@lru_cache(maxsize=None)
def nullable(r: Sere) -> bool:
    if isinstance(r, SEps):
        return True
    if isinstance(r, (SNull, SAtom, SFuse)):
        return False
    if isinstance(r, SCat):
        return all(nullable(a) for a in r.args)
    if isinstance(r, SAlt):
        return any(nullable(a) for a in r.args)
    if isinstance(r, SStar):
        return True
    raise TypeError(r)


def deriv(r: Sere, letter: Mapping[str, bool]) -> Sere:
    """Brzozowski derivative with respect to one letter (a valuation of the APs)."""
    if isinstance(r, (SEps, SNull)):
        return SNull()
    if isinstance(r, SAtom):
        return SEps() if r.b.eval(letter) else SNull()
    if isinstance(r, SCat):
        head, rest = r.args[0], mk_cat(list(r.args[1:]))
        d = mk_cat([deriv(head, letter), rest])
        if nullable(head):
            d = mk_alt([d, deriv(rest, letter)])
        return d
    if isinstance(r, SAlt):
        return mk_alt([deriv(a, letter) for a in r.args])
    if isinstance(r, SStar):
        return mk_cat([deriv(r.arg, letter), r])
    if isinstance(r, SFuse):
        dl = deriv(r.left, letter)
        out = mk_fuse(dl, r.right)
        if nullable(dl):
            out = mk_alt([out, deriv(r.right, letter)])
        return out
    raise TypeError(r)


# ---------------------------------------------------------------------------
# formula constructors with simplification
# ---------------------------------------------------------------------------
def mk_and(args: list[Core]) -> Core:
    seen: dict[tuple, Core] = {}
    for a in args:
        if isinstance(a, FF):
            return F_
        if isinstance(a, TT):
            continue
        for x in (a.args if isinstance(a, CAnd) else (a,)):
            seen.setdefault(x.key(), x)
    if not seen:
        return T_
    if len(seen) == 1:
        return next(iter(seen.values()))
    return CAnd(tuple(seen[k] for k in sorted(seen)))


def mk_or(args: list[Core]) -> Core:
    seen: dict[tuple, Core] = {}
    for a in args:
        if isinstance(a, TT):
            return T_
        if isinstance(a, FF):
            continue
        for x in (a.args if isinstance(a, COr) else (a,)):
            seen.setdefault(x.key(), x)
    if not seen:
        return F_
    if len(seen) == 1:
        return next(iter(seen.values()))
    return COr(tuple(seen[k] for k in sorted(seen)))


def mk_defer(arg: Core, strong: bool) -> Core:
    if isinstance(arg, TT) and not strong:
        return T_
    return CDefer(arg, strong)


def progress(f: Core, letter: Mapping[str, bool]) -> Core:
    """Formula progression: u, letter.w |= f  <=>  w |= progress(f, letter)."""
    if isinstance(f, (TT, FF)):
        return f
    if isinstance(f, CB):
        return T_ if f.b.eval(letter) else F_
    if isinstance(f, CAnd):
        return mk_and([progress(a, letter) for a in f.args])
    if isinstance(f, COr):
        return mk_or([progress(a, letter) for a in f.args])
    if isinstance(f, CNext):
        return mk_defer(f.arg, f.strong)
    if isinstance(f, CDefer):
        return progress(f.arg, letter)
    if isinstance(f, CImp):
        return progress(f.prop, letter) if f.b.eval(letter) else T_
    if isinstance(f, CAlways):
        return mk_and([progress(f.arg, letter), f])
    if isinstance(f, CUntil):
        return mk_or([progress(f.right, letter), mk_and([progress(f.left, letter), f])])
    if isinstance(f, CSuffix):
        d = deriv(f.sere, letter)
        if isinstance(d, SNull):
            return T_
        now = progress(f.prop, letter) if nullable(d) else T_
        return mk_and([now, CSuffix(d, f.prop)])
    if isinstance(f, CSere):
        d = deriv(f.sere, letter)
        if nullable(d):
            return T_
        if isinstance(d, SNull):
            return F_
        return CSere(d, f.strong)
    raise TypeError(f)


def end_value(f: Core) -> bool:
    """Neutral finite-path value of a residual at the end of a complete trace:
    weak operators hold, strong obligations not yet met fail."""
    if isinstance(f, TT):
        return True
    if isinstance(f, FF):
        return False
    if isinstance(f, CB):
        return False                     # a boolean needs a letter; none left
    if isinstance(f, CAnd):
        return all(end_value(a) for a in f.args)
    if isinstance(f, COr):
        return any(end_value(a) for a in f.args)
    if isinstance(f, (CNext, CDefer)):
        return not f.strong
    if isinstance(f, CImp):
        return True
    if isinstance(f, CAlways):
        return True
    if isinstance(f, CUntil):
        return not f.strong
    if isinstance(f, CSuffix):
        return True
    if isinstance(f, CSere):
        return not f.strong
    raise TypeError(f)


def strong_obligations(f: Core) -> list[Core]:
    """Top-level pending strong obligations of a residual (strong until)."""
    if isinstance(f, CAnd):
        return [a for a in f.args if isinstance(a, CUntil) and a.strong]
    if isinstance(f, CUntil) and f.strong:
        return [f]
    return []


def core_aps(f: Core) -> frozenset[str]:
    if isinstance(f, (TT, FF)):
        return frozenset()
    if isinstance(f, CB):
        return f.b.aps()
    if isinstance(f, (CAnd, COr)):
        out: frozenset[str] = frozenset()
        for a in f.args:
            out |= core_aps(a)
        return out
    if isinstance(f, (CNext, CAlways, CDefer)):
        return core_aps(f.arg)
    if isinstance(f, CImp):
        return f.b.aps() | core_aps(f.prop)
    if isinstance(f, CUntil):
        return core_aps(f.left) | core_aps(f.right)
    if isinstance(f, CSuffix):
        return sere_aps(f.sere) | core_aps(f.prop)
    if isinstance(f, CSere):
        return sere_aps(f.sere)
    raise TypeError(f)


def sere_aps(r: Sere) -> frozenset[str]:
    if isinstance(r, (SEps, SNull)):
        return frozenset()
    if isinstance(r, SAtom):
        return r.b.aps()
    if isinstance(r, (SCat, SAlt)):
        out: frozenset[str] = frozenset()
        for a in r.args:
            out |= sere_aps(a)
        return out
    if isinstance(r, SStar):
        return sere_aps(r.arg)
    if isinstance(r, SFuse):
        return sere_aps(r.left) | sere_aps(r.right)
    raise TypeError(r)


_ = (BAtom,)  # re-export convenience
