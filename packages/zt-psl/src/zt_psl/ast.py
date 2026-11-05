"""Abstract syntax for the supported PSL subset (IEEE 1850-2010, Verilog flavor).

Boolean-layer extension used by the Backplane policies (Verilog-flavour HDL expressions):
hierarchical field references (``subject.id``) and comparisons with a literal
(``subject.id == "agent.x"``, ``auth.strength >= 2``). A comparison is an atomic
proposition whose truth value is computed from verified field values by a binder
(``zt_psl.fields``); everything downstream treats it like any other AP.

Two layers are kept apart:

* surface AST (``S*`` classes) -- what the parser produced, close to the text;
* core AST (``Core*``, ``Sere*``, ``B*``) -- the desugared, negation-normal form
  the compiler and the reference interpreter both start from.

All nodes are immutable and hashable; ``key()`` gives a canonical, totally
ordered representation used for normalisation and interning.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


# ---------------------------------------------------------------------------
# Boolean layer
# ---------------------------------------------------------------------------
class BExpr:
    def eval(self, v: Mapping[str, bool]) -> bool:  # pragma: no cover - abstract
        raise NotImplementedError

    def aps(self) -> frozenset[str]:  # pragma: no cover - abstract
        raise NotImplementedError

    def text(self) -> str:  # pragma: no cover - abstract
        raise NotImplementedError


@dataclass(frozen=True)
class BConst(BExpr):
    value: bool

    def eval(self, v):
        return self.value

    def aps(self):
        return frozenset()

    def text(self):
        return "true" if self.value else "false"


@dataclass(frozen=True)
class BAtom(BExpr):
    name: str

    def eval(self, v):
        return bool(v.get(self.name, False))

    def aps(self):
        return frozenset({self.name})

    def text(self):
        return self.name


@dataclass(frozen=True)
class BNot(BExpr):
    arg: BExpr

    def eval(self, v):
        return not self.arg.eval(v)

    def aps(self):
        return self.arg.aps()

    def text(self):
        return f"!{_bparen(self.arg)}"


@dataclass(frozen=True)
class BAnd(BExpr):
    left: BExpr
    right: BExpr

    def eval(self, v):
        return self.left.eval(v) and self.right.eval(v)

    def aps(self):
        return self.left.aps() | self.right.aps()

    def text(self):
        return f"{_bparen(self.left)} && {_bparen(self.right)}"


@dataclass(frozen=True)
class BOr(BExpr):
    left: BExpr
    right: BExpr

    def eval(self, v):
        return self.left.eval(v) or self.right.eval(v)

    def aps(self):
        return self.left.aps() | self.right.aps()

    def text(self):
        return f"{_bparen(self.left)} || {_bparen(self.right)}"


@dataclass(frozen=True)
class BImp(BExpr):
    left: BExpr
    right: BExpr

    def eval(self, v):
        return (not self.left.eval(v)) or self.right.eval(v)

    def aps(self):
        return self.left.aps() | self.right.aps()

    def text(self):
        return f"{_bparen(self.left)} -> {_bparen(self.right)}"


@dataclass(frozen=True)
class BIff(BExpr):
    left: BExpr
    right: BExpr

    def eval(self, v):
        return self.left.eval(v) == self.right.eval(v)

    def aps(self):
        return self.left.aps() | self.right.aps()

    def text(self):
        return f"{_bparen(self.left)} <-> {_bparen(self.right)}"


CMP_OPS = ("==", "!=", "<", "<=", ">", ">=")


def literal_text(value: object) -> str:
    """Canonical text of a comparison literal (part of the AP name)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    s = str(value)
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


@dataclass(frozen=True)
class BCmp(BExpr):
    """``field op literal``. Evaluated through its canonical AP name; the binder sets
    that AP from the field value, so automata, the reference interpreter and the
    Boolean fast path all see an ordinary atomic proposition."""
    field: str
    op: str
    value: object             # str | int | bool

    @property
    def ap(self) -> str:
        return f"{self.field} {self.op} {literal_text(self.value)}"

    def eval(self, v):
        return bool(v.get(self.ap, False))

    def aps(self):
        return frozenset({self.ap})

    def text(self):
        return self.ap


def _bparen(b: BExpr) -> str:
    return b.text() if isinstance(b, (BAtom, BConst, BNot, BCmp)) else f"({b.text()})"


# ---------------------------------------------------------------------------
# Surface syntax (parser output)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Pos:
    file: str
    line: int
    col: int

    def __str__(self) -> str:
        return f"{self.file}:{self.line}:{self.col}"


class SNode:
    pos: Pos


@dataclass(frozen=True)
class SBool(SNode):          # boolean expression used as a property / sequence element
    expr: BExpr
    pos: Pos


@dataclass(frozen=True)
class SUnary(SNode):         # always, never, next, next!, eventually!, next[n]
    op: str
    arg: SNode
    pos: Pos
    count: int = 1


@dataclass(frozen=True)
class SBinary(SNode):        # && || -> <-> until until! until_ until!_ before before! before_ before!_
    op: str
    left: SNode
    right: SNode
    pos: Pos


@dataclass(frozen=True)
class SSuffix(SNode):        # {r} |-> p, {r} |=> p
    op: str
    sere: "SSere"
    prop: SNode
    pos: Pos


@dataclass(frozen=True)
class SSereProp(SNode):      # {r} (weak) or {r}! (strong)
    sere: "SSere"
    strong: bool
    pos: Pos


class SSere:
    pos: Pos


@dataclass(frozen=True)
class SSBool(SSere):
    expr: BExpr
    pos: Pos


@dataclass(frozen=True)
class SSCat(SSere):           # r1 ; r2
    left: SSere
    right: SSere
    pos: Pos


@dataclass(frozen=True)
class SSFusion(SSere):        # r1 : r2
    left: SSere
    right: SSere
    pos: Pos


@dataclass(frozen=True)
class SSOr(SSere):            # {r1} | {r2}
    left: SSere
    right: SSere
    pos: Pos


@dataclass(frozen=True)
class SSRep(SSere):           # r[*], r[*n], r[*n:m], r[+], b[->], b[->n]
    kind: str                 # "star" | "goto"
    arg: SSere | None         # None = standalone [*...] (i.e. true[*...])
    lo: int
    hi: int | None            # None = unbounded
    pos: Pos


@dataclass(frozen=True)
class SSRef(SSere):           # reference to a named sequence
    name: str
    pos: Pos


Annotations = tuple[tuple[str, str], ...]     # ((key, value), ...) from '// @key value' comments


@dataclass(frozen=True)
class Assertion:
    label: str
    prop: SNode
    source: str               # property text as written
    pos: Pos
    annotations: Annotations = ()


@dataclass(frozen=True)
class PropertyDecl:
    name: str
    prop: SNode
    source: str
    pos: Pos
    annotations: Annotations = ()


@dataclass(frozen=True)
class VUnit:
    name: str
    scope: str                # name in parentheses: the monitor scope the vunit is bound to
    assertions: tuple[Assertion, ...]
    pos: Pos
    properties: tuple[PropertyDecl, ...] = ()
    annotations: Annotations = ()


# ---------------------------------------------------------------------------
# Core syntax (desugared, NNF). Negation only on booleans.
# ---------------------------------------------------------------------------
class Core:
    def key(self) -> tuple:  # pragma: no cover - abstract
        raise NotImplementedError


@dataclass(frozen=True)
class TT(Core):
    def key(self):
        return ("1",)

    def __str__(self):
        return "true"


@dataclass(frozen=True)
class FF(Core):
    def key(self):
        return ("0",)

    def __str__(self):
        return "false"


@dataclass(frozen=True)
class CB(Core):               # boolean at the current step
    b: BExpr

    def key(self):
        return ("b", self.b.text())

    def __str__(self):
        return self.b.text()


@dataclass(frozen=True)
class CAnd(Core):
    args: tuple[Core, ...]    # canonical: sorted by key, >= 2, no TT/FF/CAnd inside

    def key(self):
        return ("and",) + tuple(a.key() for a in self.args)

    def __str__(self):
        return " && ".join(f"({a})" for a in self.args)


@dataclass(frozen=True)
class COr(Core):
    args: tuple[Core, ...]

    def key(self):
        return ("or",) + tuple(a.key() for a in self.args)

    def __str__(self):
        return " || ".join(f"({a})" for a in self.args)


@dataclass(frozen=True)
class CNext(Core):
    arg: Core
    strong: bool

    def key(self):
        return ("X!" if self.strong else "X", self.arg.key())

    def __str__(self):
        return f"next{'!' if self.strong else ''} ({self.arg})"


@dataclass(frozen=True)
class CImp(Core):             # b -> p with boolean b (vacuously true when no letter is left)
    b: BExpr
    prop: Core

    def key(self):
        return ("imp", self.b.text(), self.prop.key())

    def __str__(self):
        return f"({self.b.text()}) -> ({self.prop})"


@dataclass(frozen=True)
class CDefer(Core):           # residual of next/next!: arg starts at the NEXT letter;
    arg: Core                 # if the trace ends first: weak -> holds, strong -> fails
    strong: bool

    def key(self):
        return ("D!" if self.strong else "D", self.arg.key())

    def __str__(self):
        return f"at-next{'!' if self.strong else ''} ({self.arg})"


@dataclass(frozen=True)
class CAlways(Core):
    arg: Core

    def key(self):
        return ("G", self.arg.key())

    def __str__(self):
        return f"always ({self.arg})"


@dataclass(frozen=True)
class CUntil(Core):           # non-inclusive: right holds at some j, left holds on [i, j)
    left: Core
    right: Core
    strong: bool

    def key(self):
        return ("U!" if self.strong else "U", self.left.key(), self.right.key())

    def __str__(self):
        return f"({self.left}) until{'!' if self.strong else ''} ({self.right})"


@dataclass(frozen=True)
class CSuffix(Core):          # overlapping suffix implication, non-empty matches only
    sere: "Sere"
    prop: Core

    def key(self):
        return ("SI", self.sere.key(), self.prop.key())

    def __str__(self):
        return f"{{{self.sere}}} |-> ({self.prop})"


@dataclass(frozen=True)
class CSere(Core):            # SERE as a property (weak only in this implementation)
    sere: "Sere"
    strong: bool

    def key(self):
        return ("S!" if self.strong else "S", self.sere.key())

    def __str__(self):
        return f"{{{self.sere}}}{'!' if self.strong else ''}"


# ---------------------------------------------------------------------------
# SERE core
# ---------------------------------------------------------------------------
class Sere:
    def key(self) -> tuple:  # pragma: no cover - abstract
        raise NotImplementedError


@dataclass(frozen=True)
class SEps(Sere):             # matches only the empty word
    def key(self):
        return ("eps",)

    def __str__(self):
        return "[*0]"


@dataclass(frozen=True)
class SNull(Sere):            # matches nothing
    def key(self):
        return ("null",)

    def __str__(self):
        return "{}"


@dataclass(frozen=True)
class SAtom(Sere):
    b: BExpr

    def key(self):
        return ("a", self.b.text())

    def __str__(self):
        return self.b.text()


@dataclass(frozen=True)
class SCat(Sere):
    args: tuple[Sere, ...]

    def key(self):
        return ("cat",) + tuple(a.key() for a in self.args)

    def __str__(self):
        return " ; ".join(str(a) for a in self.args)


@dataclass(frozen=True)
class SAlt(Sere):
    args: tuple[Sere, ...]

    def key(self):
        return ("alt",) + tuple(a.key() for a in self.args)

    def __str__(self):
        return " | ".join(f"{{{a}}}" for a in self.args)


@dataclass(frozen=True)
class SStar(Sere):
    arg: Sere

    def key(self):
        return ("star", self.arg.key())

    def __str__(self):
        return f"{{{self.arg}}}[*]"


@dataclass(frozen=True)
class SFuse(Sere):
    left: Sere
    right: Sere

    def key(self):
        return ("fuse", self.left.key(), self.right.key())

    def __str__(self):
        return f"{{{self.left}}} : {{{self.right}}}"
