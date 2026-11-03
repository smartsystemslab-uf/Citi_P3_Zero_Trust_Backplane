"""Parser for the supported PSL subset (IEEE 1850-2010, Verilog flavor).

Accepted file structure::

    // @key value                             (annotations, attached to the next declaration)
    vunit NAME (SCOPE) {
        sequence NAME = SERE ;                 // optional, referenced as {NAME} or NAME
        property NAME = FL_PROPERTY ;
        [LABEL :] assert NAME ;  |  [LABEL :] assert FL_PROPERTY ;
    }

Boolean layer (Verilog flavour): atomic propositions, hierarchical field names
(``resource.critical``) and comparisons ``FIELD op LITERAL`` with op in
== != < <= > >= and a string / integer / true / false literal.

Everything outside the subset (see docs/PSL_SUPPORTED_SUBSET.md) raises
PSLUnsupported with the construct and its position -- nothing is ignored.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .ast import (CMP_OPS, Assertion, BAnd, BAtom, BCmp, BConst, BExpr, BIff, BImp, BNot, BOr, Pos, PropertyDecl,
                  SBinary, SBool, SNode, SSBool, SSCat, SSere, SSereProp, SSFusion, SSOr, SSRef, SSRep, SSuffix, SUnary,
                  VUnit)


class PSLError(Exception):
    def __init__(self, msg: str, pos: Pos | None = None) -> None:
        super().__init__(f"{pos}: {msg}" if pos else msg)
        self.pos = pos
        self.msg = msg


class PSLSyntaxError(PSLError):
    pass


class PSLUnsupported(PSLError):
    """A construct that is valid PSL but outside the implemented subset."""


# Reserved words of IEEE 1850 that this implementation does NOT support. Seeing
# any of them is an error (never silently ignored).
UNSUPPORTED_KEYWORDS = {
    # verification directives other than assert
    "assume": "assume directive", "assume_guarantee": "assume_guarantee directive",
    "restrict": "restrict directive", "restrict_guarantee": "restrict_guarantee directive",
    "cover": "cover directive", "fairness": "fairness directive", "strong": "strong fairness directive",
    # declarations / modelling layer
    "default": "default clock / default declarations (sampling is defined by the event model)",
    "inherit": "vunit inheritance", "vmode": "vmode", "vprop": "vprop", "endpoint": "endpoint declarations",
    "const": "const parameters", "function": "function declarations", "forall": "forall replication",
    "report": "report clause", "severity": "severity clause", "union": "union operator",
    "in": "parameter sets", "mutable": "mutable parameters", "hdltype": "HDL types", "type": "type declarations",
    # FL operators outside the subset
    "abort": "abort", "async_abort": "async_abort", "sync_abort": "sync_abort",
    "within": "within (SERE)", "eventually": "eventually without '!' (not PSL)",
    "next_a": "next_a", "next_a!": "next_a!", "next_e": "next_e", "next_e!": "next_e!",
    "next_event": "next_event", "next_event!": "next_event!", "next_event_a": "next_event_a",
    "next_event_a!": "next_event_a!", "next_event_e": "next_event_e", "next_event_e!": "next_event_e!",
    "whilenot": "whilenot", "whilenot!": "whilenot!", "whilenot_": "whilenot_", "whilenot!_": "whilenot!_",
    # built-in functions
    "prev": "prev()", "next_fn": "next()", "rose": "rose()", "fell": "fell()", "stable": "stable()",
    "ended": "ended()", "isunknown": "isunknown()", "countones": "countones()", "onehot": "onehot()",
    "onehot0": "onehot0()", "nondet": "nondet()", "nondet_vector": "nondet_vector()",
    # LTL / OBE notation
    "X": "LTL X", "X!": "LTL X!", "F": "LTL F", "G": "LTL G", "U": "LTL U", "W": "LTL W",
    "AX": "OBE AX", "AG": "OBE AG", "AF": "OBE AF", "AU": "OBE AU", "EX": "OBE EX", "EG": "OBE EG",
    "EF": "OBE EF", "EU": "OBE EU", "A": "OBE A", "E": "OBE E",
}
UNSUPPORTED_SYMBOLS = {
    "@": "clock operator @ (sampling is defined by the event model)",
    "&": "length-matching SERE and '&'",
    "[=": "non-consecutive repetition [= ]",
    "%for": "%for replicator", "%if": "%if replicator",
    "~": "bitwise negation", "^": "bitwise xor", "?": "conditional operator",
}

_TOKEN = re.compile(r"""
    (?P<ws>[ \t\r]+) | (?P<nl>\n) |
    (?P<lc>//[^\n]*) | (?P<bc>/\*.*?\*/) |
    (?P<num>\d+) | (?P<str>"(?:[^"\\\n]|\\.)*") |
    (?P<kw>(?:next_event_a|next_event_e|next_event|next_a|next_e|until|before|whilenot)!?_?(?![A-Za-z0-9_]) |
          eventually!|next!|%for|%if) |
    (?P<id>[A-Za-z_][A-Za-z0-9_$]*(?:\.[A-Za-z_][A-Za-z0-9_$]*)*) |
    (?P<sym>\|->|\|=>|<->|->|\[\*|\[\+\]|\[->|\[=|&&|\|\||==|!=|<=|>=|<|>|[{}()\[\];:|!=,@&~^?]|\.)
""", re.VERBOSE | re.DOTALL)


@dataclass
class Tok:
    kind: str
    text: str
    pos: Pos


_ANNOTATION = re.compile(r"//\s*@([A-Za-z_][A-Za-z0-9_]*)\b[ \t]*(.*)$")


def tokenize(src: str, file: str, annotations: list[tuple[int, str, str]] | None = None) -> list[Tok]:
    """Tokens of ``src``. ``// @key value`` comments are collected into ``annotations``
    as (line, key, value); all other comments are ignored."""
    out: list[Tok] = []
    i, line, col = 0, 1, 1
    while i < len(src):
        m = _TOKEN.match(src, i)
        if not m:
            raise PSLSyntaxError(f"unexpected character {src[i]!r}", Pos(file, line, col))
        kind = m.lastgroup or ""
        text = m.group(kind)
        pos = Pos(file, line, col)
        if kind == "lc":
            am = _ANNOTATION.match(text)
            if am and annotations is not None:
                annotations.append((line, am.group(1), am.group(2).strip()))
        elif kind == "ws":
            pass
        elif kind in ("nl", "bc"):
            pass
        elif kind == "kw":
            out.append(Tok("kw", text, pos))
        elif kind == "id":
            out.append(Tok("id", text, pos))
        elif kind == "num":
            out.append(Tok("num", text, pos))
        elif kind == "str":
            out.append(Tok("str", text, pos))
        else:
            out.append(Tok("sym", text, pos))
        nl = text.count("\n")
        if nl:
            line += nl
            col = len(text) - text.rfind("\n")
        else:
            col += len(text)
        i = m.end()
    out.append(Tok("eof", "", Pos(file, line, col)))
    return out


_BIN_FL = {"until", "until!", "until_", "until!_", "before", "before!", "before_", "before!_"}


class Parser:
    def __init__(self, src: str, file: str) -> None:
        self.src = src
        self.file = file
        self._annotations: list[tuple[int, str, str]] = []
        self.toks = tokenize(src, file, self._annotations)
        self._ann_floor = 0
        self.i = 0
        self.sequences: dict[str, SSere] = {}
        self.properties: dict[str, tuple[SNode, str]] = {}

    # -- token helpers ---------------------------------------------------
    def peek(self, k: int = 0) -> Tok:
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def next(self) -> Tok:
        t = self.toks[self.i]
        self.i += 1
        return t

    def at(self, text: str) -> bool:
        t = self.peek()
        return t.text == text and t.kind != "eof"

    def expect(self, text: str) -> Tok:
        t = self.next()
        if t.text != text:
            self._check_unsupported(t)
            raise PSLSyntaxError(f"expected {text!r}, found {t.text or 'end of file'!r}", t.pos)
        return t

    def _check_unsupported(self, t: Tok) -> None:
        if t.kind in ("id", "kw") and t.text in UNSUPPORTED_KEYWORDS:
            raise PSLUnsupported(f"unsupported PSL construct: {UNSUPPORTED_KEYWORDS[t.text]} ('{t.text}')", t.pos)
        if t.kind == "kw" and t.text.split("!")[0].rstrip("_") in ("whilenot", "next_a", "next_e", "next_event",
                                                                 "next_event_a", "next_event_e"):
            raise PSLUnsupported(f"unsupported PSL construct: {t.text}", t.pos)
        if t.text in UNSUPPORTED_SYMBOLS:
            raise PSLUnsupported(f"unsupported PSL construct: {UNSUPPORTED_SYMBOLS[t.text]} ('{t.text}')", t.pos)

    def _source_between(self, a: Tok, b: Tok) -> str:
        # reconstruct text of a property from the original source (line/col of tokens)
        lines = self.src.split("\n")
        if a.pos.line == b.pos.line:
            return lines[a.pos.line - 1][a.pos.col - 1:b.pos.col - 1].strip()
        parts = [lines[a.pos.line - 1][a.pos.col - 1:]]
        parts += lines[a.pos.line:b.pos.line - 1]
        parts.append(lines[b.pos.line - 1][:b.pos.col - 1])
        return " ".join(p.strip() for p in parts if p.strip())

    def _take_annotations(self, before_line: int) -> tuple[tuple[str, str], ...]:
        """Annotations written after the previous declaration and above ``before_line``."""
        out = tuple((k, v) for ln, k, v in self._annotations if self._ann_floor < ln < before_line)
        self._ann_floor = before_line
        return out

    # -- file ------------------------------------------------------------
    def parse_file(self) -> list[VUnit]:
        units: list[VUnit] = []
        while self.peek().kind != "eof":
            t = self.peek()
            self._check_unsupported(t)
            if t.text != "vunit":
                raise PSLSyntaxError(f"expected 'vunit', found {t.text!r}", t.pos)
            units.append(self.parse_vunit())
        return units

    def parse_vunit(self) -> VUnit:
        vunit_ann = self._take_annotations(self.peek().pos.line)
        start = self.expect("vunit")
        name = self._ident("vunit name")
        if not self.at("("):
            raise PSLSyntaxError("vunit must be bound to a monitor scope: vunit NAME (SCOPE) { ... }", self.peek().pos)
        self.expect("(")
        scope = self._ident("scope name")
        self.expect(")")
        self.expect("{")
        self.sequences, self.properties = {}, {}
        asserts: list[Assertion] = []
        decls: list[PropertyDecl] = []
        while not self.at("}"):
            t = self.peek()
            self._check_unsupported(t)
            if t.kind == "eof":
                raise PSLSyntaxError("unterminated vunit", t.pos)
            ann = self._take_annotations(t.pos.line)
            if t.text == "sequence":
                if ann:
                    raise PSLSyntaxError("annotations are only allowed on 'property' and 'assert' declarations", t.pos)
                self.next()
                n = self._ident("sequence name")
                self.expect("=")
                if not self.at("{"):
                    raise PSLSyntaxError("a sequence declaration needs a braced SERE: sequence NAME = { ... };",
                                         self.peek().pos)
                self.next()
                self.sequences[n] = self.parse_braced_rest()
                self.expect(";")
            elif t.text == "property":
                self.next()
                n = self._ident("property name")
                if n in self.properties:
                    raise PSLSyntaxError(f"duplicate property name {n!r}", t.pos)
                self.expect("=")
                a = self.peek()
                p = self.parse_fl()
                b = self.peek()
                self.properties[n] = (p, self._source_between(a, b))
                decls.append(PropertyDecl(name=n, prop=p, source=self.properties[n][1], pos=t.pos, annotations=ann))
                self.expect(";")
            else:
                label = ""
                if t.kind == "id" and self.peek(1).text == ":":
                    label = self.next().text
                    self.next()
                kw = self.next()
                self._check_unsupported(kw)
                if kw.text != "assert":
                    raise PSLSyntaxError(f"expected 'assert', 'property' or 'sequence', found {kw.text!r}", kw.pos)
                a = self.peek()
                if a.kind == "id" and self.peek(1).text == ";" and a.text in self.properties:
                    self.next()
                    prop, src = self.properties[a.text]
                    label = label or a.text
                else:
                    prop = self.parse_fl()
                    src = self._source_between(a, self.peek())
                if not label:
                    raise PSLSyntaxError("every assertion needs a label (used as property_id)", kw.pos)
                self.expect(";")
                asserts.append(Assertion(label=label, prop=prop, source=src, pos=kw.pos, annotations=ann))
        self.expect("}")
        return VUnit(name=name, scope=scope, assertions=tuple(asserts), pos=start.pos, properties=tuple(decls),
                     annotations=vunit_ann)

    def _ident(self, what: str) -> str:
        t = self.next()
        self._check_unsupported(t)
        if t.kind != "id":
            raise PSLSyntaxError(f"expected {what}, found {t.text!r}", t.pos)
        return t.text

    # -- FL properties ---------------------------------------------------
    # precedence (lowest -> highest), documented in PSL_SUPPORTED_SUBSET.md:
    #   always/never (operand extends to the right)  <  -> <->  <  ||  <  &&
    #   <  until*/before*  <  next/next!/next[n]/eventually!  <  {r}|->, {r}|=>, {r}, (..), boolean
    def parse_fl(self) -> SNode:
        t = self.peek()
        self._check_unsupported(t)
        if t.text in ("always", "never"):
            self.next()
            return SUnary(t.text, self.parse_fl(), t.pos)
        return self.parse_impl()

    def parse_impl(self) -> SNode:
        left = self.parse_or()
        t = self.peek()
        if t.text in ("->", "<->"):
            self.next()
            right = self.parse_fl()
            return SBinary(t.text, left, right, t.pos)
        return left

    def parse_or(self) -> SNode:
        left = self.parse_and()
        while self.at("||"):
            t = self.next()
            left = SBinary("||", left, self.parse_and(), t.pos)
        return left

    def parse_and(self) -> SNode:
        left = self.parse_until()
        while self.at("&&"):
            t = self.next()
            left = SBinary("&&", left, self.parse_until(), t.pos)
        return left

    def parse_until(self) -> SNode:
        left = self.parse_unary()
        t = self.peek()
        self._check_unsupported(t)
        if t.kind == "kw" and t.text in _BIN_FL:
            self.next()
            right = self.parse_unary()
            return SBinary(t.text, left, right, t.pos)
        return left

    def parse_unary(self) -> SNode:
        t = self.peek()
        self._check_unsupported(t)
        if t.text in ("always", "never"):
            self.next()
            return SUnary(t.text, self.parse_unary(), t.pos)
        if t.text in ("next", "next!"):
            self.next()
            count = 1
            if self.at("["):
                self.next()
                n = self.next()
                if n.kind != "num":
                    raise PSLSyntaxError("next[n] needs a constant", n.pos)
                count = int(n.text)
                self.expect("]")
            return SUnary(t.text, self.parse_unary(), t.pos, count=count)
        if t.text == "eventually!":
            self.next()
            return SUnary("eventually!", self.parse_unary(), t.pos)
        if t.text == "!":
            self.next()
            return SUnary("!", self.parse_unary(), t.pos)
        if t.text == "{":
            self.next()
            sere = self.parse_braced_rest()
            u = self.peek()
            if u.text in ("|->", "|=>"):
                self.next()
                return SSuffix(u.text, sere, self.parse_unary_or_paren_fl(), u.pos)
            if u.text == "!":
                raise PSLUnsupported("unsupported PSL construct: strong SERE property {r}!", u.pos)
            return SSereProp(sere, False, t.pos)
        if t.text == "(":
            self.next()
            p = self.parse_fl()
            self.expect(")")
            return p
        if t.kind == "id" and t.text in self.properties:
            self.next()
            return self.properties[t.text][0]
        return SBool(self.parse_bool_primary_chain(), t.pos)

    def parse_unary_or_paren_fl(self) -> SNode:
        # consequent of a suffix implication: binds like a unary operand, but
        # 'always'/'never' may extend to the right
        t = self.peek()
        if t.text in ("always", "never"):
            return self.parse_fl()
        return self.parse_unary()

    # -- boolean layer -----------------------------------------------------
    def parse_bool_primary_chain(self) -> BExpr:
        # inside FL, '&&' '||' '->' are handled by the FL levels; a boolean here is
        # an atom / constant / negated or parenthesised boolean
        return self.parse_bool_atom()

    def parse_bool_atom(self) -> BExpr:
        t = self.next()
        self._check_unsupported(t)
        if t.text == "!":
            return BNot(self.parse_bool_atom())
        if t.text == "(":
            b = self.parse_bool_expr()
            self.expect(")")
            return b
        if t.kind == "id":
            if self.at("("):
                raise PSLUnsupported(f"unsupported PSL construct: function call {t.text}()", t.pos)
            if t.text in ("true", "false"):
                return BConst(t.text == "true")
            if t.text in ("vunit", "property", "sequence", "assert", "always", "never", "next"):
                raise PSLSyntaxError(f"unexpected keyword {t.text!r}", t.pos)
            if self.peek().kind == "sym" and self.peek().text in CMP_OPS:
                op = self.next().text
                return BCmp(t.text, op, self._literal())
            return BAtom(t.text)
        if t.kind in ("str", "num") and self.peek().kind == "sym" and self.peek().text in CMP_OPS:
            raise PSLSyntaxError("a comparison must have the field on the left: FIELD op LITERAL", t.pos)
        if t.kind == "num" and t.text in ("0", "1"):
            return BConst(t.text == "1")
        raise PSLSyntaxError(f"expected a boolean, found {t.text or 'end of file'!r}", t.pos)

    def _literal(self) -> object:
        t = self.next()
        if t.kind == "str":
            body = t.text[1:-1]
            return body.replace('\\"', '"').replace("\\\\", "\\")
        if t.kind == "num":
            return int(t.text)
        if t.kind == "id" and t.text in ("true", "false"):
            return t.text == "true"
        self._check_unsupported(t)
        raise PSLSyntaxError("expected a literal (\"string\", integer, true, false) after a comparison, "
                             f"found {t.text or 'end of file'!r}", t.pos)

    def parse_bool_expr(self) -> BExpr:
        left = self.parse_bool_or()
        if self.peek().text in ("->", "<->"):
            op = self.next().text
            right = self.parse_bool_expr()
            return BImp(left, right) if op == "->" else BIff(left, right)
        return left

    def parse_bool_or(self) -> BExpr:
        left = self.parse_bool_and()
        while self.at("||"):
            self.next()
            left = BOr(left, self.parse_bool_and())
        return left

    def parse_bool_and(self) -> BExpr:
        left = self.parse_bool_atom()
        while self.at("&&"):
            self.next()
            left = BAnd(left, self.parse_bool_atom())
        return left

    # -- SEREs ---------------------------------------------------------------
    def parse_braced_rest(self) -> SSere:
        """After '{': SERE '}' [ '|' '{' SERE '}' ]*  (alternation of braced SEREs)."""
        s = self.parse_sere()
        self.expect("}")
        while self.at("|"):
            t = self.next()
            self.expect("{")
            r = self.parse_sere()
            self.expect("}")
            s = SSOr(s, r, t.pos)
        if self.at("&&"):
            # '{r1} && {r2}' at FL level would be property conjunction only if
            # followed by a property; SERE '&&' is unsupported
            pass
        return s

    def parse_sere(self) -> SSere:
        left = self.parse_sere_fuse()
        while self.at(";"):
            t = self.next()
            left = SSCat(left, self.parse_sere_fuse(), t.pos)
        return left

    def parse_sere_fuse(self) -> SSere:
        left = self.parse_sere_rep()
        while self.at(":"):
            t = self.next()
            left = SSFusion(left, self.parse_sere_rep(), t.pos)
        return left

    def parse_sere_rep(self) -> SSere:
        t = self.peek()
        self._check_unsupported(t)
        if t.text in ("[*", "[+]", "[->"):
            base: SSere | None = None
        else:
            base = self.parse_sere_prim()
        while True:
            t = self.peek()
            self._check_unsupported(t)
            if t.text == "[*":
                self.next()
                lo, hi = 0, None
                if not self.at("]"):
                    lo, hi = self._range()
                self.expect("]")
                base = SSRep("star", base, lo, hi, t.pos)
            elif t.text == "[+]":
                self.next()
                base = SSRep("star", base, 1, None, t.pos)
            elif t.text == "[->":
                self.next()
                n = 1
                if not self.at("]"):
                    lo, hi = self._range()
                    if hi != lo:
                        raise PSLUnsupported("unsupported PSL construct: goto repetition range [->n:m]", t.pos)
                    n = lo
                self.expect("]")
                if base is None or not isinstance(base, SSBool):
                    raise PSLUnsupported("goto repetition [->] is only supported on a boolean", t.pos)
                base = SSRep("goto", base, n, n, t.pos)
            else:
                break
        if base is None:
            raise PSLSyntaxError("expected a SERE", t.pos)
        return base

    def _range(self) -> tuple[int, int | None]:
        a = self.next()
        if a.kind != "num":
            raise PSLSyntaxError("expected a repetition count", a.pos)
        lo = int(a.text)
        if self.at(":"):
            self.next()
            b = self.next()
            if b.kind == "id" and b.text == "inf":
                return lo, None
            if b.kind != "num":
                raise PSLSyntaxError("expected a repetition bound", b.pos)
            hi = int(b.text)
            if hi < lo:
                raise PSLSyntaxError("empty repetition range", b.pos)
            return lo, hi
        return lo, lo

    def parse_sere_prim(self) -> SSere:
        t = self.peek()
        self._check_unsupported(t)
        if t.text == "{":
            self.next()
            return self.parse_braced_rest()
        if t.kind == "id" and t.text in self.sequences:
            self.next()
            return self.sequences[t.text]
        return SSBool(self.parse_bool_expr(), t.pos)


def parse(src: str, file: str = "<psl>") -> list[VUnit]:
    return Parser(src, file).parse_file()
