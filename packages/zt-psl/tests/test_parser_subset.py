"""Parser, simple-subset checks, explicit failure on unsupported syntax (ported from the PSL monitor
experiment; the Boolean-layer extensions are tested in test_boolean_layer.py)."""
from __future__ import annotations

import pytest

from zt_psl.automaton import EventModelScope
from zt_psl.compiler import compile_sources, load_event_model
from zt_psl.core import desugar
from zt_psl.parser import PSLError, PSLSyntaxError, PSLUnsupported, parse

TOY = {"toy": EventModelScope("toy", {"a": ["d"], "b": [], "c": []}, {"d"})}


def unit(body: str) -> str:
    return f"vunit u (toy) {{\n  {body}\n}}\n"


SUPPORTED = [
    "p: assert always (a -> next b);",
    "p: assert never (a && !d);",
    "p: assert never {a ; [*] ; b};",
    "p: assert never {a ; (!c)[*] ; b};",
    "p: assert never {a[*2:3] ; b[+] ; c[->2]};",
    "p: assert never {{a} | {b ; c}};",
    "p: assert never {a : b};",
    "p: assert {a ; b} |-> c;",
    "p: assert always ({a ; b} |=> (c until b));",
    "p: assert a before b;",
    "p: assert a before! b;",
    "p: assert a before_ b;",
    "p: assert a before!_ b;",
    "p: assert always (a -> eventually! b);",
    "p: assert (a || b) until! c;",
    "p: assert a until_ c;",
    "p: assert a until!_ c;",
    "p: assert next[2] a;",
    "p: assert next! a;",
    "p: assert always (a -> (b || next c));",
    "p: assert (a && d) before (b || c);",
    "property q = a before b;\n  p: assert q;",
    "sequence s = {a ; b};\n  p: assert never {s ; c};",
    "p: assert never {[*2] ; a};",
    "p: assert true before a;",
]


@pytest.mark.parametrize("body", SUPPORTED)
def test_supported_constructs_compile(body):
    mons = compile_sources([("t.psl", unit(body))], TOY)
    assert len(mons) == 1 and mons[0].delta


UNSUPPORTED = [
    ("p: assume always a;", "assume"),
    ("p: cover {a ; b};", "cover"),
    ("p: assert always a @ clk;", "clock"),
    ("default clock = clk;", "default"),
    ("p: assert {a ; b}!;", "strong SERE"),
    ("p: assert {a ; b};", "stand-alone"),
    ("p: assert always (a -> eventually! {b ; c});", "eventually!"),
    ("p: assert never {a && b} abort c;", "abort"),
    ("p: assert never {a within b};", "within"),
    ("p: assert never {{a} & {b}};", "&"),
    ("p: assert never {a[=2]};", "[="),
    ("p: assert always (rose(a));", "rose"),
    ("p: assert always (prev(a) -> b);", "prev"),
    ("p: assert next_e[1:2] a;", "next_e"),
    ("p: assert next_event(a) b;", "next_event"),
    ("p: assert G a;", "LTL G"),
    ("p: assert AG a;", "OBE"),
    ("p: assert a whilenot b;", "whilenot"),
    ("p: assert !(always a);", "negation"),
    ("p: assert (always a) -> b;", "left operand of '->'"),
    ("p: assert (always a) || (next b);", "at most one operand"),
    ("p: assert a until (next b);", "right operand"),
    ("p: assert (next a) before b;", "both operands"),
    ("p: assert never (next a);", "operand of 'never'"),
    ("p: assert next! (always a);", "next!"),
    ("p: assert never {[*] ; a};", None),         # allowed: leading [*] is fine (non-empty matches)
    ("p: assert never {a[*]};", "empty word"),
    ("p: assert {a[*]} |-> b;", "empty word"),
    ("p: assert never {b[->1:2]};", "goto repetition range"),
    ("p: assert forall i in {0:1}: a;", "forall"),
    ("p: assert always (onehot(a));", "onehot"),
]


@pytest.mark.parametrize("body,needle", UNSUPPORTED)
def test_unsupported_constructs_fail_explicitly(body, needle):
    if needle is None:
        compile_sources([("t.psl", unit(body))], TOY)
        return
    with pytest.raises(PSLUnsupported) as e:
        compile_sources([("t.psl", unit(body))], TOY)
    assert needle.lower() in str(e.value).lower(), str(e.value)
    assert e.value.pos is not None and e.value.pos.line >= 1      # positioned error


@pytest.mark.parametrize("src,needle", [
    ("vunit u { p: assert a; }", "bound to a monitor scope"),
    ("vunit u (toy) { assert a before b; }", "label"),
    ("vunit u (toy) { p: assert a before ; }", "expected a boolean"),
    ("vunit u (toy) { p: assert a before b }", "expected ';'"),
    ("vunit u (toy) { p: assert never {a ; b; }", "expected a boolean"),
    ("vunit u (toy) { p: assert never {a ; b ; }", "expected a boolean"),
    ("vunit u (toy) { p: assert never {a ; b ; c; }", "expected a boolean"),
    ("vunit u (toy) { sequence s = a ; b; p: assert never {s}; }", "braced SERE"),
    ("property p = a;", "expected 'vunit'"),
    ("vunit u (toy) { p: assert a before b; ", "unterminated"),
    ("vunit u (toy) { p: assert always (a == b); }", "expected a literal"),
    ("vunit u (toy) { p: assert always (\"x\" == a); }", "field on the left"),
    ("vunit u (toy) {\n  // @nl misplaced\n  sequence s = {a}; p: assert never {s}; }", "annotations are only allowed"),
])
def test_syntax_errors(src, needle):
    with pytest.raises(PSLSyntaxError) as e:
        compile_sources([("t.psl", src)], TOY)
    assert needle in str(e.value), str(e.value)


def test_undeclared_ap_and_scope_and_duplicate_id():
    with pytest.raises(PSLError, match="not declared"):
        compile_sources([("t.psl", unit("p: assert x before a;"))], TOY)
    with pytest.raises(PSLError, match="unknown scope"):
        compile_sources([("t.psl", "vunit u (nope) { p: assert a before b; }")], TOY)
    with pytest.raises(PSLError, match="duplicate property_id"):
        compile_sources([("t.psl", unit("p: assert a before b;\n  p: assert b before a;"))], TOY)


def test_desugaring_matches_lrm_definitions():
    (vu,) = parse(unit("p: assert a before b;"))
    assert str(desugar(vu.assertions[0].prop)) == "(!a && !b) until (a && !b)"
    (vu,) = parse(unit("p: assert a before_ b;"))
    assert str(desugar(vu.assertions[0].prop)) == "(!a && !b) until (a)"
    (vu,) = parse(unit("p: assert never {a ; b};"))
    assert str(desugar(vu.assertions[0].prop)) == "always ({a ; b} |-> (false))"
    (vu,) = parse(unit("p: assert {a} |=> c;"))
    assert str(desugar(vu.assertions[0].prop)) == "{a ; true} |-> (c)"
