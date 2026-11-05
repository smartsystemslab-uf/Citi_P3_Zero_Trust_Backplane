"""Compile PSL policy sets.

A *policy set* is a list of .psl files plus a field catalogue (``zt_psl.fields``).
Every vunit is bound to a catalogue scope:

* **request scope** (kind ``request``, e.g. ``pdp_request``) -- rules about one
  authorization request:

  - ``@permit`` properties ``property NAME = <boolean>;`` grant access when they
    hold (and carry ``@obligation`` annotations);
  - assertions must be invariants ``always <boolean>`` / ``never <boolean>``; the
    Boolean body is checked per request (the automaton of ``always b`` is "stay
    while b, violate when !b", so the body is evaluated directly);
  - the compiler adds the default-deny rule
    ``R_default_deny: assert always (EVENT -> (permit_1 || ... || permit_n));``.

* **temporal scope** (kind ``temporal``) -- rules over a trace of trusted runtime
  events; compiled to monitor automata (``zt_psl.automaton``).

Annotations (``// @key value`` above a declaration; unknown keys are errors):

  @rule ID            stable rule id (default: label / property name)
  @nl TEXT            the natural-language statement the rule formalises
  @source REF         where the rule came from
  @on_violation X     DENY (default) | REAUTHENTICATE | MANUAL_REVIEW | FLAG   (assertions)
                      FLAG = non-blocking: a violation adds the obligation anomaly_flag(rule=ID)
  @permit             marks a permission property                     (properties)
  @obligation T(k=v)  obligation of a permission (when it holds), or of an implication
                      constraint ``always (A -> C)`` (when A holds and the request is allowed)
  @runtime R[,R]      runtimes that evaluate the rule (default: the scope's default)
  @disabled REASON    compiled and checked, but evaluated by no runtime (listed with the reason)
  @note TEXT          free text kept in the generated description
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .ast import (BAtom, BCmp, BConst, BExpr, BImp, BOr, CAlways, CAnd, CB, CDefer, CImp, CNext, COr, Core, CSere,
                  CSuffix, CUntil, SAlt, SAtom, SCat, SFuse, SStar)
from .automaton import EventModelScope, Monitor, build
from .core import desugar, is_bool, to_bool
from .fields import FieldCatalog, ScopeSpec, atoms_of
from .parser import PSLError, parse

ROOT = Path(__file__).resolve().parent
COMPILER_FILES = ["ast.py", "parser.py", "core.py", "automaton.py", "fields.py", "compiler.py"]
ON_VIOLATION = ("DENY", "REAUTHENTICATE", "MANUAL_REVIEW", "FLAG")
RUNTIMES = ("pdp", "native", "gateway", "harness")
DEFAULT_RUNTIMES = {"request": ("pdp",), "temporal": ("native", "gateway")}
ANNOTATION_KEYS = {"rule", "nl", "source", "on_violation", "permit", "obligation", "runtime", "note", "disabled"}
VUNIT_ANNOTATION_KEYS = {"policy_set", "version", "nl", "source", "note", "runtime"}
DEFAULT_DENY_ID = "R_default_deny"


@dataclass(frozen=True)
class Obligation:
    type: str
    parameters: tuple[tuple[str, Any], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {"type": self.type, "parameters": {k: (list(v) if isinstance(v, tuple) else v)
                                                  for k, v in self.parameters}}


@dataclass
class CompiledRule:
    rule_id: str
    label: str
    kind: str                         # "permit" | "constraint" | "default_deny" | "temporal"
    scope: str
    vunit: str
    psl_file: str
    line: int
    source: str
    nl: str = ""
    origin: str = ""
    note: str = ""
    on_violation: str = "DENY"
    obligations: tuple[Obligation, ...] = ()
    runtimes: tuple[str, ...] = ()
    disabled: str = ""                # non-empty: reason; the rule is evaluated by no runtime
    expr: BExpr | None = None         # request scope: must hold (constraint) / grants (permit)
    applies: BExpr | None = None      # constraint with obligations: antecedent A of always (A -> C)
    monitor: Monitor | None = None    # temporal scope
    aps: tuple[str, ...] = ()


@dataclass
class CompiledPolicySet:
    rules: list[CompiledRule]
    catalog: FieldCatalog
    files: list[str]
    digest: str
    vunits: dict[str, dict[str, str]] = field(default_factory=dict)

    def for_scope(self, scope: str, runtime: str | None = None) -> list[CompiledRule]:
        return [r for r in self.rules if r.scope == scope and not r.disabled
                and (runtime is None or runtime in r.runtimes)]

    def rule(self, rule_id: str) -> CompiledRule:
        for r in self.rules:
            if r.rule_id == rule_id:
                return r
        raise KeyError(rule_id)


# ---------------------------------------------------------------------------
# annotations
# ---------------------------------------------------------------------------
_OBL = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(?:\((.*)\))?$")


def parse_obligation(text: str, where: str) -> Obligation:
    m = _OBL.match(text.strip())
    if not m:
        raise PSLError(f"{where}: bad @obligation {text!r}; expected TYPE or TYPE(key=value, key=[a, b])")
    params: list[tuple[str, Any]] = []
    for part in _split_top((m.group(2) or "").strip()):
        if "=" not in part:
            raise PSLError(f"{where}: bad obligation parameter {part!r}; expected key=value")
        k, v = (x.strip() for x in part.split("=", 1))
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
            raise PSLError(f"{where}: bad obligation parameter name {k!r}")
        params.append((k, _obl_value(v)))
    return Obligation(m.group(1), tuple(params))


def _split_top(body: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in body:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            if cur.strip():
                out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _obl_value(v: str) -> Any:
    if v.startswith("[") and v.endswith("]"):
        return tuple(_obl_value(x) for x in _split_top(v[1:-1]))
    if len(v) >= 2 and v[0] == v[-1] == '"':
        return v[1:-1]
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    if v in ("true", "false"):
        return v == "true"
    return v


def _ann(annotations: Iterable[tuple[str, str]], allowed: set[str], where: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for k, v in annotations:
        if k not in allowed:
            raise PSLError(f"{where}: unknown or misplaced annotation @{k} (allowed here: {sorted(allowed)})")
        out.setdefault(k, []).append(v)
    for k, vs in out.items():
        if k not in ("obligation", "note", "nl") and len(vs) > 1:
            raise PSLError(f"{where}: annotation @{k} given more than once")
    return out


def _runtimes(values: list[str] | None, default: tuple[str, ...], where: str) -> tuple[str, ...]:
    if not values:
        return default
    rts = tuple(dict.fromkeys(x.strip() for x in values[0].split(",") if x.strip()))
    bad = set(rts) - set(RUNTIMES)
    if bad or not rts:
        raise PSLError(f"{where}: @runtime must list some of {RUNTIMES}, got {values[0]!r}")
    return rts


# ---------------------------------------------------------------------------
# policy sets
# ---------------------------------------------------------------------------
def source_digest(files: list[tuple[str, str]], catalog: FieldCatalog) -> str:
    h = hashlib.sha256()
    for name, text in sorted(files):
        h.update(name.encode() + b"\0" + text.encode("utf-8") + b"\0")
    h.update(b"catalog\0" + catalog.digest.encode() + b"\0")
    for f in COMPILER_FILES:
        h.update(f.encode() + b"\0" + (ROOT / f).read_bytes() + b"\0")
    return h.hexdigest()


def atoms_of_core(core: Core) -> list[BExpr]:
    """All Boolean atoms (APs and comparisons) of a core formula."""
    out: list[BExpr] = []

    def sere(r) -> None:
        if isinstance(r, SAtom):
            out.extend(atoms_of(r.b))
        elif isinstance(r, (SCat, SAlt)):
            for x in r.args:
                sere(x)
        elif isinstance(r, SFuse):
            sere(r.left)
            sere(r.right)
        elif isinstance(r, SStar):
            sere(r.arg)

    def walk(f) -> None:
        if isinstance(f, CB):
            out.extend(atoms_of(f.b))
        elif isinstance(f, (CAnd, COr)):
            for x in f.args:
                walk(x)
        elif isinstance(f, (CNext, CDefer, CAlways)):
            walk(f.arg)
        elif isinstance(f, CImp):
            out.extend(atoms_of(f.b))
            walk(f.prop)
        elif isinstance(f, CUntil):
            walk(f.left)
            walk(f.right)
        elif isinstance(f, CSuffix):
            sere(f.sere)
            walk(f.prop)
        elif isinstance(f, CSere):
            sere(f.sere)

    walk(core)
    return list(dict.fromkeys(out))


def bools_of_core(core: Core) -> list[BExpr]:
    """Every Boolean expression evaluated at one step inside a core formula."""
    out: list[BExpr] = []

    def sere(r) -> None:
        if isinstance(r, SAtom):
            out.append(r.b)
        elif isinstance(r, (SCat, SAlt)):
            for x in r.args:
                sere(x)
        elif isinstance(r, SFuse):
            sere(r.left)
            sere(r.right)
        elif isinstance(r, SStar):
            sere(r.arg)

    def walk(f) -> None:
        if isinstance(f, CB):
            out.append(f.b)
        elif isinstance(f, (CAnd, COr)):
            for x in f.args:
                walk(x)
        elif isinstance(f, (CNext, CDefer, CAlways)):
            walk(f.arg)
        elif isinstance(f, CImp):
            out.append(f.b)
            walk(f.prop)
        elif isinstance(f, CUntil):
            walk(f.left)
            walk(f.right)
        elif isinstance(f, CSuffix):
            sere(f.sere)
            walk(f.prop)
        elif isinstance(f, CSere):
            sere(f.sere)

    walk(core)
    return out


def temporal_event_model(sc: ScopeSpec, rule_atoms: Iterable[BExpr]) -> EventModelScope:
    """Event model for automaton construction: per event, the data APs (Boolean
    fields and comparison atoms) that are defined at that event (false elsewhere)."""
    events: dict[str, list[str]] = {e: [] for e in sc.events}
    data: set[str] = set()
    for a in rule_atoms:
        if isinstance(a, BAtom) and a.name in sc.events:
            continue
        fld = a.field if isinstance(a, BCmp) else a.name           # type: ignore[union-attr]
        name = a.ap if isinstance(a, BCmp) else a.name             # type: ignore[union-attr]
        for e in sc.events_with(fld):
            if name not in events[e]:
                events[e].append(name)
        data.add(name)
    return EventModelScope(name=sc.name, events=events, data_aps=data)


def compile_policy_set(sources: list[tuple[str, str]], catalog: FieldCatalog, *,
                       max_states: int = 5000) -> CompiledPolicySet:
    rules: list[CompiledRule] = []
    ids: dict[str, str] = {}
    vunits: dict[str, dict[str, str]] = {}
    temporal_pending: list[tuple[CompiledRule, Core]] = []

    def register(r: CompiledRule, where: str) -> None:
        if r.rule_id in ids:
            raise PSLError(f"{where}: duplicate rule id {r.rule_id!r} (also {ids[r.rule_id]})")
        ids[r.rule_id] = where
        rules.append(r)

    for fname, text in sources:
        for vu in parse(text, fname):
            sc = catalog.scopes.get(vu.scope)
            if sc is None:
                raise PSLError(f"vunit {vu.name} is bound to scope {vu.scope!r}, which the field catalogue does not "
                               f"declare ({sorted(catalog.scopes)})", vu.pos)
            if vu.name in vunits:
                raise PSLError(f"duplicate vunit name {vu.name}", vu.pos)
            va = _ann(vu.annotations, VUNIT_ANNOTATION_KEYS, f"{vu.pos}")
            vunits[vu.name] = {k: " ".join(v) for k, v in va.items()} | {"scope": vu.scope, "file": fname}
            vu_runtimes = _runtimes(va.get("runtime"), DEFAULT_RUNTIMES[sc.kind], f"{vu.pos}")

            for d in vu.properties:
                where = f"{d.pos} property {d.name}"
                a = _ann(d.annotations, ANNOTATION_KEYS - {"on_violation"}, where)
                if "permit" not in a:
                    if set(a) - {"note", "nl", "source"}:
                        raise PSLError(f"{where}: @obligation/@rule/@runtime need @permit (helper properties "
                                       f"are inlined where they are used)")
                    continue
                if a["permit"] != [""]:
                    raise PSLError(f"{where}: @permit takes no value")
                if sc.kind != "request":
                    raise PSLError(f"{where}: @permit properties are only allowed in request scopes")
                if not is_bool(d.prop):
                    raise PSLError(f"{where}: a permission must be a boolean expression")
                b = to_bool(d.prop)
                catalog.check(vu.scope, b, where)
                register(CompiledRule(
                    rule_id=a.get("rule", [d.name])[0], label=d.name, kind="permit", scope=vu.scope, vunit=vu.name,
                    psl_file=fname, line=d.pos.line, source=d.source, nl=" ".join(a.get("nl", [])),
                    origin=a.get("source", [""])[0], note=" ".join(a.get("note", [])),
                    obligations=tuple(parse_obligation(o, where) for o in a.get("obligation", [])),
                    runtimes=_runtimes(a.get("runtime"), vu_runtimes, where), expr=b,
                    disabled=a.get("disabled", [""])[0], aps=tuple(sorted(b.aps()))), where)

            for asr in vu.assertions:
                where = f"{asr.pos} assertion {asr.label}"
                a = _ann(asr.annotations, ANNOTATION_KEYS - {"permit"}, where)
                ov = a.get("on_violation", ["DENY"])[0].strip().upper()
                if ov not in ON_VIOLATION:
                    raise PSLError(f"{where}: @on_violation must be one of {ON_VIOLATION}, got {ov!r}")
                core = desugar(asr.prop)
                common = dict(rule_id=a.get("rule", [asr.label])[0], label=asr.label, scope=vu.scope,
                              vunit=vu.name, psl_file=fname, line=asr.pos.line, source=asr.source,
                              nl=" ".join(a.get("nl", [])), origin=a.get("source", [""])[0],
                              note=" ".join(a.get("note", [])), on_violation=ov,
                              runtimes=_runtimes(a.get("runtime"), vu_runtimes, where),
                              disabled=a.get("disabled", [""])[0],
                              obligations=tuple(parse_obligation(o, where) for o in a.get("obligation", [])))
                if sc.kind == "request":
                    if not (isinstance(core, CAlways) and isinstance(core.arg, CB)):
                        raise PSLError(f"{where}: rules in request scope {vu.scope} must be invariants "
                                       f"'always <boolean>' or 'never <boolean>' (one authorization request is "
                                       f"one step); temporal rules belong in a temporal scope")
                    b = core.arg.b
                    catalog.check(vu.scope, b, where)
                    applies = None
                    if common["obligations"]:
                        if not isinstance(b, BImp):
                            raise PSLError(f"{where}: @obligation on an assertion needs the form "
                                           f"'always (A -> C)' (obligations apply when A holds)")
                        applies = b.left
                    register(CompiledRule(kind="constraint", expr=b, applies=applies,
                                          aps=tuple(sorted(b.aps())), **common), where)
                else:
                    if common["obligations"]:
                        raise PSLError(f"{where}: @obligation is only supported on request-scope rules")
                    for atom in atoms_of_core(core):
                        catalog.check(vu.scope, atom, where)
                    for bexpr in bools_of_core(core):
                        catalog.check_conjunctions(vu.scope, bexpr, where)
                    r = CompiledRule(kind="temporal", **common)
                    register(r, where)
                    temporal_pending.append((r, core))

    # default deny, one per request scope
    request_scopes = [s for s in catalog.scopes.values() if s.kind == "request"]
    for sc in request_scopes:
        scope_rules = [r for r in rules if r.scope == sc.name]
        if not scope_rules:
            continue
        if not sc.default_deny:
            if any(r.kind == "permit" for r in scope_rules):
                raise PSLError(f"scope {sc.name} is check-only (default_deny: false); @permit has no meaning there")
            continue
        permits = [r for r in scope_rules if r.kind == "permit" and not r.disabled]
        event = next(iter(sc.events))
        body: BExpr = BConst(False)
        for i, p in enumerate(permits):
            body = p.expr if i == 0 else BOr(body, p.expr)  # type: ignore[arg-type]
        expr = BImp(BAtom(event), body)
        names = " || ".join(p.label for p in permits) or "false"
        deny_scopes = [s for s in request_scopes if s.default_deny]
        rid = DEFAULT_DENY_ID if len(deny_scopes) == 1 else f"{DEFAULT_DENY_ID}.{sc.name}"
        register(CompiledRule(
            rule_id=rid, label=DEFAULT_DENY_ID, kind="default_deny", scope=sc.name, vunit="<generated>",
            psl_file="<generated>", line=0, source=f"always ({event} -> ({names}))",
            nl="Deny unless at least one permission holds (default deny).", on_violation="DENY",
            runtimes=tuple(sorted({rt for r in scope_rules for rt in r.runtimes})), expr=expr,
            aps=tuple(sorted(expr.aps()))), f"<generated default deny for {sc.name}>")

    for r, core in temporal_pending:
        em = temporal_event_model(catalog.scopes[r.scope], atoms_of_core(core))
        try:
            r.monitor = build(r.rule_id, r.vunit, em, core, source=r.source, psl_file=r.psl_file,
                              line=r.line, max_states=max_states)
        except ValueError as exc:
            raise PSLError(f"{r.psl_file}:{r.line}: {exc}") from exc
        r.aps = tuple(r.monitor.aps)
    return CompiledPolicySet(rules=rules, catalog=catalog, files=[f for f, _ in sources],
                             digest=source_digest(sources, catalog), vunits=vunits)


def load_policy_set(files: list[Path], catalog_path: Path) -> CompiledPolicySet:
    catalog = FieldCatalog.load(catalog_path)
    return compile_policy_set([(p.name, p.read_text(encoding="utf-8")) for p in files], catalog)


# ---------------------------------------------------------------------------
# description (generated documentation of a compiled policy set)
# ---------------------------------------------------------------------------
def describe(ps: CompiledPolicySet, title: str = "PSL policy set") -> str:
    lines = [f"# {title}", "",
             f"Generated from {', '.join(ps.files)} + field catalogue `{Path(ps.catalog.origin).name}` "
             f"(source sha256 `{ps.digest[:16]}`). Do not edit.", "",
             "| rule | kind | scope | on violation | runtimes | file:line |", "|---|---|---|---|---|---|"]
    for r in ps.rules:
        lines.append(f"| `{r.rule_id}` | {r.kind}{' (DISABLED)' if r.disabled else ''} | {r.scope} | "
                     f"{r.on_violation if r.kind != 'permit' else '--'} | "
                     f"{'none' if r.disabled else ', '.join(r.runtimes)} | {r.psl_file}:{r.line} |")
    for r in ps.rules:
        lines += ["", f"## `{r.rule_id}` ({r.kind})", ""]
        if r.nl:
            lines += [f"> {r.nl}", ""]
        if r.disabled:
            lines += [f"**DISABLED** (evaluated by no runtime): {r.disabled}", ""]
        lines += ["```psl", r.source, "```", ""]
        if r.obligations:
            lines.append("obligations: " + ", ".join(json.dumps(o.as_dict(), sort_keys=True) for o in r.obligations))
        if r.monitor is not None:
            m = r.monitor
            lines.append(f"monitor: {len(m.delta)} states, {len(m.letters)} letters; verdicts `{''.join(m.verdict)}`")
        else:
            lines.append(f"atomic propositions: {', '.join(f'`{a}`' for a in r.aps) or '--'}")
        if r.origin:
            lines.append(f"source: {r.origin}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# plain event-model compilation (pure-AP scopes; used by the subset tests)
# ---------------------------------------------------------------------------
def load_event_model(path: Path) -> dict[str, EventModelScope]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    out = {}
    for name, sc in raw["scopes"].items():
        events = {e: list(v.get("data", [])) for e, v in sc["events"].items()}
        data = set(sc.get("data_aps", {}))
        for e, ds in events.items():
            missing = set(ds) - data
            if missing:
                raise PSLError(f"event model: event {e} of scope {name} uses undeclared data APs {sorted(missing)}")
        overlap = set(events) & data
        if overlap:
            raise PSLError(f"event model: names used both as event and data AP in {name}: {sorted(overlap)}")
        out[name] = EventModelScope(name=name, events=events, data_aps=data)
    return out


def compile_sources(sources: list[tuple[str, str]], scopes: dict[str, EventModelScope]) -> list[Monitor]:
    monitors: list[Monitor] = []
    seen: dict[tuple[str, str], str] = {}
    for fname, text in sources:
        for vu in parse(text, fname):
            if vu.scope not in scopes:
                raise PSLError(f"vunit {vu.name} is bound to unknown scope '{vu.scope}'", vu.pos)
            for a in vu.assertions:
                k = (vu.scope, a.label)
                if k in seen:
                    raise PSLError(f"duplicate property_id {a.label} in scope {vu.scope} "
                                   f"(also in vunit {seen[k]})", a.pos)
                seen[k] = vu.name
                core = desugar(a.prop)
                try:
                    m = build(a.label, vu.name, scopes[vu.scope], core, source=a.source, psl_file=fname,
                              line=a.pos.line)
                except ValueError as exc:
                    raise PSLError(str(exc), a.pos) from exc
                monitors.append(m)
    return monitors


def monitor_to_dict(m: Monitor) -> dict[str, Any]:
    return {
        "property_id": m.property_id, "vunit": m.vunit, "scope": m.scope, "source": m.source,
        "psl_file": m.psl_file, "line": m.line, "core": m.core_text, "aps": m.aps,
        "letters": [{k: v for k, v in sorted(l.items()) if v} for l in m.letters],
        "letter_of": m.letter_of, "data_for_event": m.data_for_event, "initial": m.initial,
        "delta": m.delta, "verdict": "".join(m.verdict), "close": [int(c) for c in m.close],
        "residuals": m.residuals, "stats": m.stats,
    }
