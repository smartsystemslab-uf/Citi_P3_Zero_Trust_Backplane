"""Field catalogue: the declared, typed and trusted inputs of PSL policies.

A policy may only mention

* the events of its scope (``authz_request`` in a request scope; trusted runtime
  events in a temporal scope), and
* fields declared in the catalogue -- Boolean fields as atomic propositions,
  any field in a comparison ``FIELD op LITERAL``.

Each field records its type and its *trusted source* (who computes it). Unknown
fields, comparisons that do not fit the field type, and enum literals outside
the declared values are compile errors. At evaluation time a field that a rule
needs but the runtime did not supply raises :class:`UnboundField` (fail closed).

Catalogue file (YAML)::

    catalog_version: 1
    windows: {NAME: {timezone: ..., days: [MON, ...], start: "08:00", end: "18:00"}}
    scopes:
      pdp_request:
        kind: request                 # request rules: invariants checked per request
        default_deny: true            # (default) deny unless a @permit holds; false = check-only scope
        events: {authz_request: [subject.id, ...]}     # or "*" = every field
        fields:
          subject.id: {type: string, source: "..."}
          subject.role.*: {type: bool, source: "...", missing: false}   # field family
          risk.level: {type: enum, values: [low, medium, high, critical], source: "..."}
      workflow_run:
        kind: temporal
        key: [workflow_run_id, batch_id]
        events: {readiness_checked: [ready], ledger_admitted: []}
        fields: {ready: {type: bool, source: "..."}}
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, time
from pathlib import Path
from typing import Any, Callable, Mapping

import yaml

from .ast import BAnd, BAtom, BCmp, BConst, BExpr, BIff, BImp, BNot, BOr
from .parser import PSLError

FIELD_TYPES = ("string", "int", "bool", "enum")
SCOPE_KINDS = ("request", "temporal")
_OPS_BY_TYPE = {"string": {"==", "!="}, "enum": {"==", "!="}, "bool": {"==", "!="},
                "int": {"==", "!=", "<", "<=", ">", ">="}}
_DAYS = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")


class UnboundField(KeyError):
    """A rule needs a field the runtime did not supply. Callers must fail closed."""

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name

    def __str__(self) -> str:
        return f"PSL field not supplied by the runtime: {self.name}"


@dataclass(frozen=True)
class FieldSpec:
    name: str                       # exact name, or a family "prefix.*"
    type: str
    source: str
    values: tuple[str, ...] = ()    # enum members
    missing: str = "error"          # "error" (UnboundField) | "false" (bool families only)
    description: str = ""

    @property
    def family(self) -> bool:
        return self.name.endswith(".*")


@dataclass
class ScopeSpec:
    name: str
    kind: str
    events: dict[str, tuple[str, ...]]      # event -> fields defined at that event
    fields: dict[str, FieldSpec]
    key: tuple[str, ...] = ()
    description: str = ""
    default_deny: bool = True        # request scopes: deny unless a permission holds

    def spec(self, name: str) -> FieldSpec | None:
        if name in self.fields:
            return self.fields[name]
        parts = name.split(".")
        for i in range(len(parts) - 1, 0, -1):
            fam = ".".join(parts[:i]) + ".*"
            if fam in self.fields:
                return self.fields[fam]
        return None

    def events_with(self, field: str) -> list[str]:
        sp = self.spec(field)
        if sp is None:
            return []
        return [e for e, fs in self.events.items() if field in fs or sp.name in fs]


class FieldCatalog:
    def __init__(self, raw: Mapping[str, Any], origin: str = "<catalog>", digest: str = "") -> None:
        if raw.get("catalog_version") != 1:
            raise PSLError(f"{origin}: unsupported catalog_version {raw.get('catalog_version')!r} (expected 1)")
        self.origin = origin
        self.digest = digest
        self.windows: dict[str, dict[str, Any]] = {}
        for name, w in (raw.get("windows") or {}).items():
            days = [str(d).upper() for d in w.get("days", [])]
            if not days or set(days) - set(_DAYS):
                raise PSLError(f"{origin}: window {name}: days must be a subset of {_DAYS}")
            self.windows[name] = {"timezone": str(w["timezone"]), "days": days,
                                  "start": time.fromisoformat(str(w["start"])),
                                  "end": time.fromisoformat(str(w["end"]))}
        self.scopes: dict[str, ScopeSpec] = {}
        for sname, sc in (raw.get("scopes") or {}).items():
            kind = sc.get("kind")
            if kind not in SCOPE_KINDS:
                raise PSLError(f"{origin}: scope {sname}: kind must be one of {SCOPE_KINDS}")
            fields: dict[str, FieldSpec] = {}
            for fname, f in (sc.get("fields") or {}).items():
                ftype = f.get("type")
                if ftype not in FIELD_TYPES:
                    raise PSLError(f"{origin}: field {fname}: type must be one of {FIELD_TYPES}")
                if not f.get("source"):
                    raise PSLError(f"{origin}: field {fname}: a trusted 'source' is required")
                values = tuple(str(v) for v in f.get("values", ()))
                if ftype == "enum" and not values:
                    raise PSLError(f"{origin}: enum field {fname} needs 'values'")
                missing = str(f.get("missing", "error")).lower()
                if missing not in ("error", "false"):
                    raise PSLError(f"{origin}: field {fname}: missing must be 'error' or 'false'")
                if missing == "false" and ftype != "bool":
                    raise PSLError(f"{origin}: field {fname}: missing: false is only allowed for bool fields")
                fields[fname] = FieldSpec(fname, ftype, str(f["source"]), values, missing, str(f.get("description", "")))
            events: dict[str, tuple[str, ...]] = {}
            for ev, evfields in (sc.get("events") or {}).items():
                if evfields == "*":
                    events[ev] = tuple(fields)
                    continue
                for fn in evfields or []:
                    if fn not in fields:
                        raise PSLError(f"{origin}: scope {sname}: event {ev} lists undeclared field {fn}")
                events[ev] = tuple(evfields or ())
            if not events:
                raise PSLError(f"{origin}: scope {sname} declares no events")
            overlap = set(events) & set(fields)
            if overlap:
                raise PSLError(f"{origin}: scope {sname}: names used both as event and field: {sorted(overlap)}")
            if kind == "request" and len(events) != 1:
                raise PSLError(f"{origin}: request scope {sname} must have exactly one event")
            dd = sc.get("default_deny", True)
            if not isinstance(dd, bool) or (kind == "temporal" and "default_deny" in sc):
                raise PSLError(f"{origin}: scope {sname}: default_deny is a boolean of request scopes")
            self.scopes[sname] = ScopeSpec(sname, kind, events, fields, tuple(sc.get("key", ())),
                                           str(sc.get("description", "")), dd)

    @classmethod
    def load(cls, path: str | Path) -> "FieldCatalog":
        p = Path(path)
        data = p.read_bytes()
        return cls(yaml.safe_load(data.decode("utf-8")) or {}, str(p), hashlib.sha256(data).hexdigest())

    # -- static checks ---------------------------------------------------------
    def check(self, scope: str, b: BExpr, where: str) -> None:
        sc = self.scopes.get(scope)
        if sc is None:
            raise PSLError(f"{where}: unknown scope {scope!r}")
        for atom in _atoms(b):
            if isinstance(atom, BAtom):
                if atom.name in sc.events:
                    continue
                sp = sc.spec(atom.name)
                if sp is None:
                    raise PSLError(f"{where}: unknown field or event {atom.name!r} in scope {scope}")
                if sp.type != "bool":
                    raise PSLError(f"{where}: {atom.name!r} is a {sp.type} field; use a comparison "
                                   f"(e.g. {atom.name} == ...)")
                if sc.kind == "temporal" and not sc.events_with(atom.name):
                    raise PSLError(f"{where}: field {atom.name!r} is not defined at any event of scope {scope}")
            elif isinstance(atom, BCmp):
                if atom.field in sc.events:
                    raise PSLError(f"{where}: {atom.field!r} is an event, not a field")
                sp = sc.spec(atom.field)
                if sp is None:
                    raise PSLError(f"{where}: unknown field {atom.field!r} in scope {scope}")
                if atom.op not in _OPS_BY_TYPE[sp.type]:
                    raise PSLError(f"{where}: operator {atom.op} is not defined for {sp.type} field {atom.field}")
                v = atom.value
                ok = {"string": isinstance(v, str), "enum": isinstance(v, str),
                      "bool": isinstance(v, bool), "int": isinstance(v, int) and not isinstance(v, bool)}[sp.type]
                if not ok:
                    raise PSLError(f"{where}: literal {v!r} does not fit {sp.type} field {atom.field}")
                if sp.type == "enum" and v not in sp.values:
                    raise PSLError(f"{where}: {v!r} is not a value of enum field {atom.field} {list(sp.values)}")
                if sc.kind == "temporal" and not sc.events_with(atom.field):
                    raise PSLError(f"{where}: field {atom.field!r} is not defined at any event of scope {scope}")

    def check_conjunctions(self, scope: str, b: BExpr, where: str) -> None:
        """Temporal scopes: one step has exactly one event, and a field is false at events
        that do not define it. A conjunction (as written) that requires two different
        events, or an event together with a non-negated field that event does not define,
        can never hold -- it is reported instead of silently making a rule false or vacuous."""
        sc = self.scopes[scope]
        if sc.kind != "temporal":
            return
        for conj in _conjunctions(b):
            pos_events = {a.name for neg, a in conj if not neg and isinstance(a, BAtom) and a.name in sc.events}
            if len(pos_events) > 1:
                raise PSLError(f"{where}: conjunction requires events {sorted(pos_events)} at the same step "
                               f"(one event per step): it can never hold")
            if len(pos_events) == 1:
                ev = next(iter(pos_events))
                for neg, a in conj:
                    if neg or (isinstance(a, BAtom) and a.name in sc.events):
                        continue
                    fld = a.field if isinstance(a, BCmp) else a.name        # type: ignore[union-attr]
                    if ev not in sc.events_with(fld):
                        raise PSLError(f"{where}: field {fld!r} is not defined at event {ev!r}, so "
                                       f"'{ev} && {a.text()}' can never hold")

    def windows_at(self, when: datetime) -> dict[str, bool]:
        """Values of the ``time.in.<window>`` fields at a server-side timestamp.
        Same semantics as PDP's matcher: start and end inclusive; a window with
        start > end spans midnight."""
        from zoneinfo import ZoneInfo
        out = {}
        for name, w in self.windows.items():
            local = when.astimezone(ZoneInfo(w["timezone"]))
            cur = local.time().replace(tzinfo=None)
            start, end = w["start"], w["end"]
            within = start <= cur <= end if start <= end else (cur >= start or cur <= end)
            out[f"time.in.{name}"] = _DAYS[local.weekday()] in w["days"] and within
        return out


def _atoms(b: BExpr):
    if isinstance(b, (BAtom, BCmp)):
        yield b
    elif isinstance(b, BConst):
        return
    elif isinstance(b, BNot):
        yield from _atoms(b.arg)
    elif isinstance(b, (BAnd, BOr, BImp, BIff)):
        yield from _atoms(b.left)
        yield from _atoms(b.right)
    else:  # pragma: no cover
        raise PSLError(f"internal: unexpected boolean node {type(b).__name__}")


def _conjunctions(b: BExpr):
    """Every conjunction AS WRITTEN (a chain of &&), as (negated, atom) literals, anywhere in
    b -- in either polarity: an impossible conjunction makes a rule false when used
    positively and vacuously true when negated; both are policy bugs."""
    if isinstance(b, BAnd):
        lits: list[tuple[bool, BExpr]] = []
        stack: list[BExpr] = [b]
        while stack:
            x = stack.pop()
            if isinstance(x, BAnd):
                stack += [x.left, x.right]
            elif isinstance(x, (BAtom, BCmp)):
                lits.append((False, x))
            elif isinstance(x, BNot) and isinstance(x.arg, (BAtom, BCmp)):
                lits.append((True, x.arg))
            else:
                yield from _conjunctions(x)
        yield lits
    elif isinstance(b, BNot):
        yield from _conjunctions(b.arg)
    elif isinstance(b, (BOr, BImp, BIff)):
        yield from _conjunctions(b.left)
        yield from _conjunctions(b.right)
    elif isinstance(b, (BAtom, BCmp)):
        yield [(False, b)]


def atoms_of(b: BExpr) -> list[BExpr]:
    return list(dict.fromkeys(_atoms(b)))


# ---------------------------------------------------------------------------
# Binder: field values -> AP valuation
# ---------------------------------------------------------------------------
_CMP: dict[str, Callable[[Any, Any], bool]] = {
    "==": lambda a, b: a == b, "!=": lambda a, b: a != b, "<": lambda a, b: a < b,
    "<=": lambda a, b: a <= b, ">": lambda a, b: a > b, ">=": lambda a, b: a >= b}


class Binder:
    """Computes the truth value of every AP a set of rules uses, from one event and
    the field values the runtime supplied with it. Equality tests on the same field
    are grouped so each field is read once."""

    def __init__(self, scope: ScopeSpec, atoms: list[BExpr]) -> None:
        self.scope = scope
        self.event_aps = sorted({a.name for a in atoms if isinstance(a, BAtom) and a.name in scope.events})
        self.bool_fields = sorted({a.name for a in atoms if isinstance(a, BAtom) and a.name not in scope.events})
        eq: dict[str, dict[Any, list[str]]] = {}
        ne: dict[str, dict[Any, list[str]]] = {}
        other: list[tuple[str, str, Callable[[Any, Any], bool], Any]] = []
        for a in atoms:
            if not isinstance(a, BCmp):
                continue
            if a.op == "==":
                eq.setdefault(a.field, {}).setdefault(a.value, []).append(a.ap)
            elif a.op == "!=":
                ne.setdefault(a.field, {}).setdefault(a.value, []).append(a.ap)
            else:
                other.append((a.ap, a.field, _CMP[a.op], a.value))
        self.eq, self.ne, self.other = eq, ne, other
        self.fields_needed = sorted(set(self.bool_fields) | set(eq) | set(ne) | {o[1] for o in other})

    def _get(self, fields: Mapping[str, Any], name: str) -> Any:
        if name in fields:
            return fields[name]
        sp = self.scope.spec(name)
        if sp is not None and sp.missing == "false":
            return False
        raise UnboundField(name)

    def bind(self, event: str, fields: Mapping[str, Any]) -> dict[str, bool]:
        if event not in self.scope.events:
            raise KeyError(f"event {event!r} is not in scope {self.scope.name}")
        v: dict[str, bool] = {e: (e == event) for e in self.event_aps}
        for name in self.bool_fields:
            val = self._get(fields, name)
            if not isinstance(val, bool):
                raise TypeError(f"PSL field {name} must be a boolean, got {val!r}")
            v[name] = val
        for name, table in self.eq.items():
            val = self._get(fields, name)
            for lit, aps in table.items():
                hit = val == lit and type(val) is type(lit)
                for ap in aps:
                    v[ap] = hit
        for name, table in self.ne.items():
            val = self._get(fields, name)
            for lit, aps in table.items():
                hit = not (val == lit and type(val) is type(lit))
                for ap in aps:
                    v[ap] = hit
        for ap, name, fn, lit in self.other:
            val = self._get(fields, name)
            if isinstance(val, bool) or not isinstance(val, int):
                raise TypeError(f"PSL field {name} must be an integer, got {val!r}")
            v[ap] = fn(val, lit)
        return v
