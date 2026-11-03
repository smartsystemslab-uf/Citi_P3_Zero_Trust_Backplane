"""Translate controlled-natural-language policy intents (Task 1 ``policy_intent.yaml``)
into PSL, deterministically, using an explicit bindings file.

Grammar of one condition (whitespace-normalised). Whole-phrase bindings are tried
first -- for the condition and for every atom inside NOT( ... ):

    condition := phrase                                     (bindings: phrases / prerequisites / realized_by)
               | "NOT (" atom { "AND" atom } ")"
               | atom
    atom      := phrase
               | PATH "is present and non-empty"
               | PATH "is present and len(" PATH ") >=" INT
               | PATH "is a finite non-zero number"
               | PATH ( "==" | "!=" ) VALUE
               | PATH "in [" VALUE { "," VALUE } "]"

Each translated condition belongs to one scope of the field catalogue. A rule is split
into one PSL rule per request scope (``always (BOUNDARY && SUBJECT -> conditions)`` for
allow rules, ``never (BOUNDARY && SUBJECT && conditions)`` for deny rules) and, if it
has workflow prerequisites, one temporal rule
``(evidence_1 before ADMISSION) && (evidence_2 before ADMISSION) ...``.

Anything not covered by the grammar or the bindings raises IntentError naming the rule
and the text -- nothing is guessed or dropped. Rules listed under ``disabled`` are
translated and compiled but annotated ``@disabled`` with the reason.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

ON_FAIL = {"deny": "DENY", "require_manual_review": "MANUAL_REVIEW", "allow_with_flag": "FLAG"}
SCOPE_RUNTIME = {"pdp_request": "pdp", "gateway_input": "gateway", "gateway_output": "gateway",
                 "gateway_tool": "gateway", "workflow_run": "native,gateway", "harness_output": "harness"}
SCOPE_ORDER = ["pdp_request", "gateway_input", "gateway_tool", "gateway_output", "harness_output"]
_VALUE = r"[A-Za-z0-9_.\-]+"


class IntentError(ValueError):
    pass


@dataclass
class RulePart:
    scope: str
    rule_id: str
    label: str
    body: str
    on_violation: str
    obligations: list[str]
    notes: list[str] = field(default_factory=list)


@dataclass
class RuleTranslation:
    intent_id: str
    description: str
    parts: list[RulePart] = field(default_factory=list)
    realized_by: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    disabled: str = ""
    conditions: list[tuple[str, str, str]] = field(default_factory=list)   # (text, scope, psl)


def _norm(text: str) -> str:
    return " ".join(str(text).split())


def _label(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", text)


def _lit(v: str) -> str:
    if v in ("true", "false"):
        return v
    if re.fullmatch(r"-?\d+", v):
        return v
    return '"' + v + '"'


class IntentTranslator:
    def __init__(self, bindings: dict[str, Any]) -> None:
        if bindings.get("bindings_version") != 1:
            raise IntentError("unsupported bindings_version (expected 1)")
        self.b = bindings
        self.phrases = {_norm(k): v for k, v in (bindings.get("phrases") or {}).items()}
        self.prereq = {_norm(k): v for k, v in (bindings.get("prerequisites") or {}).items()}
        self.realized = {_norm(k): v for k, v in (bindings.get("realized_by") or {}).items()}

    # -- atoms ----------------------------------------------------------------
    def _field(self, path: str, scopes: list[str], rid: str) -> tuple[str, str]:
        binding = (self.b.get("fields") or {}).get(path)
        if not binding:
            raise IntentError(f"{rid}: field {path!r} is not bound (bindings: fields)")
        for s in scopes:
            if s in binding:
                return s, binding[s]
        return next(iter(binding.items()))

    def _checked(self, path: str, scopes: list[str], rid: str) -> tuple[str, str]:
        binding = (self.b.get("checked_fields") or {}).get(path)
        if not binding:
            raise IntentError(f"{rid}: field {path!r} is not bound (bindings: checked_fields)")
        for s in scopes:
            if s in binding:
                return s, binding[s]
        return next(iter(binding.items()))

    def atom(self, text: str, scopes: list[str], rid: str) -> tuple[str, str]:
        """(scope, PSL Boolean) of one atom."""
        t = _norm(text)
        if t in self.phrases:
            for s in scopes:
                if s in self.phrases[t]:
                    return s, self.phrases[t][s]
            return next(iter(self.phrases[t].items()))
        m = re.fullmatch(r"([A-Za-z_][\w.]*) is present and non-empty", t)
        if m:
            s, f = self._checked(m.group(1), scopes, rid)
            return s, f"{f}.nonempty"
        m = re.fullmatch(r"([A-Za-z_][\w.]*) is present and len\(([A-Za-z_][\w.]*)\) >= (\d+)", t)
        if m:
            if m.group(1) != m.group(2):
                raise IntentError(f"{rid}: 'X is present and len(Y)' needs X == Y: {t!r}")
            s, f = self._checked(m.group(1), scopes, rid)
            return s, f"{f}.length >= {int(m.group(3))}"
        m = re.fullmatch(r"([A-Za-z_][\w.]*) is a finite non-zero number", t)
        if m:
            s, f = self._checked(m.group(1), scopes, rid)
            return s, f"{f}.finite_nonzero"
        m = re.fullmatch(rf"([A-Za-z_][\w.]*) (==|!=) ({_VALUE})", t)
        if m:
            s, f = self._field(m.group(1), scopes, rid)
            return s, f"{f} {m.group(2)} {_lit(m.group(3))}"
        m = re.fullmatch(rf"([A-Za-z_][\w.]*) in \[\s*({_VALUE}(?:\s*,\s*{_VALUE})*)\s*\]", t)
        if m:
            s, f = self._field(m.group(1), scopes, rid)
            vals = [v.strip() for v in m.group(2).split(",")]
            body = " || ".join(f"{f} == {_lit(v)}" for v in vals)
            return s, f"({body})" if len(vals) > 1 else body
        raise IntentError(f"{rid}: condition not covered by the controlled grammar or the bindings: {t!r}")

    # -- rules ----------------------------------------------------------------
    def translate_rule(self, r: dict[str, Any]) -> RuleTranslation:
        rid = str(r["rule_id"])
        key = f"{r['resource']}/{r['action']}"
        res = (self.b.get("resources") or {}).get(key)
        if res is None:
            raise IntentError(f"{rid}: resource/action {key!r} is not bound (bindings: resources)")
        subj = (self.b.get("subjects") or {}).get(str(r["subject"]))
        if subj is None:
            raise IntentError(f"{rid}: subject {r['subject']!r} is not bound (bindings: subjects)")
        decision = str(r.get("decision", "allow")).lower()
        if decision not in ("allow", "deny"):
            raise IntentError(f"{rid}: decision must be allow or deny")
        fail = str(r.get("on_condition_fail", "deny")).lower()
        if fail not in ON_FAIL:
            raise IntentError(f"{rid}: on_condition_fail must be one of {sorted(ON_FAIL)}")
        tr = RuleTranslation(rid, _norm(r.get("description", "")))
        tr.disabled = _norm((self.b.get("disabled") or {}).get(rid, ""))
        scopes = [s for s in SCOPE_ORDER if s in res]
        by_scope: dict[str, list[str]] = {}
        evidence: list[str] = []
        for cond in r.get("conditions") or []:
            t = _norm(cond)
            if t in self.realized:
                tr.realized_by.append(f"{t} -> {_norm(self.realized[t])}")
                tr.conditions.append((t, "realized", _norm(self.realized[t])))
                continue
            if t in self.prereq:
                p = self.prereq[t]
                if "note" in p:
                    tr.notes.append(f"{t}: {p['note']}")
                if "workflow_run" in p:
                    if p["workflow_run"] not in evidence:
                        evidence.append(p["workflow_run"])
                    tr.conditions.append((t, "workflow_run", p["workflow_run"]))
                if "pdp_request" in p:
                    by_scope.setdefault("pdp_request", []).append(p["pdp_request"])
                    tr.conditions.append((t, "pdp_request", p["pdp_request"]))
                continue
            if t.startswith("session_state."):
                raise IntentError(f"{rid}: session_state condition without a trusted prerequisite binding: {t!r}")
            m = re.fullmatch(r"NOT \((.*)\)", t)
            if m:
                parts = [x.strip() for x in re.split(r"\s+AND\s+", m.group(1))]
                done = [self.atom(x, scopes, rid) for x in parts]
                if len({s for s, _ in done}) != 1:
                    raise IntentError(f"{rid}: NOT(...) mixes scopes: {t!r}")
                s = done[0][0]
                psl = "!(" + " && ".join(e for _, e in done) + ")"
            else:
                s, psl = self.atom(t, scopes, rid)
            by_scope.setdefault(s, []).append(psl)
            tr.conditions.append((t, s, psl))
        obligations = [str(o) for o in (r.get("obligations") or [])]
        for s in [x for x in SCOPE_ORDER if x in by_scope]:
            if s not in res:
                raise IntentError(f"{rid}: conditions in scope {s} but resource {key!r} has no boundary there")
            boundary = res[s]
            if r["subject"] != "*" and s not in subj:
                raise IntentError(f"{rid}: subject {r['subject']!r} is not bound in scope {s}")
            # an empty binding means: the scope's boundary already identifies the operation
            subj_cond = (subj.get(s) or None) if r["subject"] != "*" else None
            ante = " && ".join(x for x in (boundary, subj_cond) if x)
            conds = by_scope[s]
            if decision == "allow":
                body = f"always ({ante} -> {' && '.join(conds)})"
                ov = ON_FAIL[fail]
                obls = obligations
            else:
                body = f"never ({ante} && {' && '.join(conds)})"
                ov = "DENY"
                obls = []
                if obligations:
                    tr.notes.append(f"obligations {obligations} of a deny rule are not attached (the request is denied)")
            n_req = len([x for x in SCOPE_ORDER if x in by_scope])
            prid = f"intent.{rid}" if n_req == 1 else f"intent.{rid}.{s}"
            tr.parts.append(RulePart(s, prid, _label(f"intent_{rid}" + ("" if n_req == 1 else f"_{s}")), body, ov, obls))
        if evidence:
            if decision != "allow":
                raise IntentError(f"{rid}: workflow prerequisites on a deny rule are not supported")
            adm = res.get("workflow_run")
            if adm is None:
                raise IntentError(f"{rid}: prerequisites need an admission event for {key!r} (bindings: resources)")
            event = re.match(r"\s*([A-Za-z_]\w*)", adm).group(1)          # admission event of the operation
            sw = None
            if r["subject"] != "*":
                wb = subj.get("workflow_run")
                if wb is None:
                    raise IntentError(f"{rid}: subject {r['subject']!r} is not bound in scope workflow_run")
                sw = wb.get(event) if isinstance(wb, dict) else wb
                if sw is None:
                    raise IntentError(f"{rid}: subject {r['subject']!r} has no workflow_run binding for event {event!r}")
            admission = f"{adm} && {sw}" if sw and sw not in adm else adm
            body = " && ".join(f"(({e}) before ({admission}))" for e in evidence)
            notes = []
            if fail != "deny":
                notes.append(f"on_condition_fail={fail}: a temporal prerequisite can only be enforced by refusing "
                             f"the admission (DENY)")
            if obligations and not by_scope:
                notes.append(f"obligations {obligations} are not attached to temporal rules")
            tr.parts.append(RulePart("workflow_run", f"intent.{rid}.order", _label(f"intent_{rid}_order"), body,
                                     "DENY", [], notes))
        if not tr.parts and not tr.realized_by:
            raise IntentError(f"{rid}: no condition translated")
        return tr

    def translate(self, intent: dict[str, Any]) -> list[RuleTranslation]:
        rules = intent.get("policy_rules") or []
        ids = [str(r["rule_id"]) for r in rules]
        if len(ids) != len(set(ids)):
            raise IntentError("duplicate rule_id in the intent file")
        unknown_disabled = set(self.b.get("disabled") or {}) - set(ids)
        if unknown_disabled:
            raise IntentError(f"bindings disable unknown rules: {sorted(unknown_disabled)}")
        return [self.translate_rule(r) for r in rules]


def to_psl(translations: list[RuleTranslation], *, version: str, source: str) -> str:
    out = ["// GENERATED by zt_psl.intent from " + source + " -- do not edit; edit the intent",
           "// (controlled natural language) or its bindings and regenerate.",
           "// Semantics: deny-overrides. Intent 'allow' rules are CONSTRAINTS on the operations",
           "// they name; grants come only from @permit properties (least-privilege placements).", ""]
    by_scope: dict[str, list[tuple[RuleTranslation, RulePart]]] = {}
    for tr in translations:
        for p in tr.parts:
            by_scope.setdefault(p.scope, []).append((tr, p))
    for scope in SCOPE_ORDER + ["workflow_run"]:
        items = by_scope.get(scope)
        if not items:
            continue
        out += [f"// @policy_set intent.{scope}", f"// @version {version}", f"// @source {source}"]
        if SCOPE_RUNTIME[scope] not in ("pdp",):
            out.append(f"// @runtime {SCOPE_RUNTIME[scope]}")
        out.append(f"vunit intent_{scope} ({scope}) {{")
        for tr, p in items:
            out.append("")
            out.append(f"  // @rule {p.rule_id}")
            if tr.description:
                out.append(f"  // @nl {tr.description}")
            out.append(f"  // @source {source}#{tr.intent_id}")
            if p.on_violation != "DENY":
                out.append(f"  // @on_violation {p.on_violation}")
            for o in p.obligations:
                out.append(f"  // @obligation {o}")
            for n in tr.notes + p.notes:
                out.append(f"  // @note {_norm(n)}")
            if tr.disabled:
                out.append(f"  // @disabled {tr.disabled}")
            out.append(f"  {p.label}: assert {p.body};")
        out += ["}", ""]
    return "\n".join(out)


def report_markdown(translations: list[RuleTranslation], source: str) -> str:
    lines = ["# Policy intent -> PSL translation report", "",
             f"Generated by `zt_psl.intent` from `{source}` and `policy_intent_bindings.yaml`. "
             "Every intent rule and every condition is listed with the PSL it became, the scope, and who "
             "enforces it.", "",
             "| intent rule | PSL rule(s) | enforced by | status |", "|---|---|---|---|"]
    for tr in translations:
        rules = ", ".join(f"`{p.rule_id}` ({p.scope})" for p in tr.parts) or "--"
        who = sorted({SCOPE_RUNTIME[p.scope] for p in tr.parts})
        status = ("DISABLED: " + tr.disabled[:120] + ("..." if len(tr.disabled) > 120 else "")) if tr.disabled \
            else ("realized by the default deny" if not tr.parts else "translated")
        lines.append(f"| `{tr.intent_id}` | {rules} | {', '.join(who) or '--'} | {status} |")
    for tr in translations:
        lines += ["", f"## `{tr.intent_id}`", ""]
        if tr.description:
            lines += [f"> {tr.description}", ""]
        lines += ["| condition (intent) | scope | PSL |", "|---|---|---|"]
        for text, scope, psl in tr.conditions:
            lines.append(f"| {text} | {scope} | `{psl.replace('|', chr(92) + '|')}` |")
        for p in tr.parts:
            lines += ["", f"`{p.rule_id}` -- on violation {p.on_violation}"
                      + (f", obligations {', '.join(p.obligations)}" if p.obligations else ""), "",
                      "```psl", f"{p.label}: assert {p.body};", "```"]
        for n in tr.notes:
            lines.append(f"* note: {n}")
        for x in tr.realized_by:
            lines.append(f"* realized by: {x}")
        if tr.disabled:
            lines.append(f"* **DISABLED**: {tr.disabled}")
    return "\n".join(lines) + "\n"
