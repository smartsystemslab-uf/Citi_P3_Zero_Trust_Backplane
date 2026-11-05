"""Translate PDP YAML policy bundles (match / effect / priority) into PSL
(deny-overrides). Used for generated runtime bundles (native MAS runtime, real-workflow
workflows) and to check the hand-written PSL of the main policy store.

Semantic patterns (the same ones used for the hand translation):

* DENY policy with match M          -> ``never (authz_request && M)``
* ALLOW / ALLOW_WITH_OBLIGATIONS    -> ``@permit property = M`` with its obligations
* REAUTHENTICATE / MANUAL_REVIEW policy R with match M, paired with exactly one
  higher-priority allow A whose match is M plus extra conditions C
                                    -> ``@permit property = M`` (A's id and obligations)
                                       + ``always (authz_request && M -> C)`` with
                                       ``@on_violation`` = R's effect (R's id)
* REAUTHENTICATE / MANUAL_REVIEW without such a pair
                                    -> ``@permit property = M`` (scope)
                                       + ``never (authz_request && M)`` with R's effect

Anything that cannot be translated exactly (parameter conditions, time windows
without a matching catalogue window, more than one candidate pair, an allow that
would lose its conditions) raises ``TranslationError`` -- never a silent change.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

LIST_FIELDS = {
    "subjects": "subject.id",
    "resources": "resource.id",
    "actions": "action",
    "workflows": "workflow.id",
    "environments": "environment",
    "subject_domains": "subject.domain",
    "resource_domains": "resource.domain",
    "resource_classifications": "resource.classification",
    "risk_levels": "risk.level",
}
CONDITION_KEYS = {"approval_valid", "secondary_authorization_valid", "auth_strength_gte", "auth_strength_lte",
                  "min_risk", "max_risk", "min_risk_score", "max_risk_score", "risk_levels", "time_windows"}
RISKS = ["low", "medium", "high", "critical"]
EFFECTS = {"ALLOW", "ALLOW_WITH_OBLIGATIONS", "DENY", "REAUTHENTICATE", "MANUAL_REVIEW"}


class TranslationError(ValueError):
    pass


def _lit(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _any_of(field: str, values: Iterable[Any]) -> str:
    vals = list(values)
    if "*" in vals:
        return "true"
    if not vals:
        return "false"
    parts = [f"{field} == {_lit(v)}" for v in vals]
    return parts[0] if len(parts) == 1 else "(" + " || ".join(parts) + ")"


def _window_name(window: dict[str, Any], windows: dict[str, dict[str, Any]]) -> str:
    want = (str(window.get("timezone", "UTC")), sorted(str(d).upper() for d in window.get("days", [])),
            str(window["start"]), str(window["end"]))
    for name, w in windows.items():
        have = (str(w["timezone"]), sorted(str(d).upper() for d in w["days"]),
                str(w["start"])[:5], str(w["end"])[:5])
        if have == (want[0], want[1], want[2][:5], want[3][:5]):
            return name
    raise TranslationError(f"time window {window} has no matching window in the field catalogue")


def match_terms(match: dict[str, Any], windows: dict[str, dict[str, Any]], *, keys: Iterable[str] | None = None
                ) -> list[str]:
    """PSL Boolean terms (conjunction) for a PDP match block."""
    out: list[str] = []
    for key in (keys if keys is not None else sorted(match)):
        val = match[key]
        if key in LIST_FIELDS:
            if not isinstance(val, list):
                raise TranslationError(f"match key {key} must be a list")
            t = _any_of(LIST_FIELDS[key], val)
            if t != "true":
                out.append(t)
        elif key == "subject_roles":
            if "*" not in val:
                out.append("(" + " || ".join(f"subject.role.{r}" for r in val) + ")" if len(val) > 1
                           else f"subject.role.{val[0]}")
        elif key == "approval_valid":
            out.append("approval.valid" if val else "!approval.valid")
        elif key == "secondary_authorization_valid":
            out.append("approval.secondary_valid" if val else "!approval.secondary_valid")
        elif key == "auth_strength_gte":
            out.append(f"auth.strength >= {int(val)}")
        elif key == "auth_strength_lte":
            out.append(f"auth.strength <= {int(val)}")
        elif key in ("min_risk", "max_risk"):
            lvl = RISKS.index(str(val).lower())
            allowed = RISKS[lvl:] if key == "min_risk" else RISKS[:lvl + 1]
            out.append(_any_of("risk.level", allowed))
        elif key == "min_risk_score":
            out.append(f"risk.score >= {int(val)}")
        elif key == "max_risk_score":
            out.append(f"risk.score <= {int(val)}")
        elif key == "time_windows":
            names = [_window_name(w, windows) for w in val]
            out.append("(" + " || ".join(f"time.in.{n}" for n in names) + ")" if len(names) > 1
                       else f"time.in.{names[0]}")
        elif key == "parameter_conditions":
            raise TranslationError("parameter_conditions need declared param.* fields; translate this policy by hand")
        else:
            raise TranslationError(f"unsupported match key {key}")
    return out


def _conj(terms: list[str]) -> str:
    return " && ".join(terms) if terms else "true"


def _obligation(o: dict[str, Any]) -> str:
    params = o.get("parameters") or {}
    if not params:
        return str(o["type"])

    def val(v: Any) -> str:
        if isinstance(v, list):
            return "[" + ", ".join(val(x) for x in v) + "]"
        if isinstance(v, bool):
            return "true" if v else "false"
        s = str(v)
        return s if re.fullmatch(r"[A-Za-z0-9_.\-]+", s) else '"' + s + '"'

    return f"{o['type']}(" + ", ".join(f"{k}={val(v)}" for k, v in params.items()) + ")"


def _label(policy_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", policy_id)


def bundle_to_psl(bundle: dict[str, Any], *, windows: dict[str, dict[str, Any]] | None = None,
                  source: str = "") -> str:
    windows = windows or {}
    meta = bundle.get("metadata", {})
    pols = [p for p in bundle.get("policies", []) if p.get("enabled", True)]
    for p in pols:
        if p["effect"] not in EFFECTS:
            raise TranslationError(f"{p['id']}: unknown effect {p['effect']}")
    vname = _label(str(meta.get("id", "generated")))
    lines = [f"// GENERATED from policy bundle {meta.get('id')} {meta.get('version')} by zt_pdp.psl_translate",
             "// (deny-overrides). Do not edit; regenerate from the source.", "",
             f"// @policy_set {meta.get('id')}", f"// @version {meta.get('version', '1.0.0')}"]
    if source:
        lines.append(f"// @source {source}")
    lines.append(f"vunit {vname} (pdp_request) {{")
    used: set[str] = set()

    def emit(kind: str, rid: str, label: str, nl: str, body: str, *, effect: str = "DENY",
             obligations: Iterable[dict[str, Any]] = ()) -> None:
        if label in used:
            raise TranslationError(f"duplicate PSL label {label}")
        used.add(label)
        lines.append("")
        lines.append(f"  // @rule {rid}")
        if nl:
            lines.append(f"  // @nl {' '.join(str(nl).split())}")
        if kind == "permit":
            lines.append("  // @permit")
            for o in obligations:
                lines.append(f"  // @obligation {_obligation(o)}")
            lines.append(f"  property {label} = {body};")
        else:
            if effect != "DENY":
                lines.append(f"  // @on_violation {effect}")
            lines.append(f"  {label}: assert {body};")

    restrictive = [p for p in pols if p["effect"] in ("MANUAL_REVIEW", "REAUTHENTICATE")]
    allows = [p for p in pols if p["effect"] in ("ALLOW", "ALLOW_WITH_OBLIGATIONS")]
    paired: set[str] = set()
    for r in restrictive:
        rkeys = set(r.get("match", {}))
        cands = []
        for a in allows:
            akeys = set(a.get("match", {}))
            if a["priority"] > r["priority"] and rkeys <= akeys and all(
                    a["match"][k] == r["match"][k] for k in rkeys) and (akeys - rkeys) <= CONDITION_KEYS:
                cands.append(a)
        scope = _conj(match_terms(r["match"], windows))
        if len(cands) > 1:
            raise TranslationError(f"{r['id']}: more than one higher-priority allow refines it; translate by hand")
        if cands:
            a = cands[0]
            paired.add(a["id"])
            extra = _conj(match_terms(a["match"], windows, keys=sorted(set(a["match"]) - rkeys)))
            emit("permit", a["id"], _label(a["id"]), a.get("description", ""), scope,
                 obligations=a.get("obligations", []))
            emit("constraint", r["id"], _label(r["id"]), r.get("description", ""),
                 f"always (authz_request && {scope} -> {extra})", effect=r["effect"])
        else:
            emit("permit", r["id"] + ".scope", _label(r["id"]) + "_scope",
                 f"Scope of {r['id']} (reviewable / step-up, not an unconditional grant).", scope)
            emit("constraint", r["id"], _label(r["id"]), r.get("description", ""),
                 f"never (authz_request && {scope})", effect=r["effect"])
    for a in allows:
        if a["id"] in paired:
            continue
        emit("permit", a["id"], _label(a["id"]), a.get("description", ""),
             _conj(match_terms(a["match"], windows)), obligations=a.get("obligations", []))
    for d in [p for p in pols if p["effect"] == "DENY"]:
        emit("constraint", d["id"], _label(d["id"]), d.get("description", ""),
             f"never (authz_request && {_conj(match_terms(d['match'], windows))})")
    lines.append("}")
    return "\n".join(lines) + "\n"


def rebind_subject(psl_text: str, rule_ids: Iterable[str], old_subject: str, new_subject: str) -> tuple[str, int]:
    """Replace ``subject.id == old`` by ``subject.id == new`` inside the named rules only.
    Returns (text, number of rules changed)."""
    out, changed = psl_text, 0
    for rid in rule_ids:
        m = re.search(r"// @rule " + re.escape(rid) + r"\n(.*?;)", out, re.DOTALL)
        if not m:
            continue
        block = m.group(1)
        new_block = block.replace(f'subject.id == "{old_subject}"', f'subject.id == "{new_subject}"')
        if new_block != block:
            out = out[:m.start(1)] + new_block + out[m.end(1):]
            changed += 1
    return out, changed
