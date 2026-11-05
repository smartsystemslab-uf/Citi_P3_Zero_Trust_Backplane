"""Controlled natural language -> PSL (zt_psl.intent) and the policy-layer features it
uses: obligations on constraints, FLAG, check-only scopes, @disabled, and the static
check against conjunctions that can never hold."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from zt_psl import PSLError, RequestPolicyEngine, compile_policy_set
from zt_psl.fields import FieldCatalog
from zt_psl.intent import IntentError, IntentTranslator, to_psl

BACKPLANE = Path(__file__).resolve().parents[3]          # repository root
INTENT = BACKPLANE / "legacy/citi_p3/manifest_spec" / "manifest" / "policy_intent.yaml"
BINDINGS = BACKPLANE / "legacy/citi_p3/manifest_spec" / "manifest" / "policy_intent_bindings.yaml"
CATALOG = BACKPLANE / "packages/zt-pdp" / "policy_store" / "policy_fields.yaml"


def load(p: Path):
    return yaml.safe_load(p.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# the real intent file
# ---------------------------------------------------------------------------
def test_every_intent_rule_translates_and_compiles():
    trs = IntentTranslator(load(BINDINGS)).translate(load(INTENT))
    assert len(trs) == len(load(INTENT)["policy_rules"]) == 24
    ps = compile_policy_set([("intent.psl", to_psl(trs, version="1.0.0", source="policy_intent.yaml"))],
                            FieldCatalog.load(CATALOG))
    by_scope: dict[str, int] = {}
    for r in ps.rules:
        if r.kind != "default_deny":
            by_scope[r.scope] = by_scope.get(r.scope, 0) + 1
    assert by_scope == {"pdp_request": 12, "gateway_input": 2, "gateway_tool": 1, "gateway_output": 5,
                        "harness_output": 2, "workflow_run": 6}
    # no-cross-domain-transfers was disabled until the static scanner's domain fix (2026-11-03)
    assert [r.rule_id for r in ps.rules if r.disabled] == []
    assert ps.rule("intent.no-cross-domain-transfers").scope == "pdp_request"
    realized = [t for t in trs if not t.parts]
    assert [t.intent_id for t in realized] == ["forbidden-tool-block"] and realized[0].realized_by
    # every intent rule is traceable from the PSL (@source) and keeps its natural-language text (@nl)
    for r in ps.rules:
        if r.kind != "default_deny":
            assert r.origin.startswith("policy_intent.yaml#") and r.nl


def test_generated_store_file_is_current():
    """policy_store/intent.psl must be the translation of the current intent + bindings."""
    trs = IntentTranslator(load(BINDINGS)).translate(load(INTENT))
    want = to_psl(trs, version="1.0.0", source="legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml")
    have = (CATALOG.parent / "intent.psl").read_text(encoding="utf-8")
    assert have == want, "regenerate: zt-psl intent ... --out policy_store/intent.psl (then re-sign)"


# ---------------------------------------------------------------------------
# grammar and bindings
# ---------------------------------------------------------------------------
B = {
    "bindings_version": 1,
    "subjects": {"*": {}, "agent_x": {"pdp_request": 'subject.runtime_id == "agent_x"',
                                      "workflow_run": {"tool_admitted": 'tool.agent == "agent_x"'}}},
    "resources": {"tool_t/call": {"pdp_request": 'authz_request && resource.runtime_id == "t"',
                                  "workflow_run": 'tool_admitted && tool.name == "t"'}},
    "fields": {"identity.agent_id": {"pdp_request": "subject.runtime_id"},
               "args.status": {"pdp_request": "args.status"}},
    "checked_fields": {"args.note": {"pdp_request": "args.note"}, "args.rationale": {"pdp_request": "args.rationale"},
                       "args.correction_amount": {"pdp_request": "args.correction_amount"}},
    "phrases": {"args are well-formed": {"pdp_request": "args.well_formed"}},
    "prerequisites": {"session_state.r is present": {"workflow_run": 'tool_succeeded && tool.name == "v"'}},
}


def rule(*conds, subject="agent_x", decision="allow", fail="deny", rid="r1"):
    return {"rule_id": rid, "subject": subject, "resource": "tool_t", "action": "call", "decision": decision,
            "on_condition_fail": fail, "conditions": list(conds), "obligations": ["audit_log"]}


@pytest.mark.parametrize("cond,psl", [
    ("identity.agent_id == agent_x", 'subject.runtime_id == "agent_x"'),
    ("identity.agent_id != agent_y", 'subject.runtime_id != "agent_y"'),
    ("args.status in [APPROVED, REJECTED]", '(args.status == "APPROVED" || args.status == "REJECTED")'),
    ("args.note is present and non-empty", "args.note.nonempty"),
    ("args.rationale is present and len(args.rationale) >= 20", "args.rationale.length >= 20"),
    ("args.correction_amount is a finite non-zero number", "args.correction_amount.finite_nonzero"),
    ("args are well-formed", "args.well_formed"),
    ("NOT (identity.agent_id == agent_y AND args.status == X)",
     '!(subject.runtime_id == "agent_y" && args.status == "X")'),
])
def test_grammar_forms(cond, psl):
    (tr,) = IntentTranslator(B).translate({"policy_rules": [rule(cond)]})
    (part,) = tr.parts
    assert part.body == f'always (authz_request && resource.runtime_id == "t" && subject.runtime_id == "agent_x" -> {psl})'


def test_deny_rules_prerequisites_and_fail_modes():
    tr = IntentTranslator(B).translate({"policy_rules": [
        rule("identity.agent_id != agent_x", subject="*", decision="deny", rid="d"),
        rule("session_state.r is present", "args.note is present and non-empty", rid="p"),
        rule("args are well-formed", fail="allow_with_flag", rid="f")]})
    assert tr[0].parts[0].body == 'never (authz_request && resource.runtime_id == "t" && subject.runtime_id != "agent_x")'
    assert [p.scope for p in tr[1].parts] == ["pdp_request", "workflow_run"]
    assert tr[1].parts[1].body == ('((tool_succeeded && tool.name == "v") before '
                                   '(tool_admitted && tool.name == "t" && tool.agent == "agent_x"))')
    assert tr[2].parts[0].on_violation == "FLAG"


@pytest.mark.parametrize("r,needle", [
    (rule("identity.agent_id == agent_x", subject="nobody"), "subject 'nobody' is not bound"),
    ({**rule("args are well-formed"), "resource": "other"}, "resource/action 'other/call' is not bound"),
    (rule("the moon is full"), "not covered by the controlled grammar"),
    (rule("identity.role == x"), "field 'identity.role' is not bound"),
    (rule("session_state.unknown is present"), "without a trusted prerequisite binding"),
    (rule("args.note is present and len(args.rationale) >= 3"), "needs X == Y"),
    (rule("args are well-formed", fail="ignore"), "on_condition_fail"),
])
def test_untranslatable_intents_fail_explicitly(r, needle):
    with pytest.raises(IntentError) as e:
        IntentTranslator(B).translate({"policy_rules": [r]})
    assert needle in str(e.value) and r["rule_id"] in str(e.value)


def test_duplicate_and_unknown_disabled_rules_are_errors():
    with pytest.raises(IntentError, match="duplicate rule_id"):
        IntentTranslator(B).translate({"policy_rules": [rule("args are well-formed"), rule("args are well-formed")]})
    with pytest.raises(IntentError, match="disable unknown rules"):
        IntentTranslator({**B, "disabled": {"zzz": "x"}}).translate({"policy_rules": [rule("args are well-formed")]})


# ---------------------------------------------------------------------------
# policy-layer features used by the translation
# ---------------------------------------------------------------------------
CAT = {"catalog_version": 1, "scopes": {
    "pdp_request": {"kind": "request", "events": {"authz_request": "*"},
                    "fields": {"subject.runtime_id": {"type": "string", "source": "t"},
                               "args.ok": {"type": "bool", "source": "t"}}},
    "check": {"kind": "request", "default_deny": False, "events": {"ev": "*"},
              "fields": {"x": {"type": "bool", "source": "t"}}},
    "run": {"kind": "temporal", "events": {"a": ["f"], "b": []}, "fields": {"f": {"type": "bool", "source": "t"}}}}}


def test_constraint_obligations_flag_check_only_and_disabled():
    ps = compile_policy_set([("p.psl", """
vunit v (pdp_request) {
  // @permit
  property p = subject.runtime_id == "a";
  // @obligation audit_log
  R_obl: assert always (authz_request && subject.runtime_id == "a" -> true);
  // @on_violation FLAG
  R_flag: assert always (authz_request -> args.ok);
  // @disabled known conflict
  R_off: assert never (authz_request && subject.runtime_id == "a");
}
vunit c (check) {
  R_c: assert always (ev -> x);
}""")], FieldCatalog(CAT))
    eng = RequestPolicyEngine(ps)
    d = eng.decide({"subject.runtime_id": "a", "args.ok": False})
    assert d.outcome == "ALLOW_WITH_OBLIGATIONS"                                  # FLAG does not block, R_off is off
    assert [o.as_dict() for o in d.obligations] == [{"type": "audit_log", "parameters": {}},
                                                    {"type": "anomaly_flag", "parameters": {"rule": "R_flag"}}]
    assert [f.rule_id for f in d.flagged] == ["R_flag"]
    assert ps.rule("R_off").disabled == "known conflict"
    check = RequestPolicyEngine(ps, scope="check")                               # check-only: no default deny
    assert check.decide({"x": True}).outcome == "ALLOW" and check.decide({"x": False}).outcome == "DENY"
    with pytest.raises(PSLError, match="needs the form"):
        compile_policy_set([("q.psl", "vunit v (pdp_request) {\n  // @obligation audit_log\n"
                                      "  R: assert never (authz_request && args.ok);\n}")], FieldCatalog(CAT))


@pytest.mark.parametrize("body", [
    "P: assert (a before (b && f));",                 # f is not defined at event b
    "P: assert never (a && b);",                      # two events at one step
    "P: assert always (a -> next (b && f));",
])
def test_conjunctions_that_can_never_hold_are_rejected(body):
    with pytest.raises(PSLError, match="can never hold"):
        compile_policy_set([("t.psl", f"vunit v (run) {{ {body} }}")], FieldCatalog(CAT))


def test_negated_undefined_field_is_fine():
    compile_policy_set([("t.psl", "vunit v (run) { P: assert always (b && !f -> true); }")], FieldCatalog(CAT))
