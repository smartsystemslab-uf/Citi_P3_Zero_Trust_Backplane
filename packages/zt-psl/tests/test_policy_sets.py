"""Policy sets: field catalogue checks, annotations, request-rule classification,
deny-overrides decisions, Boolean fast path vs the reference interpreter, signing,
temporal rules with comparison atoms."""
from __future__ import annotations

import itertools
import random
from datetime import datetime, timezone

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zt_psl import PSLError, RequestPolicyEngine, UnboundField, compile_policy_set, parse
from zt_psl.fields import FieldCatalog
from zt_psl.reference import holds_finite
from zt_psl.runtime import MonitorRuntime
from zt_psl.signing import PolicySignatureError, sign_file, verify_file

CATALOG = yaml.safe_load("""
catalog_version: 1
windows:
  office: {timezone: America/New_York, days: [MON, TUE, WED, THU, FRI], start: "08:00", end: "18:00"}
  night: {timezone: UTC, days: [MON, TUE, WED, THU, FRI, SAT, SUN], start: "22:00", end: "06:00"}
scopes:
  pdp_request:
    kind: request
    events: {authz_request: "*"}
    fields:
      subject.id: {type: string, source: test}
      action: {type: string, source: test}
      auth.strength: {type: int, source: test}
      risk.level: {type: enum, values: [low, medium, high, critical], source: test}
      resource.critical: {type: bool, source: test}
      approval.valid: {type: bool, source: test}
      subject.role.*: {type: bool, source: test, missing: false}
      param.*: {type: string, source: test}
  run:
    kind: temporal
    key: [run_id]
    events:
      tool_succeeded: [tool, ready]
      tool_admitted: [tool]
    fields:
      tool: {type: string, source: test}
      ready: {type: bool, source: test}
""")


def cat() -> FieldCatalog:
    return FieldCatalog(CATALOG)


def compile_(src: str):
    return compile_policy_set([("t.psl", src)], cat())


def unit(body: str, scope: str = "pdp_request") -> str:
    return f"vunit v ({scope}) {{\n{body}\n}}\n"


BASE = {"subject.id": "a", "action": "read", "auth.strength": 3, "risk.level": "low",
        "resource.critical": False, "approval.valid": False}


# ---------------------------------------------------------------------------
# field catalogue / static checks
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("body,needle", [
    ('R: assert never (authz_request && subject.name == "a");', "unknown field"),
    ("R: assert never (authz_request && subject.id);", "use a comparison"),
    ('R: assert never (authz_request && auth.strength == "2");', "does not fit int"),
    ("R: assert never (authz_request && subject.id == 2);", "does not fit string"),
    ('R: assert never (authz_request && subject.id < "b");', "operator < is not defined"),
    ('R: assert never (authz_request && risk.level == "extreme");', "not a value of enum"),
    ("R: assert never (authz_request && resource.critical == 1);", "does not fit bool"),
    ("R: assert never (authz_request && authz_request == true);", "is an event"),
    ("R: assert authz_request before authz_request;", "must be invariants"),
    ("R: assert always (authz_request -> next approval.valid);", "must be invariants"),
])
def test_static_errors_are_explicit(body, needle):
    with pytest.raises(PSLError) as e:
        compile_(unit(body))
    assert needle in str(e.value), str(e.value)


def test_family_fields_and_missing_semantics():
    ps = compile_(unit('// @permit\nproperty p = subject.role.ops && param.region == "us";'))
    eng = RequestPolicyEngine(ps)
    assert eng.decide(BASE | {"subject.role.ops": True, "param.region": "us"}).outcome == "ALLOW"
    # role family: absent role == False (declared missing: false)
    assert eng.decide(BASE | {"param.region": "us"}).outcome == "DENY"
    # param family: absent value is an error (fail closed by the caller)
    with pytest.raises(UnboundField):
        eng.decide(BASE | {"subject.role.ops": True})


def test_field_values_are_type_checked_at_runtime():
    eng = RequestPolicyEngine(compile_(unit("// @permit\nproperty p = resource.critical && auth.strength >= 2;")))
    with pytest.raises(TypeError):
        eng.decide(BASE | {"resource.critical": "yes"})
    with pytest.raises(TypeError):
        eng.decide(BASE | {"resource.critical": True, "auth.strength": "3"})


def test_catalog_errors():
    for bad, needle in [({"catalog_version": 2}, "catalog_version"),
                        ({"catalog_version": 1, "scopes": {"s": {"kind": "weird", "events": {"e": []}}}}, "kind"),
                        ({"catalog_version": 1, "scopes": {"s": {"kind": "request", "events": {"e": ["x"]},
                                                                  "fields": {}}}}, "undeclared field"),
                        ({"catalog_version": 1, "scopes": {"s": {"kind": "request", "events": {"e": "*"},
                                                                  "fields": {"x": {"type": "int"}}}}}, "source"),
                        ({"catalog_version": 1, "scopes": {"s": {"kind": "request", "events": {"e": "*", "f": "*"},
                                                                  "fields": {}}}}, "exactly one event")]:
        with pytest.raises(PSLError, match=needle):
            FieldCatalog(bad)


def test_time_windows_match_pdp_semantics():
    c = cat()
    ny_fri_0800 = datetime(2026, 11, 6, 13, 0, tzinfo=timezone.utc)        # 08:00 EST, Friday
    ny_fri_1800 = datetime(2026, 11, 6, 23, 0, tzinfo=timezone.utc)        # 18:00 EST (end inclusive)
    ny_fri_1801 = datetime(2026, 11, 6, 23, 1, tzinfo=timezone.utc)
    ny_sat_1200 = datetime(2026, 11, 7, 17, 0, tzinfo=timezone.utc)
    assert c.windows_at(ny_fri_0800)["time.in.office"] is True
    assert c.windows_at(ny_fri_1800)["time.in.office"] is True
    assert c.windows_at(ny_fri_1801)["time.in.office"] is False
    assert c.windows_at(ny_sat_1200)["time.in.office"] is False
    # overnight window (start > end)
    assert c.windows_at(datetime(2026, 11, 6, 23, 30, tzinfo=timezone.utc))["time.in.night"] is True
    assert c.windows_at(datetime(2026, 11, 6, 5, 59, tzinfo=timezone.utc))["time.in.night"] is True
    assert c.windows_at(datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc))["time.in.night"] is False


# ---------------------------------------------------------------------------
# annotations
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("body,needle", [
    ("// @severity high\nR: assert never (authz_request && resource.critical);", "unknown or misplaced annotation"),
    ("// @on_violation BLOCK\nR: assert never (authz_request && resource.critical);", "@on_violation must be"),
    ("// @permit\nR: assert never (authz_request && resource.critical);", "misplaced annotation @permit"),
    ("// @obligation audit\nproperty p = resource.critical;", "need @permit"),
    ("// @permit yes\nproperty p = resource.critical;", "@permit takes no value"),
    ("// @permit\n// @obligation mask(fields)\nproperty p = resource.critical;", "expected key=value"),
    ("// @runtime pdp,cloud\nR: assert never (authz_request && resource.critical);", "@runtime must list"),
    ("// @rule x\n// @rule y\nR: assert never (authz_request && resource.critical);", "more than once"),
    ("// @permit\nproperty p = always resource.critical;", "must be a boolean"),
    ("// @rule same\nR1: assert never (authz_request && resource.critical);\n"
     "// @rule same\nR2: assert never (authz_request && approval.valid);", "duplicate rule id"),
])
def test_annotation_errors(body, needle):
    with pytest.raises(PSLError) as e:
        compile_(unit(body))
    assert needle in str(e.value), str(e.value)


def test_obligation_parsing_and_rule_metadata():
    ps = compile_(unit(
        "// @rule policy.read\n// @nl Agent a may read.\n// @source bundle.yaml\n// @permit\n"
        '// @obligation data_masking(fields=[ssn, full_account_number])\n// @obligation enhanced_logging(reason="x y")\n'
        '// @obligation require_idempotency_key\nproperty p_read = subject.id == "a" && action == "read";'))
    r = ps.rule("policy.read")
    assert (r.kind, r.label, r.nl, r.origin) == ("permit", "p_read", "Agent a may read.", "bundle.yaml")
    assert [o.as_dict() for o in r.obligations] == [
        {"type": "data_masking", "parameters": {"fields": ["ssn", "full_account_number"]}},
        {"type": "enhanced_logging", "parameters": {"reason": "x y"}},
        {"type": "require_idempotency_key", "parameters": {}}]


# ---------------------------------------------------------------------------
# deny-overrides decisions
# ---------------------------------------------------------------------------
POLICY = unit("""
  // @permit
  // @obligation enhanced_logging(reason=read)
  property p_read = subject.id == "a" && action == "read";
  // @permit
  // @obligation data_masking(fields=[ssn])
  property p_read2 = subject.id == "a" && action == "read" && risk.level == "low";
  // @permit
  property p_write = subject.id == "w" && action == "update";
  // @on_violation REAUTHENTICATE
  R_weak: assert never (authz_request && subject.id == "a" && auth.strength <= 1);
  // @on_violation MANUAL_REVIEW
  R_approval: assert always (authz_request && resource.critical && action == "update" -> approval.valid);
  R_deny_w_high_risk: assert never (authz_request && subject.id == "w" && risk.level == "critical");
""")


@pytest.mark.parametrize("fields,outcome,violated,permits", [
    ({}, "ALLOW_WITH_OBLIGATIONS", [], ["p_read", "p_read2"]),
    ({"risk.level": "high"}, "ALLOW_WITH_OBLIGATIONS", [], ["p_read"]),
    ({"auth.strength": 1}, "REAUTHENTICATE", ["R_weak"], ["p_read", "p_read2"]),
    ({"subject.id": "z"}, "DENY", ["R_default_deny"], []),
    ({"subject.id": "w", "action": "update", "resource.critical": True}, "MANUAL_REVIEW", ["R_approval"], ["p_write"]),
    ({"subject.id": "w", "action": "update", "resource.critical": True, "approval.valid": True}, "ALLOW", [],
     ["p_write"]),
    # DENY overrides MANUAL_REVIEW
    ({"subject.id": "w", "action": "update", "resource.critical": True, "risk.level": "critical"}, "DENY",
     ["R_approval", "R_deny_w_high_risk"], ["p_write"]),
    # DENY (default) overrides REAUTHENTICATE
    ({"action": "delete", "auth.strength": 0}, "DENY", ["R_default_deny", "R_weak"], []),
])
def test_deny_overrides_outcomes(fields, outcome, violated, permits):
    d = RequestPolicyEngine(compile_(POLICY)).decide(BASE | fields)
    assert d.outcome == outcome
    assert [v.rule_id for v in d.violated] == violated
    assert [p.rule_id for p in d.permits] == permits
    assert d.allowed == (outcome in ("ALLOW", "ALLOW_WITH_OBLIGATIONS"))


def test_obligations_are_the_union_of_holding_permissions():
    d = RequestPolicyEngine(compile_(POLICY)).decide(BASE)
    assert [o.as_dict() for o in d.obligations] == [
        {"type": "enhanced_logging", "parameters": {"reason": "read"}},
        {"type": "data_masking", "parameters": {"fields": ["ssn"]}}]
    assert d.reason() == "psl_permit:p_read,p_read2"


def test_adding_a_rule_never_relaxes_a_decision():
    """Monotonicity of deny-overrides: for every request, the decision with an extra
    constraint is at least as strict as without it."""
    strict = {"ALLOW": 0, "ALLOW_WITH_OBLIGATIONS": 0, "MANUAL_REVIEW": 1, "REAUTHENTICATE": 2, "DENY": 3}
    e1 = RequestPolicyEngine(compile_(POLICY))
    e2 = RequestPolicyEngine(compile_(POLICY.replace("}\n", '  // @on_violation MANUAL_REVIEW\n  R_extra: assert never '
                                                         '(authz_request && action == "read" && risk.level != "low");\n}\n')))
    for sid, act, auth, risk, crit, appr in itertools.product(["a", "w", "z"], ["read", "update"], [0, 1, 3],
                                                                ["low", "high", "critical"], [False, True],
                                                                [False, True]):
        f = {"subject.id": sid, "action": act, "auth.strength": auth, "risk.level": risk,
             "resource.critical": crit, "approval.valid": appr}
        assert strict[e2.decide(f).outcome] >= strict[e1.decide(f).outcome], f


def test_runtime_filtering_and_default_deny_per_runtime():
    ps = compile_(unit("""
  // @permit
  property p_pdp = subject.id == "a";
  // @permit
  // @runtime harness
  property p_harness = subject.id == "h";
  // @runtime harness
  R_h: assert never (authz_request && action == "delete");
"""))
    pdp, harness = RequestPolicyEngine(ps, runtime="pdp"), RequestPolicyEngine(ps, runtime="harness")
    assert pdp.decide(BASE | {"subject.id": "h"}).outcome == "DENY"          # harness permit not in the PDP
    assert harness.decide(BASE | {"subject.id": "h"}).outcome == "ALLOW"
    assert pdp.decide(BASE | {"action": "delete"}).outcome == "ALLOW"        # harness-only constraint
    assert harness.decide(BASE | {"subject.id": "h", "action": "delete"}).outcome == "DENY"


def test_fast_path_matches_reference_interpreter():
    """For request rules the PDP evaluates the Boolean body directly. Check that this
    equals the PSL semantics of the whole assertion (reference interpreter on the
    one-step trace) for random rules and random field values."""
    rng = random.Random(20261102)
    atoms = ['subject.id == "a"', 'subject.id != "w"', 'action == "read"', "auth.strength >= 2",
             "auth.strength < 1", 'risk.level == "high"', "resource.critical", "approval.valid", "subject.role.ops"]

    def rb(d):
        if d == 0 or rng.random() < 0.3:
            a = rng.choice(atoms)
            return f"!({a})" if rng.random() < 0.3 else a
        op = rng.choice(["&&", "||", "->"])
        return f"({rb(d - 1)} {op} {rb(d - 1)})"

    checked = 0
    for _ in range(300):
        body = rb(3)
        kind = rng.choice(["always", "never"])
        src = unit(f"R: assert {kind} (authz_request -> {body});" if kind == "always"
                   else f"R: assert never (authz_request && {body});")
        ps = compile_(src + unit("// @permit\nproperty p = true;").replace("vunit v", "vunit w"))
        eng = RequestPolicyEngine(ps)
        (vu,) = [u for u in parse(src, "t.psl")]
        prop = vu.assertions[0].prop
        for _ in range(20):
            f = {"subject.id": rng.choice(["a", "w", "z"]), "action": rng.choice(["read", "update"]),
                 "auth.strength": rng.randint(0, 3), "risk.level": rng.choice(["low", "high"]),
                 "resource.critical": rng.random() < 0.5, "approval.valid": rng.random() < 0.5,
                 "subject.role.ops": rng.random() < 0.5}
            letter = eng.binder.bind("authz_request", f)
            ref = holds_finite(prop, [letter], 0)
            fast = "R" not in [v.rule_id for v in eng.decide(f).violated]
            assert ref == fast, (src, f)
            checked += 1
    assert checked == 6000


# ---------------------------------------------------------------------------
# signing
# ---------------------------------------------------------------------------
def test_signing_detects_tampering_and_untrusted_keys(tmp_path):
    key, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    p = tmp_path / "x.psl"
    p.write_text(unit('// @permit\nproperty p = subject.id == "a";'), encoding="utf-8")
    sign_file(p, key, issuer="policy.prototype", key_id="policy-1")
    trusted = {("policy.prototype", "policy-1"): key.public_key()}

    def lookup(issuer, key_id):
        if (issuer, key_id) not in trusted:
            raise PolicySignatureError("untrusted signer")
        return trusted[(issuer, key_id)]

    assert verify_file(p, lookup)["file"] == "x.psl"
    p.write_text(p.read_text(encoding="utf-8").replace('"a"', '"b"'), encoding="utf-8")
    with pytest.raises(PolicySignatureError, match="changed after signing"):
        verify_file(p, lookup)
    sign_file(p, other, issuer="policy.prototype", key_id="policy-1")       # wrong key, claimed trusted id
    with pytest.raises(PolicySignatureError, match="invalid policy signature"):
        verify_file(p, lookup)
    sign_file(p, other, issuer="attacker", key_id="k")
    with pytest.raises(PolicySignatureError, match="untrusted"):
        verify_file(p, lookup)
    (tmp_path / "x.sig.json").unlink()
    with pytest.raises(PolicySignatureError, match="missing signature"):
        verify_file(p, lookup)


# ---------------------------------------------------------------------------
# temporal rules with comparison atoms
# ---------------------------------------------------------------------------
def test_temporal_rule_with_comparisons_runs_in_monitor_runtime():
    ps = compile_(unit("""
  // @rule P_ready_before_ledger
  P_ready: assert (tool_succeeded && tool == "validate" && ready) before (tool_admitted && tool == "ledger");
""", scope="run"))
    rt = MonitorRuntime.from_policy_set(ps, "native")
    key = ("run-1",)

    def ev(event, **fields):
        return rt.admit([("run", key, event, rt.bind("run", event, fields))])

    assert ev("tool_admitted", tool="validate").ok
    assert rt.observe([("run", key, "tool_succeeded", rt.bind("run", "tool_succeeded",
                                                                {"tool": "validate", "ready": False}))]).ok
    blocked = ev("tool_admitted", tool="ledger")
    assert not blocked.ok and blocked.violations[0].property_id == "P_ready_before_ledger"
    rt.observe([("run", key, "tool_succeeded", rt.bind("run", "tool_succeeded", {"tool": "validate", "ready": True}))])
    assert ev("tool_admitted", tool="ledger").ok
    with pytest.raises(PSLError, match="unknown field"):
        compile_(unit("P: assert never (tool_admitted && ready2);", scope="run"))
    orphan = dict(CATALOG, scopes=dict(CATALOG["scopes"], run=dict(CATALOG["scopes"]["run"], fields=dict(
        CATALOG["scopes"]["run"]["fields"], orphan={"type": "bool", "source": "test"}))))
    with pytest.raises(PSLError, match="not defined at any event"):
        compile_policy_set([("t.psl", unit("P: assert never (tool_admitted && orphan);", scope="run"))],
                           FieldCatalog(orphan))
