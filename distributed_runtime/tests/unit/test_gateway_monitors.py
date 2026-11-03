"""Gateway temporal rules (policy_store/gateway_runtime.psl) executed from the SIGNED store
with the real runtime: hand-derived expected verdicts for normal and violating traces of
every property (ported from the PSL monitor experiment, scheme B), plus slicing,
all-or-nothing admission, concurrency and capacity."""
from __future__ import annotations

import threading

import pytest

from zt_psl.runtime import CapacityExceeded, MonitorRuntime
from zt_distributed.psl_guard import GATEWAY_SCOPES

K = ("attempt-1",)
ID_B = {"identity.workload_ok": True, "identity.agent_registered": True, "identity.agent_credential_ok": True}
ADM = {"permit.bound": True, "permit.live": True, "tool.critical": False}
PRE = {"audit.correlated": True, "audit.durable": True}
POST = {"audit.correlated": True}
ADMISSION_EVENTS = {"execution_admitted", "execution_started", "ledger_admitted", "report_admitted",
                    "exception_admitted"}


def g(pid: str) -> str:
    return f"gateway.{pid}"


@pytest.fixture
def rt(policy_set):
    def make(**kw) -> MonitorRuntime:
        return MonitorRuntime.from_policy_set(policy_set, "gateway", scopes=GATEWAY_SCOPES, **kw)
    return make


def normal(idd=ID_B):
    return [("request_received", {}), ("identity_verified", idd), ("authorization_allowed", {}),
            ("permit_verified", {}), ("execution_requested", {}), ("execution_admitted", ADM),
            ("audit_pre_recorded", PRE), ("execution_started", {}), ("execution_succeeded", {}),
            ("audit_post_recorded", POST)]


def step(r: MonitorRuntime, scope: str, key: tuple, ev: str, fields: dict):
    target = [(scope, key, ev, r.bind(scope, ev, fields))]
    return r.admit(target) if ev in ADMISSION_EVENTS else r.observe(target)


def play(r: MonitorRuntime, trace, key=K, scope="request_attempt"):
    out = []
    for ev, fields in trace:
        out += [(v.property_id, v.event, v.when) for v in step(r, scope, key, ev, fields).violations]
    return out


def test_store_defines_exactly_the_gateway_monitors(rt):
    r = rt()
    assert set(r.machines) == set(GATEWAY_SCOPES)
    pids = {m.pid for ms in r.machines.values() for m in ms}
    assert pids == {g(p) for p in ("P1_identity", "P1_authorization", "P1_permit", "P1_binding", "P1_admission",
                                   "P2_request", "P5_live", "P6_pre_audit", "P6_post_audit",
                                   "P6_outcome_after_start", "P6_outcome_recorded", "P6_single_outcome",
                                   "P2_operation", "P3_at_most_once", "P4_ledger_after_readiness",
                                   "P4_report_after_match", "P4_exception_after_mismatch", "P4_participant",
                                   "P4_within_dispatch")}


def test_native_runtime_does_not_load_gateway_rules(policy_set):
    native = MonitorRuntime.from_policy_set(policy_set, "native")
    assert set(native.machines) == {"workflow_run"}


def test_normal_request_trace_has_no_violation_and_closes_clean(rt):
    r = rt()
    assert play(r, normal()) == []
    v = r.verdicts("request_attempt", K)
    assert v[g("P1_identity")] == "S" and v[g("P1_authorization")] == "S" and v[g("P1_permit")] == "S"
    assert v[g("P6_pre_audit")] == "S" and v[g("P1_admission")] == "S"
    assert v[g("P2_request")] == "P" and v[g("P5_live")] == "P"       # safety: never satisfied early
    assert v[g("P6_post_audit")] == "P"                                 # response: pending, not violated
    assert r.close("request_attempt", K) == []


def test_mid_trace_pending_is_not_a_violation_but_close_decides(rt):
    r = rt()
    assert play(r, normal()[:8]) == []                 # execution_started, no outcome yet
    assert r.verdicts("request_attempt", K)[g("P6_outcome_recorded")] == "P"
    closed = r.close("request_attempt", K)
    assert [c.property_id for c in closed] == [g("P6_outcome_recorded")] and all(c.when == "close" for c in closed)


def test_outcome_without_post_audit_detected_at_close_only(rt):
    r = rt()
    assert play(r, normal()[:9]) == []
    assert [c.property_id for c in r.close("request_attempt", K)] == [g("P6_post_audit")]


@pytest.mark.parametrize("drop,expect", [("identity_verified", "P1_identity"),
                                         ("authorization_allowed", "P1_authorization"),
                                         ("permit_verified", "P1_permit")])
def test_missing_prerequisite_event_blocks_admission(rt, drop, expect):
    r = rt()
    got = play(r, [e for e in normal() if e[0] != drop])
    assert (g(expect), "execution_admitted", "admission") in got
    assert r.verdicts("request_attempt", K)[g("P1_admission")] != "S"     # admission not committed


@pytest.mark.parametrize("weak", ["identity.workload_ok", "identity.agent_registered", "identity.agent_credential_ok"])
def test_scheme_b_requires_both_identity_layers(rt, weak):
    r = rt()
    assert (g("P1_identity"), "execution_admitted", "admission") in play(r, normal({**ID_B, weak: False}))


@pytest.mark.parametrize("field,pid", [("permit.bound", "P1_binding"), ("permit.live", "P5_live")])
def test_admission_data_checks(rt, field, pid):
    r = rt()
    t = normal()
    t[5] = ("execution_admitted", {**ADM, field: False})
    assert (g(pid), "execution_admitted", "admission") in play(r, t)


def test_deny_then_execute_is_blocked_at_request_scope(rt):
    r = rt()
    t = [("request_received", {}), ("identity_verified", ID_B), ("authorization_denied", {}),
         ("request_denied", {}), ("execution_admitted", ADM)]
    assert (g("P2_request"), "execution_admitted", "admission") in play(r, t)


def test_pre_audit_must_be_durable_before_start(rt):
    r = rt()
    t = normal()
    t[6] = ("audit_pre_recorded", {"audit.correlated": True, "audit.durable": False})
    assert (g("P6_pre_audit"), "execution_started", "admission") in play(r, t)


def test_duplicate_outcome_and_success_without_start(rt):
    r = rt()
    assert (g("P6_single_outcome"), "execution_succeeded", "step") in play(r, normal()[:9] + [("execution_succeeded", {})])
    r = rt()
    assert (g("P6_outcome_after_start"), "execution_succeeded", "step") in play(r, normal()[:7] + [("execution_succeeded", {})])


OP = ("wfr-1", "transaction_processing_agent", "execute_transfer", "digest")


def op(r, ev, fields=None):
    return step(r, "operation", OP, ev, fields or {})


def test_critical_at_most_once_and_retry_after_failure(rt):
    r = rt()
    assert op(r, "execution_admitted", {"tool.critical": True}).ok
    second = op(r, "execution_admitted", {"tool.critical": True})
    assert not second.ok and second.violations[0].property_id == g("P3_at_most_once")
    assert op(r, "execution_failed").ok                # an explicit failure allows one new admission
    assert op(r, "execution_admitted", {"tool.critical": True}).ok
    assert not op(r, "execution_admitted", {"tool.critical": True}).ok


def test_non_critical_repeat_allowed_and_denied_operation_blocked(rt):
    r = rt()
    for _ in range(3):
        assert op(r, "execution_admitted", {"tool.critical": False}).ok
    r = rt()
    assert op(r, "op_denied").ok
    res = op(r, "execution_admitted", {"tool.critical": False})
    assert not res.ok and res.violations[0].property_id == g("P2_operation")


B_ = ("wfr-1", "EOD-B-000001")


def wb(r, ev):
    return step(r, "workflow_batch", B_, ev, {})


def test_eod_preconditions(rt):
    r = rt()
    assert not wb(r, "ledger_admitted").ok                          # skipped readiness
    r = rt()
    assert wb(r, "readiness_not_ready").ok and not wb(r, "ledger_admitted").ok
    r = rt()
    for ev in ("readiness_ready", "batch_other", "ledger_admitted", "recon_matched", "report_admitted"):
        assert wb(r, ev).ok, ev
    r = rt()
    for ev in ("readiness_ready", "ledger_admitted", "recon_mismatched"):
        assert wb(r, ev).ok
    assert not wb(r, "report_admitted").ok                          # report after mismatch
    assert wb(r, "exception_admitted").ok
    r = rt()
    for ev in ("readiness_ready", "ledger_admitted", "recon_matched"):
        assert wb(r, ev).ok
    assert not wb(r, "exception_admitted").ok                       # exception without mismatch


def test_participation(rt):
    P = ("wfr-1", "ledger_update_agent")
    r = rt()
    res = step(r, "workflow_participation", P, "execution_admitted", {})
    assert not res.ok and res.violations[0].property_id == g("P4_participant")
    r = rt()
    assert step(r, "workflow_participation", P, "dispatched", {}).ok
    assert step(r, "workflow_participation", P, "execution_admitted", {}).ok
    assert step(r, "workflow_participation", P, "dispatch_ended", {}).ok
    res = step(r, "workflow_participation", P, "execution_admitted", {})
    assert not res.ok and res.violations[0].property_id == g("P4_within_dispatch")
    assert step(r, "workflow_participation", P, "dispatched", {}).ok
    assert step(r, "workflow_participation", P, "execution_admitted", {}).ok


def test_slices_are_isolated(rt):
    r = rt()
    play(r, [("request_received", {}), ("authorization_denied", {}), ("request_denied", {})], key=("attempt-2",))
    assert play(r, normal()) == []
    wb1, wb2 = ("wfr-1", "EOD-B-1"), ("wfr-2", "EOD-B-1")
    step(r, "workflow_batch", wb1, "readiness_ready", {})
    assert not step(r, "workflow_batch", wb2, "ledger_admitted", {}).ok     # no borrowing across runs
    assert step(r, "workflow_batch", wb1, "ledger_admitted", {}).ok


def test_multi_slice_admission_is_all_or_nothing(rt):
    r = rt()
    P = ("wfr-1", "ledger_update_agent")
    step(r, "workflow_participation", P, "dispatched", {})
    play(r, normal()[:5])
    targets = [("request_attempt", K, "execution_admitted", r.bind("request_attempt", "execution_admitted", ADM)),
               ("workflow_participation", P, "execution_admitted", {}),
               ("workflow_batch", B_, "ledger_admitted", {})]               # readiness missing -> must fail
    res = r.admit(targets)
    assert not res.ok and [v.property_id for v in res.violations] == [g("P4_ledger_after_readiness")]
    assert r.verdicts("request_attempt", K)[g("P1_admission")] == "P"       # nothing committed
    step(r, "workflow_batch", B_, "readiness_ready", {})
    assert r.admit(targets).ok


def test_concurrent_duplicate_critical_admissions_only_one_wins(rt):
    r = rt()
    wins = []
    barrier = threading.Barrier(16)
    data = r.bind("operation", "execution_admitted", {"tool.critical": True})

    def worker():
        barrier.wait()
        wins.append(r.admit([("operation", OP, "execution_admitted", data)]).ok)
    ts = [threading.Thread(target=worker) for _ in range(16)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert wins.count(True) == 1 and wins.count(False) == 15


def test_capacity_rejects_new_slices_and_never_evicts(rt):
    r = rt(capacity={"request_attempt": 2})
    play(r, [("request_received", {})], key=("a",))
    play(r, [("request_received", {}), ("authorization_denied", {}), ("request_denied", {})], key=("b",))
    with pytest.raises(CapacityExceeded):
        r.observe([("request_attempt", ("c",), "request_received", {})])
    assert not step(r, "request_attempt", ("b",), "execution_admitted", ADM).ok   # denial still enforced
    r.close("request_attempt", ("a",))
    assert r.observe([("request_attempt", ("c",), "request_received", {})]).ok


def test_binding_requires_the_catalogue_fields(rt):
    r = rt()
    with pytest.raises(KeyError):                       # field missing -> UnboundField (fail closed)
        r.bind("request_attempt", "execution_admitted", {"permit.bound": True})
