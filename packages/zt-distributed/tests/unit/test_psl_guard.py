"""Gateway PSL guard: the start step in the tool thread, single-use tickets, the audit store.

* the pre-execution record, ``audit_pre_recorded`` and ``execution_started`` happen in
  ``redeem`` (the gateway runs it in a worker thread right before the tool host executes);
* a refused start raises PslStartDenied and the tool is not executed;
* tickets are single use and bound to the admitted arguments;
* a durable (fsync) audit write does not hold the append lock while it waits for the disk.
"""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from zt_distributed import psl_guard
from zt_distributed.psl_guard import Attempt, AuditStore, PslGuard, PslStartDenied, TicketError

NS = "org.zt-adk/"


def guard_tools(tools, guard_ref):
    """What the gateway does around the tool host: redeem the admission ticket, then execute."""
    out = {}
    for name, fn in tools.items():
        def make(name=name, fn=fn):
            def guarded(_psl_ticket=None, **kwargs):
                guard_ref().redeem(_psl_ticket, name, kwargs)
                return fn(**kwargs)
            return guarded
        out[name] = make()
    return out


class _Events:
    def emit(self, *a, **k):
        pass


class _Spans:
    def __init__(self):
        self.recs = []

    def add(self, rec):
        self.recs.append(rec)


def _guard(tmp_path: Path, policy_set) -> tuple[PslGuard, _Spans]:
    spans = _Spans()
    return PslGuard(policy_set=policy_set, engine=None, events=_Events(), spans=spans,
                    audit_path=tmp_path / "psl_audit.jsonl"), spans


def _admitted(g: PslGuard, *, tool: str = "account_agent__reset_password", critical: bool = True, n: int = 0) -> Attempt:
    """Drive one attempt to ``execution_admitted`` with the events the gateway produces."""
    args = {"username": "alice", "n": n}
    att = g.request_received(jsonrpc_id=n, session=None, tool=tool, args=args,
                             meta={NS + "workflow_run_id": "wfr-test"}, meta_ns=NS)
    att.agent, att.critical, att.permit_id = "account_agent", critical, f"permit-{n}"
    k = att.key()
    for ev, fields in (("identity_verified", {"identity.workload_ok": True, "identity.agent_registered": True,
                                              "identity.agent_credential_ok": True}),
                       ("authorization_allowed", {}), ("permit_verified", {}), ("execution_requested", {})):
        assert g._obs(att, [("request_attempt", k, ev, fields)]) == []
    g.dispatched("wfr-test", att.agent)
    res = g.runtime.admit(g._bound([
        ("request_attempt", k, "execution_admitted", {"permit.bound": True, "permit.live": True,
                                                      "tool.critical": critical}),
        ("operation", att.op_key(), "execution_admitted", {"tool.critical": critical}),
        ("workflow_participation", ("wfr-test", att.agent), "execution_admitted", {})]))
    assert res.ok, res.violations
    return att


def _records(tmp_path: Path) -> list[dict]:
    p = tmp_path / "psl_audit.jsonl"
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()] if p.exists() else []


def test_correlation_ids_come_from_meta_and_are_never_identity(tmp_path, policy_set):
    g, _ = _guard(tmp_path, policy_set)
    att = g.request_received(jsonrpc_id=7, session="abcdef0123456789", tool="t", args={"a": 1},
                             meta={NS + "request_id": "r-1", NS + "workflow_run_id": "wfr-1",
                                   NS + "identity_valid": True}, meta_ns=NS)
    assert (att.request_id, att.workflow_run_id, att.session) == ("r-1", "wfr-1", "abcdef01...")
    assert att.agent is None                                          # set only by identity_verified


def test_start_in_tool_thread_writes_record_then_starts(tmp_path, policy_set):
    g, spans = _guard(tmp_path, policy_set)
    att = _admitted(g)
    ran = []
    tools = guard_tools({"account_agent__reset_password": lambda **kw: ran.append(kw) or "ok"}, lambda: g)
    tk = g.issue_ticket(att)
    with ThreadPoolExecutor(1) as ex:
        out = ex.submit(lambda: tools["account_agent__reset_password"](_psl_ticket=tk, **att.args)).result()
    assert out == "ok" and ran == [att.args]
    assert g.runtime.verdicts("request_attempt", att.key())["gateway.P6_pre_audit"] == "S"
    recs = _records(tmp_path)
    assert [r["phase"] for r in recs] == ["pre_execution"] and recs[0]["attempt_id"] == att.attempt_id
    assert g.audit.fsyncs == 1 and att.start_ns > 0                   # critical tool: write-ahead fsync
    g.flush_deferred(att)
    g.execution_finished(att, True, "ok")
    assert g.finish(att) == []                                        # outcome record closes the scope clean
    assert [r["phase"] for r in _records(tmp_path)] == ["pre_execution", "outcome"]
    assert not [s for s in spans.recs if s.get("ep") == "psl_violation"]


def test_failed_pre_record_refuses_start_and_function_does_not_run(tmp_path, policy_set, monkeypatch):
    g, spans = _guard(tmp_path, policy_set)
    att = _admitted(g)

    def disk_full(rec, *, durable):
        raise OSError("disk full")
    monkeypatch.setattr(g.audit, "write", disk_full)
    ran = []
    tools = guard_tools({"account_agent__reset_password": lambda **kw: ran.append(kw)}, lambda: g)
    tk = g.issue_ticket(att)
    with ThreadPoolExecutor(1) as ex:
        with pytest.raises(PslStartDenied) as ei:
            ex.submit(lambda: tools["account_agent__reset_password"](_psl_ticket=tk, **att.args)).result()
    assert "gateway.P6_pre_audit" in str(ei.value)
    assert ran == []                                                  # the business function never ran
    assert spans.recs == []                                           # reported on the event loop side
    g.start_denied(att, str(ei.value))
    assert [s["property_id"] for s in spans.recs if s.get("ep") == "psl_violation"] == ["gateway.P6_pre_audit"]
    assert att.denied and att.layer == "psl_monitor"


def test_ticket_is_single_use_and_bound_to_arguments(tmp_path, policy_set):
    g, _ = _guard(tmp_path, policy_set)
    att = _admitted(g)
    tools = guard_tools({"account_agent__reset_password": lambda **kw: "ok"}, lambda: g)
    tk = g.issue_ticket(att)
    with pytest.raises(TicketError):                  # other arguments than admitted
        tools["account_agent__reset_password"](_psl_ticket=tk, username="mallory", n=0)
    att2 = _admitted(g, n=1)
    tk2 = g.issue_ticket(att2)
    assert tools["account_agent__reset_password"](_psl_ticket=tk2, **att2.args) == "ok"
    with pytest.raises(TicketError):                  # reuse
        tools["account_agent__reset_password"](_psl_ticket=tk2, **att2.args)
    with pytest.raises(TicketError):                  # no ticket
        tools["account_agent__reset_password"](**att2.args)


def test_rejected_attempt_marks_operation_denied(tmp_path, policy_set):
    g, _ = _guard(tmp_path, policy_set)
    att = g.request_received(jsonrpc_id=1, session=None, tool="account_agent__unlock_account", args={"username": "bob"},
                             meta={NS + "workflow_run_id": "wfr-test"}, meta_ns=NS)
    att.agent = "account_agent"
    g.reject(att, "authorization_denied", layer="pdp", reason="DENY", terminal_for_operation=True)
    res = g.runtime.admit(g._bound([("operation", att.op_key(), "execution_admitted", {"tool.critical": True})]))
    assert not res.ok and res.violations[0].property_id == "gateway.P2_operation"
    assert g.by_run["wfr-test"] == {("operation", att.op_key())}
    g.run_closed("wfr-test")                                          # workflow end releases the slices
    assert "wfr-test" not in g.by_run


def test_concurrent_critical_starts_each_get_a_durable_record(tmp_path, policy_set):
    g, _ = _guard(tmp_path, policy_set)
    atts = [_admitted(g, n=i) for i in range(16)]
    tools = guard_tools({"account_agent__reset_password": lambda **kw: kw["n"]}, lambda: g)
    tickets = [g.issue_ticket(a) for a in atts]
    with ThreadPoolExecutor(16) as ex:
        outs = list(ex.map(lambda p: tools["account_agent__reset_password"](_psl_ticket=p[1], **p[0].args), zip(atts, tickets)))
    assert sorted(outs) == list(range(16))
    assert sorted(r["attempt_id"] for r in _records(tmp_path)) == sorted(a.attempt_id for a in atts)
    assert g.audit.fsyncs == 16 and g.audit.records == 16


def test_audit_append_does_not_wait_for_another_writers_fsync(tmp_path, monkeypatch):
    store = AuditStore(tmp_path / "a.jsonl")
    entered, release = threading.Event(), threading.Event()
    real_fsync = psl_guard.os.fsync

    def slow_fsync(fd):
        entered.set()
        assert release.wait(5)
        real_fsync(fd)

    monkeypatch.setattr(psl_guard.os, "fsync", slow_fsync)
    t = threading.Thread(target=store.write, args=({"phase": "pre_execution", "i": 1},), kwargs={"durable": True})
    t.start()
    assert entered.wait(5)
    t0 = time.perf_counter()
    store.write({"phase": "outcome", "i": 2}, durable=False)
    waited = time.perf_counter() - t0
    release.set()
    t.join(5)
    assert waited < 0.5, f"non-durable append waited {waited:.3f}s for a foreign fsync"
    lines = [json.loads(x) for x in (tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [r["i"] for r in lines] == [1, 2] and store.fsyncs == 1 and store.records == 2


def test_guard_refuses_a_store_without_gateway_monitors(tmp_path, policy_set):
    class NoGateway:                      # a policy set whose rules no runtime "gateway" evaluates
        rules = [r for r in policy_set.rules if r.scope not in psl_guard.GATEWAY_SCOPES]
        digest = policy_set.digest
        catalog = policy_set.catalog
    with pytest.raises(RuntimeError, match="no gateway monitors"):
        PslGuard(policy_set=NoGateway(), engine=None, events=_Events(), spans=_Spans(),
                 audit_path=tmp_path / "x.jsonl")
