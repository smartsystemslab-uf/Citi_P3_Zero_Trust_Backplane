"""PSL runtime monitoring of the MCP tool path inside the gateway PEP.

The monitored properties are the temporal rules of the SIGNED policy store
(zero_trust_pdp_task4_secure/policy_store/gateway_runtime.psl, runtime "gateway",
scopes request_attempt / operation / workflow_batch / workflow_participation); they are
loaded from the same verified PslPolicyStore the in-process PDP uses -- there is no
second copy of the policies. The workflow_run rules of intent.psl are evaluated by the
engine's own monitor in authorize / begin_tool / finish_tool.

Responsibilities
* derive trusted events and field values from server-side results only (authenticator
  output, PDP decision, Permit Lease decoded and signature-verified with the Task 5
  validator, revocation service, the business function's own return value) -- never
  from client-supplied MCP ``_meta`` fields;
* slice the event stream per scope key and run the monitors; field values are bound
  to the monitors' atomic propositions through the catalogue (MonitorRuntime.bind);
* admission: atomically check-and-commit ``execution_admitted`` across all affected
  slices BEFORE the business function can run, then hand out a single-use execution
  ticket bound to (attempt, tool, args digest); the business functions are wrapped so
  that they refuse to run without a ticket;
* start (in the tool thread, immediately before the business function): redeem the
  ticket, write the pre-execution record (write-ahead with fsync for critical tools),
  observe ``audit_pre_recorded``, then admit ``execution_started``; violations found in
  the thread are reported by the event loop afterwards (``flush_deferred``);
* close scopes (request end, workflow run end) and report close violations.
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from zt_psl.runtime import CapacityExceeded, MonitorRuntime, Violation, args_digest

GATEWAY_SCOPES = ("request_attempt", "operation", "workflow_batch", "workflow_participation")
EOD_TOOLS = {"validate_eod_readiness", "get_eod_batch", "apply_ledger_updates", "get_reconciliation_data",
             "create_exception_case", "store_report"}
BATCH_ADMISSION = {"apply_ledger_updates": "ledger_admitted", "store_report": "report_admitted",
                   "create_exception_case": "exception_admitted"}
DEFAULT_CAPACITY = {"request_attempt": 20000, "operation": 50000, "workflow_batch": 20000,
                    "workflow_participation": 20000}
P5_LIVE = "gateway.P5_live"

Target = tuple[str, tuple, str, Mapping[str, Any]]      # (scope, key, event, catalogue field values)


class TicketError(RuntimeError):
    pass


class PslStartDenied(RuntimeError):
    """``execution_started`` was refused in the tool thread; the business function did not run."""


@dataclass
class Attempt:
    attempt_id: str
    jsonrpc_id: Any
    session: str | None
    tool: str
    args: dict[str, Any]
    digest: str
    request_id: str = ""
    call_id: str = ""
    workflow_run_id: str = ""
    agent: str | None = None
    workload: str | None = None
    auth_mode: str | None = None
    permit_id: str | None = None
    critical: bool = False
    t0: int = field(default_factory=time.perf_counter_ns)
    psl_ns: int = 0
    lock_wait_ns: int = 0
    audit_ns: int = 0
    binding_ns: int = 0
    start_ns: int = 0
    violations: list[dict[str, Any]] = field(default_factory=list)
    denied: bool = False
    outcome: str | None = None
    layer: str | None = None
    reason: str | None = None
    closed: bool = False
    deferred: list[Violation] = field(default_factory=list)

    def key(self) -> tuple:
        return (self.attempt_id,)

    def op_key(self) -> tuple:
        return (self.workflow_run_id, self.agent, self.tool, self.digest)

    def correlation(self) -> dict[str, Any]:
        return {"attempt_id": self.attempt_id, "request_id": self.request_id, "call_id": self.call_id,
                "jsonrpc_id": self.jsonrpc_id, "mcp_session": self.session, "agent": self.agent,
                "workload": self.workload, "auth_mode": self.auth_mode, "tool": self.tool,
                "args_sha256": self.digest, "workflow_run_id": self.workflow_run_id, "permit_id": self.permit_id}


class Ticket:
    __slots__ = ("attempt_id", "tool", "digest", "used", "att")

    def __init__(self, att: Attempt) -> None:
        self.attempt_id, self.tool, self.digest, self.used, self.att = att.attempt_id, att.tool, att.digest, False, att


class AuditStore:
    """Append-only JSON lines. Appends are serialised by a short lock; a durable write
    fsyncs a duplicate descriptor OUTSIDE the lock and returns only after its own record
    is on disk."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.records = 0
        self.fsyncs = 0

    def write(self, rec: Mapping[str, Any], *, durable: bool) -> None:
        line = json.dumps(rec, sort_keys=True, default=str) + "\n"
        dup = -1
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                if durable:
                    dup = os.dup(fh.fileno())
            self.records += 1
        if dup >= 0:
            try:
                os.fsync(dup)
            finally:
                os.close(dup)
            with self._lock:
                self.fsyncs += 1


class PslGuard:
    def __init__(self, *, policy_set: Any, engine: Any, events: Any, spans: Any, audit_path: Path,
                 capacity: Mapping[str, int] | None = None) -> None:
        self.engine = engine
        self.events = events
        self.spans = spans
        self.runtime = MonitorRuntime.from_policy_set(policy_set, "gateway", scopes=GATEWAY_SCOPES,
                                                      capacity=capacity or DEFAULT_CAPACITY)
        missing = set(GATEWAY_SCOPES) - set(self.runtime.machines)
        if missing:                       # fail closed: the signed store must define every gateway scope
            raise RuntimeError(f"signed policy store has no gateway monitors for scopes {sorted(missing)}")
        self.audit = AuditStore(audit_path)
        self.tickets: dict[str, Ticket] = {}
        self._tickets_lock = threading.Lock()
        self.by_run: dict[str, set[tuple[str, tuple]]] = {}
        self._run_lock = threading.Lock()
        self.counters: dict[str, int] = {}
        self._count_lock = threading.Lock()
        self.events.emit("psl_monitor_loaded", source_sha256=self.runtime.source_sha256,
                         properties=sorted({m.pid for ms in self.runtime.machines.values() for m in ms}))

    # ------------------------------------------------------------------ util
    def _count(self, k: str, n: int = 1) -> None:
        with self._count_lock:
            self.counters[k] = self.counters.get(k, 0) + n

    def _index_run(self, wfr: str, scope: str, key: tuple) -> None:
        if not wfr:
            return
        with self._run_lock:
            self.by_run.setdefault(wfr, set()).add((scope, key))

    def _bound(self, targets: list[Target]) -> list[tuple[str, tuple, str, dict[str, bool]]]:
        """Catalogue field values -> the atomic propositions the monitors read at that event."""
        return [(scope, key, ev, self.runtime.bind(scope, ev, fields)) for scope, key, ev, fields in targets]

    def _obs(self, att: Attempt | None, targets: list[Target]) -> list[Violation]:
        res = self.runtime.observe(self._bound(targets))
        if att is not None:
            att.psl_ns += res.check_ns
            att.lock_wait_ns += res.lock_wait_ns
        for scope, key, _, _ in targets:
            if scope != "request_attempt":
                self._index_run(key[0], scope, key)
        if res.violations:
            self._report(att, res.violations)
        return res.violations

    def _report(self, att: Attempt | None, viols: list[Violation]) -> None:
        for v in viols:
            d = {"property_id": v.property_id, "scope": v.scope, "event": v.event, "when": v.when}
            if att is not None:
                att.violations.append(d)
            self._count(f"violation:{v.when}:{v.property_id}")
            self.spans.add({"ep": "psl_violation", "ts": time.time(), **d,
                            "key": [str(x)[:64] for x in v.key],
                            **({"attempt_id": att.attempt_id, "request_id": att.request_id} if att else {})})

    # --------------------------------------------------------------- request
    def request_received(self, *, jsonrpc_id: Any, session: str | None, tool: str, args: dict[str, Any],
                         meta: Mapping[str, Any], meta_ns: str) -> Attempt:
        att = Attempt(attempt_id=str(uuid.uuid4()), jsonrpc_id=jsonrpc_id,
                      session=(session[:8] + "...") if session else None, tool=str(tool), args=dict(args or {}),
                      digest=args_digest(args or {}))
        # correlation identifiers only (signed with the request body in scheme B); never
        # read as identity or permit statements
        att.request_id = str(meta.get(meta_ns + "request_id", ""))[:128]
        att.call_id = str(meta.get(meta_ns + "call_id", ""))[:128]
        att.workflow_run_id = str(meta.get(meta_ns + "workflow_run_id", ""))[:128]
        self._obs(att, [("request_attempt", att.key(), "request_received", {})])
        return att

    def identity_verified(self, att: Attempt, ident: Any, transport: Any) -> None:
        att.agent, att.workload, att.auth_mode = ident.agent_id, ident.workload_spiffe_id, ident.auth_mode
        fields = {
            "identity.workload_ok": bool(transport is not None and ident.workload_spiffe_id
                                         and transport.spiffe_id == ident.workload_spiffe_id),
            "identity.agent_registered": bool(ident.subject_kind == "agent" and ident.agent_id
                                              and ident.identity_version),
            "identity.agent_credential_ok": bool(ident.auth_mode == "B" and ident.agent_credential_id
                                                 and "rfc9421" in (ident.authentication_method or "")),
        }
        self._obs(att, [("request_attempt", att.key(), "identity_verified", fields)])

    def reject(self, att: Attempt, event: str, *, layer: str, reason: str, terminal_for_operation: bool) -> None:
        """A layer rejected this attempt: record the rejection, the denial and (for terminal
        decisions about an authenticated caller's operation) the operation denial."""
        t: list[Target] = [("request_attempt", att.key(), event, {})] if event != "request_denied" else []
        t.append(("request_attempt", att.key(), "request_denied", {}))
        self._obs(att, t)
        if terminal_for_operation and att.agent and att.workflow_run_id:
            self._obs(att, [("operation", att.op_key(), "op_denied", {})])
        att.denied, att.layer, att.reason, att.outcome = True, layer, reason, "denied"

    # ------------------------------------------------------- authorization path
    def authorization_result(self, att: Attempt, pending: Any, auth_ctx_flags: Mapping[str, bool]) -> str:
        """Classify the authorization result into trusted events.
        Returns 'allowed' | 'authorization_denied' | 'permit_rejected' | 'authorization_unavailable'."""
        auth = pending.authorization
        ra = auth.runtime_authorization
        att.critical = bool(auth.placement and auth.placement.get("critical"))
        if auth.allowed and auth_ctx_flags.get("validate_ok"):
            att.permit_id = auth.permit_id
            self._obs(att, [("request_attempt", att.key(), "authorization_allowed", {}),
                            ("request_attempt", att.key(), "permit_verified", {})])
            return "allowed"
        if ra is None:                         # no generated PEP placement: local default deny
            return "authorization_denied"
        if auth.source == "PSL_WORKFLOW_MONITOR":
            # a workflow_run rule (intent.psl) refused the call after the PDP allowed it: a
            # terminal policy decision, not a permit failure
            return "authorization_denied"
        if ra.decision is not None and not ra.decision.allows_execution:
            return "authorization_denied"
        if auth_ctx_flags.get("issue_called"):     # decision allowed, lease issue/validation failed
            self._obs(att, [("request_attempt", att.key(), "authorization_allowed", {})])
            return "permit_rejected"
        reason = str(auth.reason or "")
        if reason.startswith(("PDP_TIMEOUT", "PDP_INTEGRATION_ERROR")):
            return "authorization_unavailable"     # not a decision: non-terminal for the operation
        return "authorization_denied"

    def execution_requested(self, att: Attempt) -> None:
        self._obs(att, [("request_attempt", att.key(), "execution_requested", {})])

    def _binding(self, att: Attempt, pending: Any, ident: Any, args_to_run: Mapping[str, Any]) -> tuple[bool, bool, str]:
        t0 = time.perf_counter_ns()
        try:
            token = pending.authorization.runtime_authorization.token
            comps = self.engine.components
            claims = comps.validator.decode_and_verify(token).claims          # Task 5 code, signature checked
            req = pending.request
            placement = pending.authorization.placement or {}
            caller_ok = self.engine.bridge.subject_runtime_ids.get(claims.subject) == ident.agent_id == att.agent
            bound = bool(claims.request_hash == req.request_hash()
                         and claims.subject == str(placement.get("subject_canonical_id"))
                         and claims.resource == str(placement.get("resource_canonical_id"))
                         and claims.action == str(placement.get("action"))
                         and args_digest(req.parameters) == args_digest(args_to_run) == att.digest
                         and claims.permit_id == att.permit_id and caller_ok)
            now = comps.validator.trusted_clock.now()
            live = now < claims.expires_at
            reason = "" if live else "permit_expired"
            if live:
                try:
                    comps.revocations.validate_lease(claims)
                except Exception as exc:                 # RevocationError
                    live, reason = False, f"revoked:{exc}"
            if live and ident.credential_expiry is not None and datetime.now(timezone.utc) >= ident.credential_expiry:
                live, reason = False, "credential_expired"
            return bound, live, reason
        except Exception as exc:
            return False, False, f"binding_check_error:{type(exc).__name__}"
        finally:
            att.binding_ns += time.perf_counter_ns() - t0

    def admit(self, att: Attempt, pending: Any, ident: Any, args_to_run: Mapping[str, Any]) -> tuple[bool, str]:
        """Atomic admission across all affected slices; returns (ok, reason)."""
        bound, live, live_reason = self._binding(att, pending, ident, args_to_run)
        targets: list[Target] = [
            ("request_attempt", att.key(), "execution_admitted",
             {"permit.bound": bound, "permit.live": live, "tool.critical": att.critical}),
            ("operation", att.op_key(), "execution_admitted", {"tool.critical": att.critical}),
            ("workflow_participation", (att.workflow_run_id, att.agent), "execution_admitted", {}),
        ]
        batch = (att.args or {}).get("batch_id")
        if att.tool in BATCH_ADMISSION and batch:
            targets.append(("workflow_batch", (att.workflow_run_id, str(batch)), BATCH_ADMISSION[att.tool], {}))
        try:
            res = self.runtime.admit(self._bound(targets))
        except CapacityExceeded as exc:
            self._count("capacity_rejection")
            self.reject(att, "request_denied", layer="psl_capacity", reason=str(exc), terminal_for_operation=False)
            return False, "PSL_CAPACITY_EXHAUSTED"
        att.psl_ns += res.check_ns
        att.lock_wait_ns += res.lock_wait_ns
        for scope, key, _, _ in targets:
            if scope != "request_attempt":
                self._index_run(key[0], scope, key)
        if not res.ok:
            self._report(att, res.violations)
            pids = sorted({v.property_id for v in res.violations})
            detail = ",".join(pids) + (f" ({live_reason})" if live_reason and P5_LIVE in pids else "")
            self.reject(att, "request_denied", layer="psl_monitor", reason=detail, terminal_for_operation=True)
            self._count("psl_denied")
            return False, detail
        self._count("admitted")
        return True, ""

    def issue_ticket(self, att: Attempt) -> Ticket:
        tk = Ticket(att)
        with self._tickets_lock:
            self.tickets[att.attempt_id] = tk
        return tk

    def redeem(self, ticket: Ticket | None, tool: str, args: Mapping[str, Any]) -> None:
        """Tool thread, immediately before the business function: redeem the ticket, write the
        pre-execution record, observe ``audit_pre_recorded``, admit ``execution_started``.
        Raises if the function must not run."""
        if ticket is None:
            raise TicketError("business function called without a PSL admission ticket")
        ts = time.perf_counter_ns()
        with self._tickets_lock:
            live = self.tickets.pop(ticket.attempt_id, None)
        if live is not ticket or ticket.used or ticket.tool != tool or ticket.digest != args_digest(args):
            raise TicketError("invalid, reused or mismatched PSL admission ticket")
        ticket.used = True
        att = ticket.att
        try:
            self._start(att)
        finally:
            att.start_ns += time.perf_counter_ns() - ts

    def _start(self, att: Attempt) -> None:
        rec = {"phase": "pre_execution", "ts": time.time(), **att.correlation(),
               "critical": att.critical, "psl": "admitted"}
        t0 = time.perf_counter_ns()
        durable_ok = True
        try:
            self.audit.write(rec, durable=att.critical)   # write-ahead (fsync) for critical tools
        except OSError:
            durable_ok = False
        att.audit_ns += time.perf_counter_ns() - t0
        res = self.runtime.observe(self._bound([("request_attempt", att.key(), "audit_pre_recorded",
                                                 {"audit.correlated": True, "audit.durable": durable_ok})]))
        att.psl_ns += res.check_ns
        att.lock_wait_ns += res.lock_wait_ns
        att.deferred.extend(res.violations)
        res = self.runtime.admit(self._bound([("request_attempt", att.key(), "execution_started", {})]))
        att.psl_ns += res.check_ns
        att.lock_wait_ns += res.lock_wait_ns
        if not res.ok:
            att.deferred.extend(res.violations)
            raise PslStartDenied(",".join(sorted({v.property_id for v in res.violations})))

    def flush_deferred(self, att: Attempt) -> None:
        if att.deferred:
            viols, att.deferred = att.deferred, []
            self._report(att, viols)

    def start_denied(self, att: Attempt, reason: str) -> None:
        self.flush_deferred(att)
        self.reject(att, "request_denied", layer="psl_monitor", reason=reason, terminal_for_operation=True)

    def execution_finished(self, att: Attempt, ok: bool, result: Any) -> None:
        ev = "execution_succeeded" if ok else "execution_failed"
        att.outcome = "succeeded" if ok else "failed"
        t: list[Target] = [("request_attempt", att.key(), ev, {}), ("operation", att.op_key(), ev, {})]
        batch = (att.args or {}).get("batch_id")
        if ok and att.tool in EOD_TOOLS and batch:
            t.append(("workflow_batch", (att.workflow_run_id, str(batch)), self._batch_event(att.tool, result), {}))
        self._obs(att, t)

    @staticmethod
    def _batch_event(tool: str, result: Any) -> str:
        try:
            data = json.loads(result) if isinstance(result, str) else dict(result)
        except Exception:
            return "batch_other"
        if tool == "validate_eod_readiness":
            return "readiness_ready" if data.get("ready") is True else "readiness_not_ready"
        if tool == "get_reconciliation_data":
            diff = data.get("difference")
            if diff is None or "error" in data:
                return "batch_other"
            return "recon_matched" if abs(float(diff)) < 0.005 else "recon_mismatched"
        return "batch_other"

    def finish(self, att: Attempt) -> list[dict[str, Any]]:
        """Outcome record + close of the request scope. Returns close violations."""
        if att.closed:
            return []
        rec = {"phase": "outcome", "ts": time.time(), **att.correlation(),
               "outcome": att.outcome or ("denied" if att.denied else "unknown"), "layer": att.layer,
               "reason": (att.reason or "")[:200], "psl_violations": att.violations, "critical": att.critical}
        t0 = time.perf_counter_ns()
        try:
            self.audit.write(rec, durable=False)
            self._obs(att, [("request_attempt", att.key(), "audit_post_recorded", {"audit.correlated": True})])
        except OSError:
            pass
        att.audit_ns += time.perf_counter_ns() - t0
        closed = self.runtime.close("request_attempt", att.key())
        att.closed = True
        with self._tickets_lock:
            self.tickets.pop(att.attempt_id, None)
        out = []
        for v in closed:
            d = {"property_id": v.property_id, "scope": v.scope, "event": v.event, "when": v.when}
            out.append(d)
            self._count(f"violation:close:{v.property_id}")
            self.spans.add({"ep": "psl_violation", "ts": time.time(), **d,
                            "attempt_id": att.attempt_id, "request_id": att.request_id})
        return out

    # ---------------------------------------------------------- workflow runs
    def dispatched(self, wfr: str, agent: str) -> None:
        self._obs(None, [("workflow_participation", (wfr, agent), "dispatched", {})])

    def dispatch_ended(self, wfr: str, agent: str) -> None:
        self._obs(None, [("workflow_participation", (wfr, agent), "dispatch_ended", {})])

    def run_closed(self, wfr: str) -> None:
        with self._run_lock:
            keys = self.by_run.pop(wfr, set())
        for scope, key in keys:
            for v in self.runtime.close(scope, key):
                self._report(None, [v])

    # ------------------------------------------------------------------ misc
    def denial_body(self, att: Attempt, reason: str, *, tool: str, agent: str | None) -> dict[str, Any]:
        pids = [v["property_id"] for v in att.violations] or None
        return {"status": "zero_trust_denied", "boundary": "psl_monitor",
                "reason_code": "PSL_CAPACITY_EXHAUSTED" if reason == "PSL_CAPACITY_EXHAUSTED" else "PSL_VIOLATION",
                "reason": reason, "property_id": pids[0] if pids else None, "property_ids": pids,
                "attempt_id": att.attempt_id, "request_id": att.request_id, "workflow_run_id": att.workflow_run_id,
                "tool": tool, "agent": agent}

    def snapshot(self) -> dict[str, Any]:
        snap = self.runtime.snapshot()
        snap.update(counters=dict(self.counters), open_runs=len(self.by_run), tickets=len(self.tickets),
                    audit_records=self.audit.records, audit_fsyncs=self.audit.fsyncs)
        return snap


def guard_tools(tools: Mapping[str, Callable[..., Any]], guard_ref: Callable[[], PslGuard]) -> dict[str, Callable[..., Any]]:
    """Wrap every business function: it runs only with a valid single-use admission ticket."""
    out = {}
    for name, fn in tools.items():
        def make(name=name, fn=fn):
            def guarded(_psl_ticket: Ticket | None = None, **kwargs: Any) -> Any:
                guard_ref().redeem(_psl_ticket, name, kwargs)
                return fn(**kwargs)
            guarded.__name__ = name
            guarded.__doc__ = fn.__doc__
            guarded.__wrapped_original__ = fn       # type: ignore[attr-defined]
            return guarded
        out[name] = make()
    return out
