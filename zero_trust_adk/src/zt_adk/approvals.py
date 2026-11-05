"""Human approval of critical operations.

When the PDP holds an operation for MANUAL_REVIEW, the runtime files an approval request
(``<state>/approvals/requests/<id>.json``) describing exactly the operation the PDP decided:
subject, resource, action, workflow and run, environment and the tool arguments, plus the
request hash the PDP binds approvals to. An approver inspects it and signs a decision with
an approver key that the runtime never holds (``zt-adk approvals approve|deny``). The signed
decision is stored next to the request; the runtime picks it up, attaches it to a fresh PDP
request, and the PDP verifies signature, issuer purpose, request binding, lifetime and single
use before the policy can allow the operation.

Before signing, the approver's tool recomputes the request hash from the shown fields: a
request file whose hash does not match what it shows is refused.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from zt_backplane.canonical import compute_request_hash
from zt_backplane.evidence_issuer import IssuerKey, bound_decision_payload, sign_bound_decision
from zt_backplane.models import PDPRequest

PURPOSES = ("human_approval", "secondary_authorization")


class ApprovalError(RuntimeError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _atomic_write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def operation_hash(op: dict[str, Any]) -> str:
    """The PDP request hash of an operation (zt_backplane.canonical.operation_payload)."""
    req = PDPRequest(
        schema_version="1.0", request_id="hash-only", trace_id="hash-only",
        subject={"canonical_id": op["subject"], "runtime_id": op["subject_runtime_id"], "identity_evidence": {}},
        resource={"canonical_id": op["resource"], "runtime_id": op.get("resource_runtime_id")},
        action=op["action"],
        context={"workflow_id": op.get("workflow_id"), "workflow_instance_id": op.get("workflow_instance_id"),
                 "risk": "low", "timestamp": _now(), "environment": op["environment"], "auth_strength": 0,
                 "human_approval": {}},
        parameters=dict(op.get("parameters") or {}), request_hash=None)
    return compute_request_hash(req)


@dataclass
class ApprovalRequest:
    approval_id: str
    record: dict[str, Any]

    @property
    def status(self) -> str:
        return str(self.record.get("status"))


class ApprovalStore:
    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory)
        self.requests = self.dir / "requests"
        self.decisions = self.dir / "decisions"
        self.requests.mkdir(parents=True, exist_ok=True)
        self.decisions.mkdir(parents=True, exist_ok=True)

    # -- runtime side ------------------------------------------------------------------
    def file_request(self, *, operation: dict[str, Any], request_hash: str, purposes: list[str], app: str,
                     agent: str, tool: str, reason: str, trace_id: str, ttl_seconds: int = 3600) -> ApprovalRequest:
        if operation_hash(operation) != request_hash:
            raise ApprovalError("operation and request hash disagree")
        # one open request per operation: reuse it
        for existing in self.list(status="pending"):
            if existing.record.get("request_hash") == request_hash and existing.record.get("purposes") == purposes:
                return existing
        approval_id = f"apr-{uuid.uuid4().hex[:12]}"
        now = _now()
        record = {
            "approval_id": approval_id, "status": "pending", "created_at": _iso(now),
            "expires_at": _iso(now + timedelta(seconds=ttl_seconds)), "app": app, "agent": agent, "tool": tool,
            "reason": reason, "trace_id": trace_id, "purposes": purposes, "request_hash": request_hash,
            "operation": operation,
        }
        _atomic_write(self.requests / f"{approval_id}.json", record)
        return ApprovalRequest(approval_id, record)

    def decisions_for(self, approval_id: str) -> dict[str, dict[str, Any]]:
        out = {}
        for purpose in PURPOSES:
            p = self.decisions / f"{approval_id}.{purpose}.json"
            if p.exists():
                out[purpose] = json.loads(p.read_text(encoding="utf-8"))
        return out

    def find_for_hash(self, request_hash: str) -> list[ApprovalRequest]:
        return [r for r in self.list() if r.record.get("request_hash") == request_hash]

    def mark(self, approval_id: str, status: str, **extra: Any) -> None:
        p = self.requests / f"{approval_id}.json"
        rec = json.loads(p.read_text(encoding="utf-8"))
        rec["status"] = status
        rec.update(extra)
        _atomic_write(p, rec)

    async def wait(self, approval_id: str, purposes: list[str], *, timeout: float, poll: float) -> dict[str, Any]:
        """Wait until every purpose has a decision, one is a DENY, or the timeout passes."""
        import asyncio

        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            got = self.decisions_for(approval_id)
            if any(d.get("decision") == "DENY" for d in got.values()):
                return got
            if all(p in got for p in purposes):
                return got
            if time.monotonic() >= deadline:
                return got
            await asyncio.sleep(poll)

    # -- approver side -------------------------------------------------------------------
    def list(self, status: str | None = None) -> list[ApprovalRequest]:
        out = []
        for p in sorted(self.requests.glob("apr-*.json")):
            rec = json.loads(p.read_text(encoding="utf-8"))
            if status is None or rec.get("status") == status:
                out.append(ApprovalRequest(rec["approval_id"], rec))
        return out

    def get(self, approval_id: str) -> ApprovalRequest:
        p = self.requests / f"{approval_id}.json"
        if not p.exists():
            raise ApprovalError(f"no approval request {approval_id}")
        rec = json.loads(p.read_text(encoding="utf-8"))
        return ApprovalRequest(approval_id, rec)

    def decide(self, approval_id: str, *, key: IssuerKey, purpose: str, approve: bool, approver: str,
               lifetime_seconds: int, comment: str = "") -> dict[str, Any]:
        if purpose not in PURPOSES:
            raise ApprovalError(f"unknown purpose {purpose}")
        req = self.get(approval_id)
        rec = req.record
        if purpose not in rec.get("purposes", []):
            raise ApprovalError(f"request {approval_id} does not ask for {purpose}")
        if rec.get("status") != "pending":
            raise ApprovalError(f"request {approval_id} is {rec.get('status')}")
        if datetime.fromisoformat(rec["expires_at"].replace("Z", "+00:00")) < _now():
            raise ApprovalError(f"request {approval_id} expired")
        if operation_hash(rec["operation"]) != rec["request_hash"]:
            raise ApprovalError("the request's hash does not match the operation it shows: refused")
        other = self.decisions_for(approval_id)
        if other and any(d.get("issuer") == key.issuer for d in other.values()):
            raise ApprovalError("the same approver cannot give both the approval and the secondary authorization")
        op = rec["operation"]
        payload = bound_decision_payload(
            request_hash=rec["request_hash"], subject_canonical_id=op["subject"],
            resource_canonical_id=op["resource"], action=op["action"],
            workflow_instance_id=op.get("workflow_instance_id"), decision="ALLOW" if approve else "DENY",
            issued_at=_now(), lifetime_seconds=lifetime_seconds,
            extra={"approval_id": approval_id, "approver": approver, "comment": comment[:500]})
        signed = sign_bound_decision(payload, key)
        _atomic_write(self.decisions / f"{approval_id}.{purpose}.json", signed)
        decisions = self.decisions_for(approval_id)
        if not approve:
            self.mark(approval_id, "denied", decided_at=_iso(_now()))
        elif all(p in decisions for p in rec["purposes"]):
            self.mark(approval_id, "approved", decided_at=_iso(_now()))
        return signed
