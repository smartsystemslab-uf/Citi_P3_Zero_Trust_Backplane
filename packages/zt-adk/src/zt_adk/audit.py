"""Append-only, hash-chained audit log (JSON lines).

Every record carries ``prev`` (hash of the previous record) and ``hash`` (SHA-256 over the
previous hash and the canonical JSON of the record without its hash). ``verify_chain``
detects any edited, removed or reordered record. Records that matter for accountability
(critical operations, approvals, denials) are fsync'ed before the call returns.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _canonical(rec: dict[str, Any]) -> bytes:
    return json.dumps(rec, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False).encode("utf-8")


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq, self._prev = self._tail()

    def _tail(self) -> tuple[int, str]:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0, GENESIS
        last = b""
        with self.path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            block = min(size, 65536)
            fh.seek(size - block)
            lines = [ln for ln in fh.read().splitlines() if ln.strip()]
            last = lines[-1] if lines else b""
        if not last:
            return 0, GENESIS
        rec = json.loads(last)
        return int(rec.get("seq", 0)), str(rec.get("hash", GENESIS))

    RESERVED = frozenset({"seq", "ts", "event", "prev", "hash"})

    def write(self, event_type: str, *, durable: bool = False, **fields: Any) -> dict[str, Any]:
        clash = self.RESERVED.intersection(fields)
        if clash:                       # a payload field would replace the record's own keys
            raise ValueError(f"audit record fields {sorted(clash)} are reserved")
        with self._lock:
            self._seq += 1
            rec: dict[str, Any] = {"seq": self._seq, "ts": datetime.now(timezone.utc).isoformat(),
                                   "event": event_type, **fields, "prev": self._prev}
            rec["hash"] = hashlib.sha256(self._prev.encode() + _canonical(rec)).hexdigest()
            line = json.dumps(rec, sort_keys=True, default=str, ensure_ascii=False) + "\n"
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                if durable:
                    os.fsync(fh.fileno())
            self._prev = rec["hash"]
            return rec


def verify_chain(path: Path) -> dict[str, Any]:
    prev, n = GENESIS, 0
    with Path(path).open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            rec = json.loads(line)
            h = rec.pop("hash", None)
            if rec.get("prev") != prev:
                return {"ok": False, "records": n, "error": f"line {lineno}: previous-hash link broken"}
            if hashlib.sha256(prev.encode() + _canonical(rec)).hexdigest() != h:
                return {"ok": False, "records": n, "error": f"line {lineno}: record hash mismatch"}
            prev, n = h, n + 1
    return {"ok": True, "records": n, "head": prev}
