"""Controlled service map: SPIFFE ID -> subject for the Backplane's own SERVICES
(gateway, agent-credential issuer, ingress clients).

Agents never authenticate through this map: in scheme B an agent is identified by
its agent certificate, which must be bound to the workload SPIFFE ID of the mTLS peer
(``agent_identity.verifier``). The map is written by the trusted deployment step and
reloaded when the file changes (rate-limited); it is never filled from request data.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..events import EventLog


@dataclass(frozen=True)
class MapEntry:
    kind: str
    agent_id: str
    identity_version: str
    enabled: bool
    # ingress services only: end-user roles this front end may assert for a session
    user_roles: tuple[str, ...] = ()


class IdentityMap:
    """Controlled SPIFFE-ID -> subject registry, reloaded when the file changes."""

    def __init__(self, path: str | Path, *, events: EventLog | None = None,
                 on_change: Callable[[str, str, str], None] | None = None) -> None:
        self.path = Path(path)
        self.events = events or EventLog(None)
        self.on_change = on_change
        self._mtime = 0.0
        self._last_check = 0.0
        self.version = 0
        self.entries: dict[str, MapEntry] = {}
        self._load()

    def _load(self) -> None:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        new = {
            sid: MapEntry(kind=e["kind"], agent_id=e["agent_id"],
                          identity_version=f"wl-idv-{int(e['identity_version'])}",
                          enabled=bool(e["enabled"]),
                          user_roles=tuple(str(r) for r in e.get("user_roles", ())))
            for sid, e in raw["entries"].items()
        }
        old = self.entries
        self.entries = new
        self.version = int(raw["version"])
        self._mtime = os.stat(self.path).st_mtime
        for sid, e in new.items():
            prev = old.get(sid)
            if prev is not None and (prev.identity_version != e.identity_version or prev.enabled != e.enabled):
                self.events.emit("identity_map_change", spiffe_id=sid, agent_id=e.agent_id,
                                 enabled=e.enabled, identity_version=e.identity_version)
                if self.on_change:
                    self.on_change(e.agent_id, e.identity_version, e.kind)

    def maybe_reload(self) -> None:
        now = time.monotonic()
        if now - self._last_check < 2.0:
            return
        self._last_check = now
        try:
            if os.stat(self.path).st_mtime != self._mtime:
                self._load()
        except OSError:
            pass

    def lookup(self, spiffe_id: str) -> MapEntry | None:
        self.maybe_reload()
        return self.entries.get(spiffe_id)
