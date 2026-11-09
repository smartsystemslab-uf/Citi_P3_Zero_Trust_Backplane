"""Run history: every run the console makes is kept as one JSON file so it can be reloaded in the trace viewer."""
from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any

ID_RE = re.compile(r"^R-\d{8}T\d{6}-[0-9a-f]{4}$")
KEEP = 300


class RunLog:
    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _by_age(self) -> list[Path]:
        """Oldest first. File names only carry whole seconds, so runs in the same second are ordered by mtime."""
        return sorted(self.dir.glob("R-*.json"), key=lambda p: (p.stat().st_mtime_ns, p.name))

    def add(self, app: str, name: str, result: dict[str, Any]) -> str:
        rid = f"R-{time.strftime('%Y%m%dT%H%M%S', time.gmtime())}-{uuid.uuid4().hex[:4]}"
        rec = {"id": rid, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "app": app,
               "name": (name or "").strip()[:120], **result}
        with self._lock:
            tmp = self.dir / f".{rid}.tmp"
            tmp.write_text(json.dumps(rec), encoding="utf-8")
            os.replace(tmp, self.dir / f"{rid}.json")
            files = self._by_age()
            for old in files[:-KEEP]:
                old.unlink(missing_ok=True)
        return rid

    def list(self, apps: str | tuple[str, ...], limit: int = 60) -> list[dict[str, Any]]:
        names = (apps,) if isinstance(apps, str) else tuple(apps)
        out = []
        for p in reversed(self._by_age()):
            try:
                r = json.loads(p.read_text(encoding="utf-8"))
            except ValueError:
                continue
            if r.get("app") not in (*names, None):
                continue
            out.append({"id": r["id"], "ts": r["ts"], "name": r.get("name", ""), "role": r.get("role", ""),
                        "messages": r.get("messages", []), "state": r["verdict"]["state"],
                        "title": r["verdict"]["title"], "passed": r.get("passed")})
            if len(out) >= limit:
                break
        return out

    def get(self, rid: str) -> dict[str, Any] | None:
        if not ID_RE.match(rid):
            return None
        p = self.dir / f"{rid}.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else None
