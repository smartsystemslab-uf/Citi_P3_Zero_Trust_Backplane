"""Tiny append-only JSONL event log for lifecycle / rotation evidence."""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class EventLog:
    def __init__(self, path: str | Path | None, *, component: str = "") -> None:
        self.path = Path(path) if path else None
        self.component = component or os.environ.get("CITI_COMPONENT", "")
        self._lock = threading.Lock()
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: str, **fields: Any) -> dict[str, Any]:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "mono": time.monotonic(),
            "component": self.component,
            "event": event,
            **fields,
        }
        if self.path is not None:
            line = json.dumps(record, default=str, sort_keys=True)
            with self._lock:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
        return record
