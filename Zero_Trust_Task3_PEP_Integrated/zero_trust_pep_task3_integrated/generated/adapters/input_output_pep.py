"""Generated placeholder for input_output_pep.py; no current manifest edge requires this adapter type."""
from __future__ import annotations
from typing import Any, Callable
from zt_pep.runtime import PEPEnforcer


def protect(enforcer: PEPEnforcer, placement_id: str, operation: Callable[..., Any]) -> Callable[..., Any]:
    return enforcer.wrap_sync(placement_id, operation)
