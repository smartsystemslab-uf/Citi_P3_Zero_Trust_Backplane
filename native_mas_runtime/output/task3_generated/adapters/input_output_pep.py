"""Generated PEP adapters. Regenerate rather than editing this file."""
from __future__ import annotations
import inspect
from typing import Any, Callable

from zt_pep.runtime import PEPEnforcer

def protect(enforcer: PEPEnforcer, placement_id: str, operation: Callable[..., Any]) -> Callable[..., Any]:
    return enforcer.wrap_async(placement_id, operation) if inspect.iscoroutinefunction(operation) else enforcer.wrap_sync(placement_id, operation)

def protect_pep_native_cli_input(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.native.cli_input', operation)

def protect_pep_native_cli_output(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.native.cli_output', operation)
