"""Generated PEP adapters. Regenerate rather than editing this file."""
from __future__ import annotations
import inspect
from typing import Any, Callable

from zt_pep.runtime import PEPEnforcer

def protect(enforcer: PEPEnforcer, placement_id: str, operation: Callable[..., Any]) -> Callable[..., Any]:
    return enforcer.wrap_async(placement_id, operation) if inspect.iscoroutinefunction(operation) else enforcer.wrap_sync(placement_id, operation)

def protect_pep_eod_processing_reconcile(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.eod_processing.reconcile', operation)

def protect_pep_fraud_review_read_history(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.fraud_review.read_history', operation)
