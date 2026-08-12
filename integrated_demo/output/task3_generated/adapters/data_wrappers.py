"""Generated PEP adapters. Regenerate rather than editing this file."""
from __future__ import annotations
import inspect
from typing import Any, Callable

from zt_pep.runtime import PEPEnforcer

def protect(enforcer: PEPEnforcer, placement_id: str, operation: Callable[..., Any]) -> Callable[..., Any]:
    return enforcer.wrap_async(placement_id, operation) if inspect.iscoroutinefunction(operation) else enforcer.wrap_sync(placement_id, operation)

def protect_pep_scanner_scan_edge_027_create_customer_unknown(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_027_create_customer_unknown', operation)

def protect_pep_scanner_scan_edge_028_create_account_unknown(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_028_create_account_unknown', operation)

def protect_pep_scanner_scan_edge_029_create_policy_unknown(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_029_create_policy_unknown', operation)

def protect_pep_scanner_scan_edge_030_create_rule_unknown(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_030_create_rule_unknown', operation)

def protect_pep_scanner_scan_edge_031_update_transaction_status_unknown(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_031_update_transaction_status_unknown', operation)
