"""Generated PEP adapters. Regenerate rather than editing this file."""
from __future__ import annotations
import inspect
from typing import Any, Callable

from zt_pep.runtime import PEPEnforcer

def protect(enforcer: PEPEnforcer, placement_id: str, operation: Callable[..., Any]) -> Callable[..., Any]:
    return enforcer.wrap_async(placement_id, operation) if inspect.iscoroutinefunction(operation) else enforcer.wrap_sync(placement_id, operation)

def protect_pep_customer_transaction_execute_transfer(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.customer_transaction.execute_transfer', operation)

def protect_pep_eod_processing_get_batches(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.eod_processing.get_batches', operation)

def protect_pep_fraud_review_policy_search(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.fraud_review.policy_search', operation)

def protect_pep_ledger_update_apply_ledger_updates(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.ledger_update.apply_ledger_updates', operation)

def protect_pep_scanner_scan_edge_005_report_writing_agent_store_report(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_005_report_writing_agent_store_report', operation)

def protect_pep_scanner_scan_edge_006_exception_agent_create_exception_case(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_006_exception_agent_create_exception_case', operation)

def protect_pep_scanner_scan_edge_007_transaction_monitoring_agent_get_customer_context(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_007_transaction_monitoring_agent_get_customer_context', operation)

def protect_pep_scanner_scan_edge_010_fraud_detection_agent_get_customer_context(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_010_fraud_detection_agent_get_customer_context', operation)

def protect_pep_scanner_scan_edge_014_compliance_agent_get_customer_context(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_014_compliance_agent_get_customer_context', operation)

def protect_pep_scanner_scan_edge_026_risk_compliance_agent_search_policies(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_026_risk_compliance_agent_search_policies', operation)
