"""Generated PEP adapters. Regenerate rather than editing this file."""
from __future__ import annotations
import inspect
from typing import Any, Callable

from zt_pep.runtime import PEPEnforcer

def protect(enforcer: PEPEnforcer, placement_id: str, operation: Callable[..., Any]) -> Callable[..., Any]:
    return enforcer.wrap_async(placement_id, operation) if inspect.iscoroutinefunction(operation) else enforcer.wrap_sync(placement_id, operation)

def protect_pep_fraud_review_read_history(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.fraud_review.read_history', operation)

def protect_pep_mid_office_financial_data_read_profile(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.mid_office.financial_data.read_profile', operation)

def protect_pep_mid_office_operations_read_snapshot(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.mid_office.operations.read_snapshot', operation)

def protect_pep_scanner_scan_edge_001_validation_checkpoint_agent_validate_eod_readiness(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_001_validation_checkpoint_agent_validate_eod_readiness', operation)

def protect_pep_scanner_scan_edge_004_reconciliation_agent_get_reconciliation_data(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_004_reconciliation_agent_get_reconciliation_data', operation)

def protect_pep_scanner_scan_edge_008_transaction_monitoring_agent_get_transaction_context(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_008_transaction_monitoring_agent_get_transaction_context', operation)

def protect_pep_scanner_scan_edge_009_transaction_monitoring_agent_list_recent_transactions(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_009_transaction_monitoring_agent_list_recent_transactions', operation)

def protect_pep_scanner_scan_edge_012_fraud_detection_agent_list_recent_transactions(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_012_fraud_detection_agent_list_recent_transactions', operation)

def protect_pep_scanner_scan_edge_015_compliance_agent_get_transaction_context(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_015_compliance_agent_get_transaction_context', operation)

def protect_pep_scanner_scan_edge_016_decision_making_agent_submit_manual_review(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_016_decision_making_agent_submit_manual_review', operation)

def protect_pep_scanner_scan_edge_017_knowledge_base_agent_search_faqs(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_017_knowledge_base_agent_search_faqs', operation)

def protect_pep_scanner_scan_edge_020_forecasting_agent_get_operations_snapshot(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_020_forecasting_agent_get_operations_snapshot', operation)

def protect_pep_scanner_scan_edge_021_validation_agent_persist_validated_schedule(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_021_validation_agent_persist_validated_schedule', operation)

def protect_pep_scanner_scan_edge_022_support_guidance_agent_get_support_playbooks(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_022_support_guidance_agent_get_support_playbooks', operation)

def protect_pep_scanner_scan_edge_024_recommender_agent_search_product_catalog(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_024_recommender_agent_search_product_catalog', operation)

def protect_pep_scanner_scan_edge_025_loan_agent_search_loan_playbooks(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_025_loan_agent_search_loan_playbooks', operation)
