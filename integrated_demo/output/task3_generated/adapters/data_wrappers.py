"""Generated PEP adapters. Regenerate rather than editing this file."""
from __future__ import annotations
import inspect
from typing import Any, Callable

from zt_pep.runtime import PEPEnforcer

def protect(enforcer: PEPEnforcer, placement_id: str, operation: Callable[..., Any]) -> Callable[..., Any]:
    return enforcer.wrap_async(placement_id, operation) if inspect.iscoroutinefunction(operation) else enforcer.wrap_sync(placement_id, operation)

def protect_pep_scanner_scan_edge_036_create_customer_customers(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_036_create_customer_customers', operation)

def protect_pep_scanner_scan_edge_037_create_customer_customers(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_037_create_customer_customers', operation)

def protect_pep_scanner_scan_edge_038_get_customer_customers(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_038_get_customer_customers', operation)

def protect_pep_scanner_scan_edge_039_list_customer_accounts_accounts(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_039_list_customer_accounts_accounts', operation)

def protect_pep_scanner_scan_edge_040_get_customer_context_customers(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_040_get_customer_context_customers', operation)

def protect_pep_scanner_scan_edge_041_list_customer_transactions_accounts(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_041_list_customer_transactions_accounts', operation)

def protect_pep_scanner_scan_edge_042_list_customer_transactions_transactions(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_042_list_customer_transactions_transactions', operation)

def protect_pep_scanner_scan_edge_043_create_account_customers(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_043_create_account_customers', operation)

def protect_pep_scanner_scan_edge_044_create_account_accounts(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_044_create_account_accounts', operation)

def protect_pep_scanner_scan_edge_045_create_account_accounts(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_045_create_account_accounts', operation)

def protect_pep_scanner_scan_edge_046_get_account_accounts(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_046_get_account_accounts', operation)

def protect_pep_scanner_scan_edge_047_get_transaction_transactions(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_047_get_transaction_transactions', operation)

def protect_pep_scanner_scan_edge_048_list_transactions_transactions(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_048_list_transactions_transactions', operation)

def protect_pep_scanner_scan_edge_049_create_policy_policies(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_049_create_policy_policies', operation)

def protect_pep_scanner_scan_edge_050_create_policy_policies(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_050_create_policy_policies', operation)

def protect_pep_scanner_scan_edge_051_list_policies_policies(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_051_list_policies_policies', operation)

def protect_pep_scanner_scan_edge_052_search_policies_policies(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_052_search_policies_policies', operation)

def protect_pep_scanner_scan_edge_053_create_rule_rules(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_053_create_rule_rules', operation)

def protect_pep_scanner_scan_edge_054_create_rule_rules(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_054_create_rule_rules', operation)

def protect_pep_scanner_scan_edge_055_list_rules_rules(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_055_list_rules_rules', operation)

def protect_pep_scanner_scan_edge_056_update_transaction_status_transactions(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_056_update_transaction_status_transactions', operation)

def protect_pep_scanner_scan_edge_057_get_customer_product_affinity_customers(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_057_get_customer_product_affinity_customers', operation)

def protect_pep_scanner_scan_edge_058_get_customer_product_affinity_accounts(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_058_get_customer_product_affinity_accounts', operation)

def protect_pep_scanner_scan_edge_059_trigger_eod_reconciliation_transactions(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_059_trigger_eod_reconciliation_transactions', operation)

def protect_pep_scanner_scan_edge_060_trigger_eod_reconciliation_audit_logs(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_060_trigger_eod_reconciliation_audit_logs', operation)

def protect_pep_scanner_scan_edge_061_get_reconciliation_mismatches_audit_logs(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_061_get_reconciliation_mismatches_audit_logs', operation)

def protect_pep_scanner_scan_edge_062_resolve_ledger_entry_transactions(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_062_resolve_ledger_entry_transactions', operation)

def protect_pep_scanner_scan_edge_063_resolve_ledger_entry_audit_logs(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_063_resolve_ledger_entry_audit_logs', operation)
