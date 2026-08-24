"""Generated PEP adapters. Regenerate rather than editing this file."""
from __future__ import annotations
import inspect
from typing import Any, Callable

from zt_pep.runtime import PEPEnforcer

try:
    from fastapi import HTTPException, Request
except ImportError:  # FastAPI is optional until this adapter is used.
    HTTPException = RuntimeError
    Request = Any


def make_fastapi_dependency(enforcer: PEPEnforcer, placement_id: str):
    async def dependency(request: Request) -> dict[str, Any]:
        try:
            parameters = dict(getattr(request, "path_params", {}) or {})
            query = getattr(request, "query_params", None)
            if query is not None:
                parameters.update(dict(query))
            decision, _ = enforcer.authorize(placement_id, parameters=parameters)
            if decision.get("decision") not in {"ALLOW", "ALLOW_WITH_OBLIGATIONS"}:
                raise HTTPException(status_code=403, detail=decision.get("reason", "denied"))
            return decision
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"PEP fail-closed: {exc}") from exc
    return dependency

def protect_pep_scanner_scan_edge_027_get_transaction_get_transaction(enforcer: PEPEnforcer):
    return make_fastapi_dependency(enforcer, 'pep.scanner.scan_edge_027_get_transaction_get_transaction')

def protect_pep_scanner_scan_edge_028_run_fraud_and_compliance_workflow_monitoring_evaluate_transaction(enforcer: PEPEnforcer):
    return make_fastapi_dependency(enforcer, 'pep.scanner.scan_edge_028_run_fraud_and_compliance_workflow_monitoring_evaluate_transaction')

def protect_pep_scanner_scan_edge_029_update_transaction_status_update_transaction_status(enforcer: PEPEnforcer):
    return make_fastapi_dependency(enforcer, 'pep.scanner.scan_edge_029_update_transaction_status_update_transaction_status')

def protect_pep_scanner_scan_edge_030_get_branch_workload_get_branch_workload(enforcer: PEPEnforcer):
    return make_fastapi_dependency(enforcer, 'pep.scanner.scan_edge_030_get_branch_workload_get_branch_workload')

def protect_pep_scanner_scan_edge_031_propose_staffing_adjustment_propose_staffing_adjustment(enforcer: PEPEnforcer):
    return make_fastapi_dependency(enforcer, 'pep.scanner.scan_edge_031_propose_staffing_adjustment_propose_staffing_adjustment')

def protect_pep_scanner_scan_edge_032_get_customer_product_affinity_get_customer_product_affinity(enforcer: PEPEnforcer):
    return make_fastapi_dependency(enforcer, 'pep.scanner.scan_edge_032_get_customer_product_affinity_get_customer_product_affinity')

def protect_pep_scanner_scan_edge_033_trigger_eod_reconciliation_trigger_eod_reconciliation(enforcer: PEPEnforcer):
    return make_fastapi_dependency(enforcer, 'pep.scanner.scan_edge_033_trigger_eod_reconciliation_trigger_eod_reconciliation')

def protect_pep_scanner_scan_edge_034_get_reconciliation_mismatches_get_reconciliation_mismatches(enforcer: PEPEnforcer):
    return make_fastapi_dependency(enforcer, 'pep.scanner.scan_edge_034_get_reconciliation_mismatches_get_reconciliation_mismatches')

def protect_pep_scanner_scan_edge_035_resolve_ledger_entry_resolve_ledger_entry(enforcer: PEPEnforcer):
    return make_fastapi_dependency(enforcer, 'pep.scanner.scan_edge_035_resolve_ledger_entry_resolve_ledger_entry')
