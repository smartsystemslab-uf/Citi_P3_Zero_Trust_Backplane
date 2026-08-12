"""Generated PEP adapters. Regenerate rather than editing this file."""
from __future__ import annotations
import inspect
from typing import Any, Callable

from zt_pep.runtime import PEPEnforcer

class AgentRoutePEPMiddleware:
    def __init__(self, app: Any, enforcer: PEPEnforcer, placement_resolver: Callable[[Any], str | None]):
        self.app = app
        self.enforcer = enforcer
        self.placement_resolver = placement_resolver

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        placement_id = self.placement_resolver(scope)
        if placement_id:
            decision, _ = self.enforcer.authorize(placement_id, parameters={"route": scope.get("path")})
            if decision.get("decision") not in {"ALLOW", "ALLOW_WITH_OBLIGATIONS"}:
                raise PermissionError(f"agent route blocked by {placement_id}")
        await self.app(scope, receive, send)

def protect_pep_scanner_scan_edge_032_mid_office_router_representative_assistant_workflow(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_032_mid_office_router_representative_assistant_workflow', operation)

def protect_pep_scanner_scan_edge_033_mid_office_planning_parallel_validation_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_033_mid_office_planning_parallel_validation_agent', operation)

def protect_pep_scanner_scan_edge_034_mid_office_planning_parallel_support_guidance_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_034_mid_office_planning_parallel_support_guidance_agent', operation)

def protect_pep_scanner_scan_edge_035_mid_office_planning_workflow_data_analysis_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_035_mid_office_planning_workflow_data_analysis_agent', operation)

def protect_pep_scanner_scan_edge_036_mid_office_planning_workflow_forecasting_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_036_mid_office_planning_workflow_forecasting_agent', operation)

def protect_pep_scanner_scan_edge_037_mid_office_planning_workflow_staff_scheduling_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_037_mid_office_planning_workflow_staff_scheduling_agent', operation)

def protect_pep_scanner_scan_edge_038_mid_office_planning_workflow_planning_summary_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_038_mid_office_planning_workflow_planning_summary_agent', operation)

def protect_pep_scanner_scan_edge_039_representative_assist_parallel_financial_data_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_039_representative_assist_parallel_financial_data_agent', operation)

def protect_pep_scanner_scan_edge_040_representative_assist_parallel_recommender_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_040_representative_assist_parallel_recommender_agent', operation)

def protect_pep_scanner_scan_edge_041_representative_assist_parallel_loan_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_041_representative_assist_parallel_loan_agent', operation)

def protect_pep_scanner_scan_edge_042_representative_assist_parallel_risk_compliance_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_042_representative_assist_parallel_risk_compliance_agent', operation)
