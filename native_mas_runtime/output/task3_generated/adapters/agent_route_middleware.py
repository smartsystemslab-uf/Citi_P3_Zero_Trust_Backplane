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

def protect_pep_native_route_user_proxy_agent_back_office_router(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.native.route_user_proxy_agent_back_office_router', operation)

def protect_pep_native_route_user_proxy_agent_front_office_router(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.native.route_user_proxy_agent_front_office_router', operation)

def protect_pep_native_route_user_proxy_agent_mid_office_router(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.native.route_user_proxy_agent_mid_office_router', operation)

def protect_pep_scanner_scan_edge_064_back_office_eod_workflow_validation_checkpoint_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_064_back_office_eod_workflow_validation_checkpoint_agent', operation)

def protect_pep_scanner_scan_edge_065_back_office_eod_workflow_eod_processing_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_065_back_office_eod_workflow_eod_processing_agent', operation)

def protect_pep_scanner_scan_edge_066_back_office_eod_workflow_ledger_update_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_066_back_office_eod_workflow_ledger_update_agent', operation)

def protect_pep_scanner_scan_edge_067_back_office_eod_workflow_reconciliation_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_067_back_office_eod_workflow_reconciliation_agent', operation)

def protect_pep_scanner_scan_edge_068_back_office_eod_workflow_report_writing_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_068_back_office_eod_workflow_report_writing_agent', operation)

def protect_pep_scanner_scan_edge_069_back_office_eod_workflow_exception_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_069_back_office_eod_workflow_exception_agent', operation)

def protect_pep_scanner_scan_edge_070_back_office_router_back_office_eod_workflow(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_070_back_office_router_back_office_eod_workflow', operation)

def protect_pep_scanner_scan_edge_071_front_office_transaction_workflow_transaction_monitoring_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_071_front_office_transaction_workflow_transaction_monitoring_agent', operation)

def protect_pep_scanner_scan_edge_072_front_office_transaction_workflow_fraud_detection_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_072_front_office_transaction_workflow_fraud_detection_agent', operation)

def protect_pep_scanner_scan_edge_073_front_office_transaction_workflow_compliance_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_073_front_office_transaction_workflow_compliance_agent', operation)

def protect_pep_scanner_scan_edge_074_front_office_transaction_workflow_decision_making_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_074_front_office_transaction_workflow_decision_making_agent', operation)

def protect_pep_scanner_scan_edge_075_customer_service_chatbot_workflow_chatbot_intent_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_075_customer_service_chatbot_workflow_chatbot_intent_agent', operation)

def protect_pep_scanner_scan_edge_076_customer_service_chatbot_workflow_knowledge_base_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_076_customer_service_chatbot_workflow_knowledge_base_agent', operation)

def protect_pep_scanner_scan_edge_077_customer_service_chatbot_workflow_customer_service_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_077_customer_service_chatbot_workflow_customer_service_agent', operation)

def protect_pep_scanner_scan_edge_078_customer_service_chatbot_workflow_transaction_processing_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_078_customer_service_chatbot_workflow_transaction_processing_agent', operation)

def protect_pep_scanner_scan_edge_079_front_office_router_front_office_transaction_workflow(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_079_front_office_router_front_office_transaction_workflow', operation)

def protect_pep_scanner_scan_edge_080_front_office_router_customer_service_chatbot_workflow(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_080_front_office_router_customer_service_chatbot_workflow', operation)

def protect_pep_scanner_scan_edge_081_mid_office_router_mid_office_planning_workflow(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_081_mid_office_router_mid_office_planning_workflow', operation)

def protect_pep_scanner_scan_edge_082_mid_office_router_representative_assistant_workflow(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_082_mid_office_router_representative_assistant_workflow', operation)

def protect_pep_scanner_scan_edge_083_mid_office_planning_parallel_validation_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_083_mid_office_planning_parallel_validation_agent', operation)

def protect_pep_scanner_scan_edge_084_mid_office_planning_parallel_support_guidance_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_084_mid_office_planning_parallel_support_guidance_agent', operation)

def protect_pep_scanner_scan_edge_085_mid_office_planning_workflow_data_analysis_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_085_mid_office_planning_workflow_data_analysis_agent', operation)

def protect_pep_scanner_scan_edge_086_mid_office_planning_workflow_forecasting_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_086_mid_office_planning_workflow_forecasting_agent', operation)

def protect_pep_scanner_scan_edge_087_mid_office_planning_workflow_staff_scheduling_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_087_mid_office_planning_workflow_staff_scheduling_agent', operation)

def protect_pep_scanner_scan_edge_088_mid_office_planning_workflow_mid_office_planning_parallel(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_088_mid_office_planning_workflow_mid_office_planning_parallel', operation)

def protect_pep_scanner_scan_edge_089_mid_office_planning_workflow_planning_summary_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_089_mid_office_planning_workflow_planning_summary_agent', operation)

def protect_pep_scanner_scan_edge_090_representative_assist_parallel_financial_data_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_090_representative_assist_parallel_financial_data_agent', operation)

def protect_pep_scanner_scan_edge_091_representative_assist_parallel_recommender_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_091_representative_assist_parallel_recommender_agent', operation)

def protect_pep_scanner_scan_edge_092_representative_assist_parallel_loan_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_092_representative_assist_parallel_loan_agent', operation)

def protect_pep_scanner_scan_edge_093_representative_assist_parallel_risk_compliance_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_093_representative_assist_parallel_risk_compliance_agent', operation)

def protect_pep_scanner_scan_edge_094_representative_assistant_workflow_representative_assist_parallel(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_094_representative_assistant_workflow_representative_assist_parallel', operation)

def protect_pep_scanner_scan_edge_095_representative_assistant_workflow_representative_merge_agent(enforcer: PEPEnforcer, operation: Callable[..., Any]) -> Callable[..., Any]:
    return protect(enforcer, 'pep.scanner.scan_edge_095_representative_assistant_workflow_representative_merge_agent', operation)
