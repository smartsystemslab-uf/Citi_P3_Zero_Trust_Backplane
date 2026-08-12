# Logical-to-Physical PEP Map

## `physical_pep.agent_route_enforce_closed_boundary_agent_agent`
- Type: `agent_route`
- Generated adapter: `adapters/agent_route_middleware.py`
- Mode / failure: `enforce` / `closed`
- Logical placements:
  - `pep.scanner.scan_edge_032_mid_office_router_representative_assistant_workflow`
  - `pep.scanner.scan_edge_033_mid_office_planning_parallel_validation_agent`
  - `pep.scanner.scan_edge_034_mid_office_planning_parallel_support_guidance_agent`
  - `pep.scanner.scan_edge_035_mid_office_planning_workflow_data_analysis_agent`
  - `pep.scanner.scan_edge_036_mid_office_planning_workflow_forecasting_agent`
  - `pep.scanner.scan_edge_037_mid_office_planning_workflow_staff_scheduling_agent`
  - `pep.scanner.scan_edge_038_mid_office_planning_workflow_planning_summary_agent`
  - `pep.scanner.scan_edge_039_representative_assist_parallel_financial_data_agent`
  - `pep.scanner.scan_edge_040_representative_assist_parallel_recommender_agent`
  - `pep.scanner.scan_edge_041_representative_assist_parallel_loan_agent`
  - `pep.scanner.scan_edge_042_representative_assist_parallel_risk_compliance_agent`

## `physical_pep.data_enforce_closed_shared_data_access_guard`
- Type: `data`
- Generated adapter: `adapters/data_wrappers.py`
- Mode / failure: `enforce` / `closed`
- Logical placements:
  - `pep.scanner.scan_edge_027_create_customer_unknown`
  - `pep.scanner.scan_edge_028_create_account_unknown`
  - `pep.scanner.scan_edge_029_create_policy_unknown`
  - `pep.scanner.scan_edge_030_create_rule_unknown`
  - `pep.scanner.scan_edge_031_update_transaction_status_unknown`

## `physical_pep.mcp_enforce_closed_shared_mcp_gateway`
- Type: `mcp`
- Generated adapter: `adapters/mcp_wrappers.py`
- Mode / failure: `enforce` / `closed`
- Logical placements:
  - `pep.customer_transaction.execute_transfer`
  - `pep.eod_processing.get_batches`
  - `pep.fraud_review.policy_search`
  - `pep.ledger_update.apply_ledger_updates`
  - `pep.scanner.scan_edge_005_report_writing_agent_store_report`
  - `pep.scanner.scan_edge_006_exception_agent_create_exception_case`
  - `pep.scanner.scan_edge_007_transaction_monitoring_agent_get_customer_context`
  - `pep.scanner.scan_edge_010_fraud_detection_agent_get_customer_context`
  - `pep.scanner.scan_edge_014_compliance_agent_get_customer_context`
  - `pep.scanner.scan_edge_026_risk_compliance_agent_search_policies`

## `physical_pep.tool_enforce_closed_python_function`
- Type: `tool`
- Generated adapter: `adapters/tool_wrappers.py`
- Mode / failure: `enforce` / `closed`
- Logical placements:
  - `pep.fraud_review.read_history`
  - `pep.mid_office.financial_data.read_profile`
  - `pep.mid_office.operations.read_snapshot`
  - `pep.scanner.scan_edge_001_validation_checkpoint_agent_validate_eod_readiness`
  - `pep.scanner.scan_edge_004_reconciliation_agent_get_reconciliation_data`
  - `pep.scanner.scan_edge_008_transaction_monitoring_agent_get_transaction_context`
  - `pep.scanner.scan_edge_009_transaction_monitoring_agent_list_recent_transactions`
  - `pep.scanner.scan_edge_012_fraud_detection_agent_list_recent_transactions`
  - `pep.scanner.scan_edge_015_compliance_agent_get_transaction_context`
  - `pep.scanner.scan_edge_016_decision_making_agent_submit_manual_review`
  - `pep.scanner.scan_edge_017_knowledge_base_agent_search_faqs`
  - `pep.scanner.scan_edge_020_forecasting_agent_get_operations_snapshot`
  - `pep.scanner.scan_edge_021_validation_agent_persist_validated_schedule`
  - `pep.scanner.scan_edge_022_support_guidance_agent_get_support_playbooks`
  - `pep.scanner.scan_edge_024_recommender_agent_search_product_catalog`
  - `pep.scanner.scan_edge_025_loan_agent_search_loan_playbooks`
