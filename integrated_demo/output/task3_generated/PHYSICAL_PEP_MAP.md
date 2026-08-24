# Logical-to-Physical PEP Map

## `physical_pep.agent_route_enforce_open_for_noncritical_boundary_agent_agent`
- Type: `agent_route`
- Generated adapter: `adapters/agent_route_middleware.py`
- Mode / failure: `enforce` / `open_for_noncritical`
- Logical placements:
  - `pep.scanner.scan_edge_064_back_office_eod_workflow_validation_checkpoint_agent`
  - `pep.scanner.scan_edge_065_back_office_eod_workflow_eod_processing_agent`
  - `pep.scanner.scan_edge_066_back_office_eod_workflow_ledger_update_agent`
  - `pep.scanner.scan_edge_067_back_office_eod_workflow_reconciliation_agent`
  - `pep.scanner.scan_edge_068_back_office_eod_workflow_report_writing_agent`
  - `pep.scanner.scan_edge_069_back_office_eod_workflow_exception_agent`
  - `pep.scanner.scan_edge_070_back_office_router_back_office_eod_workflow`
  - `pep.scanner.scan_edge_071_front_office_transaction_workflow_transaction_monitoring_agent`
  - `pep.scanner.scan_edge_072_front_office_transaction_workflow_fraud_detection_agent`
  - `pep.scanner.scan_edge_073_front_office_transaction_workflow_compliance_agent`
  - `pep.scanner.scan_edge_074_front_office_transaction_workflow_decision_making_agent`
  - `pep.scanner.scan_edge_075_customer_service_chatbot_workflow_chatbot_intent_agent`
  - `pep.scanner.scan_edge_076_customer_service_chatbot_workflow_knowledge_base_agent`
  - `pep.scanner.scan_edge_077_customer_service_chatbot_workflow_customer_service_agent`
  - `pep.scanner.scan_edge_078_customer_service_chatbot_workflow_transaction_processing_agent`
  - `pep.scanner.scan_edge_079_front_office_router_front_office_transaction_workflow`
  - `pep.scanner.scan_edge_080_front_office_router_customer_service_chatbot_workflow`
  - `pep.scanner.scan_edge_081_mid_office_router_mid_office_planning_workflow`
  - `pep.scanner.scan_edge_082_mid_office_router_representative_assistant_workflow`
  - `pep.scanner.scan_edge_083_mid_office_planning_parallel_validation_agent`
  - `pep.scanner.scan_edge_084_mid_office_planning_parallel_support_guidance_agent`
  - `pep.scanner.scan_edge_085_mid_office_planning_workflow_data_analysis_agent`
  - `pep.scanner.scan_edge_086_mid_office_planning_workflow_forecasting_agent`
  - `pep.scanner.scan_edge_087_mid_office_planning_workflow_staff_scheduling_agent`
  - `pep.scanner.scan_edge_088_mid_office_planning_workflow_mid_office_planning_parallel`
  - `pep.scanner.scan_edge_089_mid_office_planning_workflow_planning_summary_agent`
  - `pep.scanner.scan_edge_090_representative_assist_parallel_financial_data_agent`
  - `pep.scanner.scan_edge_091_representative_assist_parallel_recommender_agent`
  - `pep.scanner.scan_edge_092_representative_assist_parallel_loan_agent`
  - `pep.scanner.scan_edge_093_representative_assist_parallel_risk_compliance_agent`
  - `pep.scanner.scan_edge_094_representative_assistant_workflow_representative_assist_parallel`
  - `pep.scanner.scan_edge_095_representative_assistant_workflow_representative_merge_agent`

## `physical_pep.api_enforce_closed_shared_api_dependency`
- Type: `api`
- Generated adapter: `adapters/fastapi_dependencies.py`
- Mode / failure: `enforce` / `closed`
- Logical placements:
  - `pep.scanner.scan_edge_027_get_transaction_get_transaction`
  - `pep.scanner.scan_edge_028_run_fraud_and_compliance_workflow_monitoring_evaluate_transaction`
  - `pep.scanner.scan_edge_029_update_transaction_status_update_transaction_status`
  - `pep.scanner.scan_edge_032_get_customer_product_affinity_get_customer_product_affinity`
  - `pep.scanner.scan_edge_033_trigger_eod_reconciliation_trigger_eod_reconciliation`
  - `pep.scanner.scan_edge_035_resolve_ledger_entry_resolve_ledger_entry`

## `physical_pep.api_enforce_open_for_noncritical_shared_api_dependency`
- Type: `api`
- Generated adapter: `adapters/fastapi_dependencies.py`
- Mode / failure: `enforce` / `open_for_noncritical`
- Logical placements:
  - `pep.scanner.scan_edge_030_get_branch_workload_get_branch_workload`
  - `pep.scanner.scan_edge_031_propose_staffing_adjustment_propose_staffing_adjustment`
  - `pep.scanner.scan_edge_034_get_reconciliation_mismatches_get_reconciliation_mismatches`

## `physical_pep.data_enforce_closed_shared_data_access_guard`
- Type: `data`
- Generated adapter: `adapters/data_wrappers.py`
- Mode / failure: `enforce` / `closed`
- Logical placements:
  - `pep.scanner.scan_edge_036_create_customer_customers`
  - `pep.scanner.scan_edge_037_create_customer_customers`
  - `pep.scanner.scan_edge_038_get_customer_customers`
  - `pep.scanner.scan_edge_039_list_customer_accounts_accounts`
  - `pep.scanner.scan_edge_040_get_customer_context_customers`
  - `pep.scanner.scan_edge_041_list_customer_transactions_accounts`
  - `pep.scanner.scan_edge_042_list_customer_transactions_transactions`
  - `pep.scanner.scan_edge_043_create_account_customers`
  - `pep.scanner.scan_edge_044_create_account_accounts`
  - `pep.scanner.scan_edge_045_create_account_accounts`
  - `pep.scanner.scan_edge_046_get_account_accounts`
  - `pep.scanner.scan_edge_047_get_transaction_transactions`
  - `pep.scanner.scan_edge_048_list_transactions_transactions`
  - `pep.scanner.scan_edge_050_create_policy_policies`
  - `pep.scanner.scan_edge_054_create_rule_rules`
  - `pep.scanner.scan_edge_056_update_transaction_status_transactions`
  - `pep.scanner.scan_edge_057_get_customer_product_affinity_customers`
  - `pep.scanner.scan_edge_058_get_customer_product_affinity_accounts`
  - `pep.scanner.scan_edge_059_trigger_eod_reconciliation_transactions`
  - `pep.scanner.scan_edge_060_trigger_eod_reconciliation_audit_logs`
  - `pep.scanner.scan_edge_061_get_reconciliation_mismatches_audit_logs`
  - `pep.scanner.scan_edge_062_resolve_ledger_entry_transactions`
  - `pep.scanner.scan_edge_063_resolve_ledger_entry_audit_logs`

## `physical_pep.data_enforce_open_for_noncritical_shared_data_access_guard`
- Type: `data`
- Generated adapter: `adapters/data_wrappers.py`
- Mode / failure: `enforce` / `open_for_noncritical`
- Logical placements:
  - `pep.scanner.scan_edge_049_create_policy_policies`
  - `pep.scanner.scan_edge_051_list_policies_policies`
  - `pep.scanner.scan_edge_052_search_policies_policies`
  - `pep.scanner.scan_edge_053_create_rule_rules`
  - `pep.scanner.scan_edge_055_list_rules_rules`

## `physical_pep.mcp_enforce_closed_shared_mcp_gateway`
- Type: `mcp`
- Generated adapter: `adapters/mcp_wrappers.py`
- Mode / failure: `enforce` / `closed`
- Logical placements:
  - `pep.customer_transaction.execute_transfer`
  - `pep.ledger_update.apply_ledger_updates`
  - `pep.scanner.scan_edge_005_report_writing_agent_store_report`
  - `pep.scanner.scan_edge_006_exception_agent_create_exception_case`
  - `pep.scanner.scan_edge_007_transaction_monitoring_agent_get_customer_context`
  - `pep.scanner.scan_edge_010_fraud_detection_agent_get_customer_context`
  - `pep.scanner.scan_edge_014_compliance_agent_get_customer_context`

## `physical_pep.mcp_enforce_open_for_noncritical_shared_mcp_gateway`
- Type: `mcp`
- Generated adapter: `adapters/mcp_wrappers.py`
- Mode / failure: `enforce` / `open_for_noncritical`
- Logical placements:
  - `pep.eod_processing.get_batches`
  - `pep.fraud_review.policy_search`
  - `pep.scanner.scan_edge_026_risk_compliance_agent_search_policies`

## `physical_pep.tool_enforce_closed_python_function`
- Type: `tool`
- Generated adapter: `adapters/tool_wrappers.py`
- Mode / failure: `enforce` / `closed`
- Logical placements:
  - `pep.fraud_review.read_history`
  - `pep.mid_office.financial_data.read_profile`
  - `pep.scanner.scan_edge_008_transaction_monitoring_agent_get_transaction_context`
  - `pep.scanner.scan_edge_009_transaction_monitoring_agent_list_recent_transactions`
  - `pep.scanner.scan_edge_012_fraud_detection_agent_list_recent_transactions`
  - `pep.scanner.scan_edge_015_compliance_agent_get_transaction_context`
  - `pep.scanner.scan_edge_016_decision_making_agent_submit_manual_review`
  - `pep.scanner.scan_edge_021_validation_agent_persist_validated_schedule`

## `physical_pep.tool_enforce_open_for_noncritical_python_function`
- Type: `tool`
- Generated adapter: `adapters/tool_wrappers.py`
- Mode / failure: `enforce` / `open_for_noncritical`
- Logical placements:
  - `pep.mid_office.operations.read_snapshot`
  - `pep.scanner.scan_edge_001_validation_checkpoint_agent_validate_eod_readiness`
  - `pep.scanner.scan_edge_004_reconciliation_agent_get_reconciliation_data`
  - `pep.scanner.scan_edge_017_knowledge_base_agent_search_faqs`
  - `pep.scanner.scan_edge_020_forecasting_agent_get_operations_snapshot`
  - `pep.scanner.scan_edge_022_support_guidance_agent_get_support_playbooks`
  - `pep.scanner.scan_edge_024_recommender_agent_search_product_catalog`
  - `pep.scanner.scan_edge_025_loan_agent_search_loan_playbooks`
