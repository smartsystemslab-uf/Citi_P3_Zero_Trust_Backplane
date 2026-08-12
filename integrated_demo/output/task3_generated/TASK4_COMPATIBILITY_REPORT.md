# Task 3 / Task 4 Compatibility Report

- Task 4 package: `task4_compatibility_view`
- Interface schemas match: **True**
- All generated requests resolve in Task 4 registries: **True**
- Overall compatible: **True**

## Policy coverage note

Registry compatibility does not imply every interaction is allowed. Task 4 remains default-deny.
Known generated edges without a candidate explicit policy: **36**.
These edges will return DENY until Task 4 policy bundles are extended.

- `edge.scanner.scan_edge_003_ledger_update_agent_apply_ledger_updates` → default DENY
- `edge.scanner.scan_edge_001_validation_checkpoint_agent_validate_eod_readiness` → default DENY
- `edge.scanner.scan_edge_004_reconciliation_agent_get_reconciliation_data` → default DENY
- `edge.scanner.scan_edge_005_report_writing_agent_store_report` → default DENY
- `edge.scanner.scan_edge_006_exception_agent_create_exception_case` → default DENY
- `edge.scanner.scan_edge_007_transaction_monitoring_agent_get_customer_context` → default DENY
- `edge.scanner.scan_edge_008_transaction_monitoring_agent_get_transaction_context` → default DENY
- `edge.scanner.scan_edge_009_transaction_monitoring_agent_list_recent_transactions` → default DENY
- `edge.scanner.scan_edge_010_fraud_detection_agent_get_customer_context` → default DENY
- `edge.scanner.scan_edge_012_fraud_detection_agent_list_recent_transactions` → default DENY
- `edge.scanner.scan_edge_014_compliance_agent_get_customer_context` → default DENY
- `edge.scanner.scan_edge_015_compliance_agent_get_transaction_context` → default DENY
- `edge.scanner.scan_edge_016_decision_making_agent_submit_manual_review` → default DENY
- `edge.scanner.scan_edge_017_knowledge_base_agent_search_faqs` → default DENY
- `edge.scanner.scan_edge_020_forecasting_agent_get_operations_snapshot` → default DENY
- `edge.scanner.scan_edge_021_validation_agent_persist_validated_schedule` → default DENY
- `edge.scanner.scan_edge_022_support_guidance_agent_get_support_playbooks` → default DENY
- `edge.scanner.scan_edge_024_recommender_agent_search_product_catalog` → default DENY
- `edge.scanner.scan_edge_025_loan_agent_search_loan_playbooks` → default DENY
- `edge.scanner.scan_edge_026_risk_compliance_agent_search_policies` → default DENY
- `edge.scanner.scan_edge_027_create_customer_unknown` → default DENY
- `edge.scanner.scan_edge_028_create_account_unknown` → default DENY
- `edge.scanner.scan_edge_029_create_policy_unknown` → default DENY
- `edge.scanner.scan_edge_030_create_rule_unknown` → default DENY
- `edge.scanner.scan_edge_031_update_transaction_status_unknown` → default DENY
- `edge.scanner.scan_edge_032_mid_office_router_representative_assistant_workflow` → default DENY
- `edge.scanner.scan_edge_033_mid_office_planning_parallel_validation_agent` → default DENY
- `edge.scanner.scan_edge_034_mid_office_planning_parallel_support_guidance_agent` → default DENY
- `edge.scanner.scan_edge_035_mid_office_planning_workflow_data_analysis_agent` → default DENY
- `edge.scanner.scan_edge_036_mid_office_planning_workflow_forecasting_agent` → default DENY
- `edge.scanner.scan_edge_037_mid_office_planning_workflow_staff_scheduling_agent` → default DENY
- `edge.scanner.scan_edge_038_mid_office_planning_workflow_planning_summary_agent` → default DENY
- `edge.scanner.scan_edge_039_representative_assist_parallel_financial_data_agent` → default DENY
- `edge.scanner.scan_edge_040_representative_assist_parallel_recommender_agent` → default DENY
- `edge.scanner.scan_edge_041_representative_assist_parallel_loan_agent` → default DENY
- `edge.scanner.scan_edge_042_representative_assist_parallel_risk_compliance_agent` → default DENY
