# Task 4 PDP policy set (PSL)

Generated from back_office.psl, core.psl, front_office.psl, ledger_access.psl, mid_office.psl, tool_access.psl + field catalogue `policy_fields.yaml` (source sha256 `696e226a6293fbf6`). Do not edit.

| rule | kind | scope | on violation | runtimes | file:line |
|---|---|---|---|---|---|
| `policy.back_office.report_read_reconciliation` | permit | pdp_request | -- | pdp | back_office.psl:13 |
| `policy.back_office.eod_read_batches` | permit | pdp_request | -- | pdp | back_office.psl:30 |
| `policy.back_office.report_deny_ledger_update` | constraint | pdp_request | DENY | pdp | back_office.psl:21 |
| `core.critical_write_requires_dual_approval` | constraint | pdp_request | MANUAL_REVIEW | pdp | core.psl:17 |
| `policy.front_office.fraud_read_transaction_history` | permit | pdp_request | -- | pdp | front_office.psl:16 |
| `policy.front_office.customer_profile_read` | permit | pdp_request | -- | pdp | front_office.psl:40 |
| `policy.front_office.fraud_deny_transfer` | constraint | pdp_request | DENY | pdp | front_office.psl:25 |
| `policy.front_office.customer_profile_reauthenticate` | constraint | pdp_request | REAUTHENTICATE | pdp | front_office.psl:48 |
| `policy.ledger.eod_approved_update` | permit | pdp_request | -- | pdp | ledger_access.psl:27 |
| `policy.ledger.report_deny_update` | constraint | pdp_request | DENY | pdp | ledger_access.psl:11 |
| `policy.ledger.eod_pending_review` | constraint | pdp_request | MANUAL_REVIEW | pdp | ledger_access.psl:36 |
| `policy.mid_office.operations_read` | permit | pdp_request | -- | pdp | mid_office.psl:12 |
| `policy.mid_office.financial_data_read` | permit | pdp_request | -- | pdp | mid_office.psl:22 |
| `policy.mid_office.support_guidance_business_hours` | permit | pdp_request | -- | pdp | mid_office.psl:32 |
| `policy.tool.knowledge_search` | permit | pdp_request | -- | pdp | tool_access.psl:12 |
| `policy.tool.transfer_approved` | permit | pdp_request | -- | pdp | tool_access.psl:27 |
| `policy.tool.transfer_pending_review` | constraint | pdp_request | MANUAL_REVIEW | pdp | tool_access.psl:36 |
| `R_default_deny` | default_deny | pdp_request | DENY | pdp | <generated>:0 |

## `policy.back_office.report_read_reconciliation` (permit)

> Report agent may read reconciliation results in the verified EOD workflow.

```psl
subject.id == "agent.back_office.report" && resource.id == "resource.back_office.reconciliation_results" && action == "read" && workflow.id == "workflow.back_office.eod_processing"
```

obligations: {"parameters": {"reason": "reconciliation_report_access"}, "type": "enhanced_logging"}
atomic propositions: `action == "read"`, `resource.id == "resource.back_office.reconciliation_results"`, `subject.id == "agent.back_office.report"`, `workflow.id == "workflow.back_office.eod_processing"`

## `policy.back_office.eod_read_batches` (permit)

> EOD agent may read EOD batches in the verified EOD workflow.

```psl
subject.id == "agent.back_office.eod" && resource.id == "resource.back_office.eod_batches" && action == "read" && workflow.id == "workflow.back_office.eod_processing"
```

obligations: {"parameters": {"reason": "eod_batch_access"}, "type": "enhanced_logging"}
atomic propositions: `action == "read"`, `resource.id == "resource.back_office.eod_batches"`, `subject.id == "agent.back_office.eod"`, `workflow.id == "workflow.back_office.eod_processing"`

## `policy.back_office.report_deny_ledger_update` (constraint)

> Report agent must never modify the ledger.

```psl
never (authz_request && subject.id == "agent.back_office.report" && resource.id == "resource.back_office.ledger" && action == "update")
```

atomic propositions: `action == "update"`, `authz_request`, `resource.id == "resource.back_office.ledger"`, `subject.id == "agent.back_office.report"`

## `core.critical_write_requires_dual_approval` (constraint)

> A write to a critical resource requires a signed human approval and an independent secondary authorization, both bound to the request hash.

```psl
always (authz_request && resource.critical && critical_write_action -> approval.valid && approval.secondary_valid)
```

atomic propositions: `action == "approve"`, `action == "cancel"`, `action == "create"`, `action == "execute"`, `action == "reject"`, `action == "store"`, `action == "submit"`, `action == "update"`, `approval.secondary_valid`, `approval.valid`, `authz_request`, `resource.critical`

## `policy.front_office.fraud_read_transaction_history` (permit)

> Fraud agent may read transaction history only in the verified fraud-review workflow.

```psl
subject.id == "agent.front_office.fraud" && resource.id == "resource.front_office.transaction_history" && action == "read" && workflow.id == "workflow.front_office.fraud_review" && (risk.level == "low" || risk.level == "medium" || risk.level == "high")
```

obligations: {"parameters": {"reason": "fraud_data_access"}, "type": "enhanced_logging"}, {"parameters": {"fields": ["full_account_number", "ssn"]}, "type": "data_masking"}
atomic propositions: `action == "read"`, `resource.id == "resource.front_office.transaction_history"`, `risk.level == "high"`, `risk.level == "low"`, `risk.level == "medium"`, `subject.id == "agent.front_office.fraud"`, `workflow.id == "workflow.front_office.fraud_review"`

## `policy.front_office.customer_profile_read` (permit)

> Strongly authenticated customer-service agent may read masked customer profile data.

```psl
subject.id == "agent.front_office.customer_service" && resource.id == "resource.front_office.customer_profile" && action == "read"
```

obligations: {"parameters": {"fields": ["ssn", "full_account_number"]}, "type": "data_masking"}, {"parameters": {"reason": "restricted_customer_profile"}, "type": "enhanced_logging"}
atomic propositions: `action == "read"`, `resource.id == "resource.front_office.customer_profile"`, `subject.id == "agent.front_office.customer_service"`

## `policy.front_office.fraud_deny_transfer` (constraint)

> Fraud-analysis agents must never execute banking transfers.

```psl
never (authz_request && subject.id == "agent.front_office.fraud" && resource.id == "resource.front_office.banking_transfer" && (action == "execute" || action == "cancel"))
```

atomic propositions: `action == "cancel"`, `action == "execute"`, `authz_request`, `resource.id == "resource.front_office.banking_transfer"`, `subject.id == "agent.front_office.fraud"`

## `policy.front_office.customer_profile_reauthenticate` (constraint)

> Weakly authenticated customer-service access requires step-up authentication.

```psl
never (authz_request && subject.id == "agent.front_office.customer_service" && resource.id == "resource.front_office.customer_profile" && action == "read" && auth.strength <= 1)
```

atomic propositions: `action == "read"`, `auth.strength <= 1`, `authz_request`, `resource.id == "resource.front_office.customer_profile"`, `subject.id == "agent.front_office.customer_service"`

## `policy.ledger.eod_approved_update` (permit)

> EOD ledger update may proceed only with signed human approval and independent authorization bound to the request hash.

```psl
subject.id == "agent.back_office.eod" && resource.id == "resource.back_office.ledger" && action == "update" && workflow.id == "workflow.back_office.eod_processing"
```

obligations: {"parameters": {"reason": "critical_ledger_write"}, "type": "enhanced_logging"}, {"parameters": {}, "type": "require_idempotency_key"}, {"parameters": {}, "type": "require_change_ticket"}, {"parameters": {}, "type": "independent_resource_audit"}
atomic propositions: `action == "update"`, `resource.id == "resource.back_office.ledger"`, `subject.id == "agent.back_office.eod"`, `workflow.id == "workflow.back_office.eod_processing"`

## `policy.ledger.report_deny_update` (constraint)

> Explicitly deny report-agent ledger writes.

```psl
never (authz_request && subject.id == "agent.back_office.report" && resource.id == "resource.back_office.ledger" && action == "update")
```

atomic propositions: `action == "update"`, `authz_request`, `resource.id == "resource.back_office.ledger"`, `subject.id == "agent.back_office.report"`

## `policy.ledger.eod_pending_review` (constraint)

> EOD ledger update remains blocked until signed approval and an independent authorization are present.

```psl
always (authz_request && subject.id == "agent.back_office.eod" && resource.id == "resource.back_office.ledger" && action == "update" && workflow.id == "workflow.back_office.eod_processing" -> approval.valid && approval.secondary_valid)
```

atomic propositions: `action == "update"`, `approval.secondary_valid`, `approval.valid`, `authz_request`, `resource.id == "resource.back_office.ledger"`, `subject.id == "agent.back_office.eod"`, `workflow.id == "workflow.back_office.eod_processing"`

## `policy.mid_office.operations_read` (permit)

> Data-analysis role may read internal operations data.

```psl
subject.role.operations_analyst && resource.id == "resource.mid_office.internal_operations_data" && action == "read"
```

atomic propositions: `action == "read"`, `resource.id == "resource.mid_office.internal_operations_data"`, `subject.role.operations_analyst`

## `policy.mid_office.financial_data_read` (permit)

> Financial-data agent may read masked financial data with verified stronger authentication.

```psl
subject.id == "agent.mid_office.financial_data" && resource.id == "resource.mid_office.financial_customer_data" && action == "read" && auth.strength >= 2 && (risk.level == "low" || risk.level == "medium")
```

obligations: {"parameters": {"fields": ["full_account_number", "ssn"]}, "type": "data_masking"}, {"parameters": {"reason": "financial_customer_data"}, "type": "enhanced_logging"}
atomic propositions: `action == "read"`, `auth.strength >= 2`, `resource.id == "resource.mid_office.financial_customer_data"`, `risk.level == "low"`, `risk.level == "medium"`, `subject.id == "agent.mid_office.financial_data"`

## `policy.mid_office.support_guidance_business_hours` (permit)

> Support-guidance agent may read operations data only during server-verified weekday business hours.

```psl
subject.id == "agent.mid_office.support_guidance" && resource.id == "resource.mid_office.internal_operations_data" && action == "read" && time.in.business_hours_new_york
```

atomic propositions: `action == "read"`, `resource.id == "resource.mid_office.internal_operations_data"`, `subject.id == "agent.mid_office.support_guidance"`, `time.in.business_hours_new_york`

## `policy.tool.knowledge_search` (permit)

> Knowledge and compliance agents may search managed policy content.

```psl
(subject.id == "agent.front_office.knowledge_base" || subject.id == "agent.front_office.compliance") && resource.id == "resource.front_office.policy_knowledge_base" && (action == "read" || action == "search")
```

atomic propositions: `action == "read"`, `action == "search"`, `resource.id == "resource.front_office.policy_knowledge_base"`, `subject.id == "agent.front_office.compliance"`, `subject.id == "agent.front_office.knowledge_base"`

## `policy.tool.transfer_approved` (permit)

> A transfer may proceed only when approval and secondary authorization are signed and request-bound.

```psl
subject.id == "agent.front_office.transaction_processing" && resource.id == "resource.front_office.banking_transfer" && action == "execute" && workflow.id == "workflow.front_office.customer_transaction"
```

obligations: {"parameters": {"reason": "financial_write"}, "type": "enhanced_logging"}, {"parameters": {}, "type": "require_idempotency_key"}, {"parameters": {}, "type": "independent_resource_audit"}
atomic propositions: `action == "execute"`, `resource.id == "resource.front_office.banking_transfer"`, `subject.id == "agent.front_office.transaction_processing"`, `workflow.id == "workflow.front_office.customer_transaction"`

## `policy.tool.transfer_pending_review` (constraint)

> Transfer execution is blocked until signed approval and independent authorization are present.

```psl
always (authz_request && subject.id == "agent.front_office.transaction_processing" && resource.id == "resource.front_office.banking_transfer" && action == "execute" && workflow.id == "workflow.front_office.customer_transaction" -> approval.valid && approval.secondary_valid)
```

atomic propositions: `action == "execute"`, `approval.secondary_valid`, `approval.valid`, `authz_request`, `resource.id == "resource.front_office.banking_transfer"`, `subject.id == "agent.front_office.transaction_processing"`, `workflow.id == "workflow.front_office.customer_transaction"`

## `R_default_deny` (default_deny)

> Deny unless at least one permission holds (default deny).

```psl
always (authz_request -> (report_read_reconciliation || eod_read_batches || fraud_read_transaction_history || customer_profile_read || eod_approved_update || operations_read || financial_data_read || support_guidance_business_hours || knowledge_search || transfer_approved))
```

atomic propositions: `action == "execute"`, `action == "read"`, `action == "search"`, `action == "update"`, `auth.strength >= 2`, `authz_request`, `resource.id == "resource.back_office.eod_batches"`, `resource.id == "resource.back_office.ledger"`, `resource.id == "resource.back_office.reconciliation_results"`, `resource.id == "resource.front_office.banking_transfer"`, `resource.id == "resource.front_office.customer_profile"`, `resource.id == "resource.front_office.policy_knowledge_base"`, `resource.id == "resource.front_office.transaction_history"`, `resource.id == "resource.mid_office.financial_customer_data"`, `resource.id == "resource.mid_office.internal_operations_data"`, `risk.level == "high"`, `risk.level == "low"`, `risk.level == "medium"`, `subject.id == "agent.back_office.eod"`, `subject.id == "agent.back_office.report"`, `subject.id == "agent.front_office.compliance"`, `subject.id == "agent.front_office.customer_service"`, `subject.id == "agent.front_office.fraud"`, `subject.id == "agent.front_office.knowledge_base"`, `subject.id == "agent.front_office.transaction_processing"`, `subject.id == "agent.mid_office.financial_data"`, `subject.id == "agent.mid_office.support_guidance"`, `subject.role.operations_analyst`, `time.in.business_hours_new_york`, `workflow.id == "workflow.back_office.eod_processing"`, `workflow.id == "workflow.front_office.customer_transaction"`, `workflow.id == "workflow.front_office.fraud_review"`
