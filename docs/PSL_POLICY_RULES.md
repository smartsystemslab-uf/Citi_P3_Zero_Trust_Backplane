# PDP policy set (PSL)

Generated from back_office.psl, core.psl, front_office.psl, gateway_runtime.psl, identity.psl, intent.psl, ledger_access.psl, mid_office.psl, tool_access.psl + field catalogue `policy_fields.yaml` (source sha256 `e6a072169fb10d7e`). Do not edit.

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
| `gateway.P1_identity` | temporal | request_attempt | DENY | gateway | gateway_runtime.psl:19 |
| `gateway.P1_authorization` | temporal | request_attempt | DENY | gateway | gateway_runtime.psl:23 |
| `gateway.P1_permit` | temporal | request_attempt | DENY | gateway | gateway_runtime.psl:27 |
| `gateway.P1_binding` | temporal | request_attempt | DENY | gateway | gateway_runtime.psl:31 |
| `gateway.P1_admission` | temporal | request_attempt | DENY | gateway | gateway_runtime.psl:35 |
| `gateway.P2_request` | temporal | request_attempt | DENY | gateway | gateway_runtime.psl:39 |
| `gateway.P5_live` | temporal | request_attempt | DENY | gateway | gateway_runtime.psl:45 |
| `gateway.P6_pre_audit` | temporal | request_attempt | DENY | gateway | gateway_runtime.psl:49 |
| `gateway.P6_post_audit` | temporal | request_attempt | DENY | gateway | gateway_runtime.psl:53 |
| `gateway.P6_outcome_after_start` | temporal | request_attempt | DENY | gateway | gateway_runtime.psl:58 |
| `gateway.P6_outcome_recorded` | temporal | request_attempt | DENY | gateway | gateway_runtime.psl:62 |
| `gateway.P6_single_outcome` | temporal | request_attempt | DENY | gateway | gateway_runtime.psl:66 |
| `gateway.P2_operation` | temporal | operation | DENY | gateway | gateway_runtime.psl:78 |
| `gateway.P3_at_most_once` | temporal | operation | DENY | gateway | gateway_runtime.psl:82 |
| `gateway.P4_ledger_after_readiness` | temporal | workflow_batch | DENY | gateway | gateway_runtime.psl:94 |
| `gateway.P4_report_after_match` | temporal | workflow_batch | DENY | gateway | gateway_runtime.psl:98 |
| `gateway.P4_exception_after_mismatch` | temporal | workflow_batch | DENY | gateway | gateway_runtime.psl:102 |
| `gateway.P4_participant` | temporal | workflow_participation | DENY | gateway | gateway_runtime.psl:113 |
| `gateway.P4_within_dispatch` | temporal | workflow_participation | DENY | gateway | gateway_runtime.psl:117 |
| `identity.spiffe-b-agent-verified` | constraint | pdp_request | DENY | pdp | identity.psl:19 |
| `identity.spiffe-b-service-io-only` | constraint | pdp_request | DENY | pdp | identity.psl:24 |
| `identity.spiffe-b-known-subject-kind` | constraint | pdp_request | DENY | pdp | identity.psl:30 |
| `intent.front-office-router-allowed-targets` | constraint | pdp_request | DENY | pdp | intent.psl:15 |
| `intent.mid-office-router-allowed-targets` | constraint | pdp_request | DENY | pdp | intent.psl:21 |
| `intent.back-office-router-allowed-targets` | constraint | pdp_request | DENY | pdp | intent.psl:27 |
| `intent.no-cross-domain-transfers` | constraint | pdp_request | DENY | pdp | intent.psl:33 |
| `intent.execute-transfer-caller-restriction` | constraint | pdp_request | DENY | pdp | intent.psl:41 |
| `intent.execute-transfer-non-caller-block` | constraint | pdp_request | DENY | pdp | intent.psl:47 |
| `intent.apply-ledger-updates-pipeline-gate` | constraint | pdp_request | DENY | pdp | intent.psl:54 |
| `intent.update-transaction-status-rationale-required` | constraint | pdp_request | DENY | pdp | intent.psl:60 |
| `intent.resolve-ledger-entry-valid-amount` | constraint | pdp_request | DENY | pdp | intent.psl:67 |
| `intent.submit-manual-review-decision-agent-only` | constraint | pdp_request | DENY | pdp | intent.psl:73 |
| `intent.tool-argument-json-validity` | constraint | pdp_request | DENY | pdp | intent.psl:78 |
| `intent.require-validation-before-ledger` | constraint | pdp_request | DENY | pdp | intent.psl:84 |
| `intent.require-valid-session` | constraint | gateway_input | DENY | gateway | intent.psl:97 |
| `intent.block-prompt-injection-patterns` | constraint | gateway_input | DENY | gateway | intent.psl:103 |
| `intent.trigger-eod-reconciliation-system-only` | constraint | gateway_tool | DENY | gateway | intent.psl:117 |
| `intent.no-account-id-in-output` | constraint | gateway_output | DENY | gateway | intent.psl:130 |
| `intent.no-ssn-in-output` | constraint | gateway_output | DENY | gateway | intent.psl:137 |
| `intent.no-email-in-output` | constraint | gateway_output | DENY | gateway | intent.psl:143 |
| `intent.no-phone-in-output` | constraint | gateway_output | DENY | gateway | intent.psl:149 |
| `intent.no-sensitive-amount-in-output` | constraint | gateway_output | FLAG | gateway | intent.psl:156 |
| `intent.required-text-terms-in-decision-output` | constraint | harness_output | MANUAL_REVIEW | harness | intent.psl:170 |
| `intent.expected-status-must-match` | constraint | harness_output | MANUAL_REVIEW | harness | intent.psl:177 |
| `intent.execute-transfer-caller-restriction.order` | temporal | workflow_run | DENY | native, gateway | intent.psl:190 |
| `intent.apply-ledger-updates-pipeline-gate.order` | temporal | workflow_run | DENY | native, gateway | intent.psl:195 |
| `intent.resolve-ledger-entry-valid-amount.order` | temporal | workflow_run | DENY | native, gateway | intent.psl:200 |
| `intent.submit-manual-review-decision-agent-only.order` | temporal | workflow_run | DENY | native, gateway | intent.psl:205 |
| `intent.require-upstream-reports-before-decision.order` | temporal | workflow_run | DENY | native, gateway | intent.psl:211 |
| `intent.require-validation-before-ledger.order` | temporal | workflow_run | DENY | native, gateway | intent.psl:216 |
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

## `gateway.P1_identity` (temporal)

> A tool call is admitted only after THIS request passed both identity layers: the verified workload SVID of the mTLS peer and the agent certificate, registry and RFC 9421 signature bound to that workload.

```psl
(identity_verified && identity.workload_ok && identity.agent_registered && identity.agent_credential_ok) before execution_admitted
```

monitor: 3 states, 10 letters; verdicts `PVS`

## `gateway.P1_authorization` (temporal)

> A tool call is admitted only after the PDP allowed this request.

```psl
authorization_allowed before execution_admitted
```

monitor: 3 states, 3 letters; verdicts `PSV`

## `gateway.P1_permit` (temporal)

> A tool call is admitted only after a Permit Lease bound to this request was verified.

```psl
permit_verified before execution_admitted
```

monitor: 3 states, 3 letters; verdicts `PVS`

## `gateway.P1_binding` (temporal)

> At admission the Permit Lease still binds tool, resource, arguments and the authenticated caller.

```psl
never (execution_admitted && !permit.bound)
```

monitor: 2 states, 3 letters; verdicts `PV`

## `gateway.P1_admission` (temporal)

> The business function starts only through an admission.

```psl
execution_admitted before execution_started
```

monitor: 3 states, 3 letters; verdicts `PSV`

## `gateway.P2_request` (temporal)

> Once any layer rejected or denied this request, it is never executed.

```psl
never { (identity_rejected || run_rejected || authorization_denied || authorization_unavailable || permit_rejected || obligation_rejected || request_denied) ; [*] ; (execution_admitted || execution_started) }
```

monitor: 3 states, 10 letters; verdicts `PPV`

## `gateway.P5_live` (temporal)

> At admission the Permit Lease is unexpired and not revoked, and the caller's agent credential is still valid.

```psl
never (execution_admitted && !permit.live)
```

monitor: 2 states, 3 letters; verdicts `PV`

## `gateway.P6_pre_audit` (temporal)

> A durable, correlated pre-execution audit record exists before the business function starts.

```psl
(audit_pre_recorded && audit.correlated && audit.durable) before execution_started
```

monitor: 3 states, 7 letters; verdicts `PSV`

## `gateway.P6_post_audit` (temporal)

> Every outcome (success, failure, denial) is followed by a correlated outcome record before the request scope closes.

```psl
always ((execution_succeeded || execution_failed || request_denied) -> eventually! (audit_post_recorded && audit.correlated))
```

monitor: 2 states, 7 letters; verdicts `PP`

## `gateway.P6_outcome_after_start` (temporal)

> An execution outcome is reported only for a started business function.

```psl
execution_started before (execution_succeeded || execution_failed)
```

monitor: 3 states, 4 letters; verdicts `PVS`

## `gateway.P6_outcome_recorded` (temporal)

> A started business function reports an outcome before the request scope closes.

```psl
always (execution_started -> eventually! (execution_succeeded || execution_failed))
```

monitor: 2 states, 4 letters; verdicts `PP`

## `gateway.P6_single_outcome` (temporal)

> Each request has at most one execution outcome.

```psl
never { (execution_succeeded || execution_failed) ; [*] ; (execution_succeeded || execution_failed) }
```

monitor: 3 states, 3 letters; verdicts `PPV`

## `gateway.P2_operation` (temporal)

> A terminally denied operation (same run, agent, tool and arguments) is not executed later through a new request id, JSON-RPC id, MCP session or idempotency key.

```psl
never { op_denied ; [*] ; execution_admitted }
```

monitor: 3 states, 3 letters; verdicts `PPV`

## `gateway.P3_at_most_once` (temporal)

> A protected critical write executes at most once per operation; a new admission is allowed only after the previous one ended in an explicit failure.

```psl
never { (execution_admitted && tool.critical) ; (!execution_failed)[*] ; (execution_admitted && tool.critical) }
```

monitor: 3 states, 4 letters; verdicts `PPV`

## `gateway.P4_ledger_after_readiness` (temporal)

> Ledger posting for a batch is admitted only after readiness validation of that batch succeeded in this run with ready = true.

```psl
readiness_ready before ledger_admitted
```

monitor: 3 states, 3 letters; verdicts `PVS`

## `gateway.P4_report_after_match` (temporal)

> The EOD report for a batch is admitted only after its reconciliation matched in this run.

```psl
recon_matched before report_admitted
```

monitor: 3 states, 3 letters; verdicts `PSV`

## `gateway.P4_exception_after_mismatch` (temporal)

> An exception case for a batch is admitted only after its reconciliation showed a mismatch in this run.

```psl
recon_mismatched before exception_admitted
```

monitor: 3 states, 3 letters; verdicts `PVS`

## `gateway.P4_participant` (temporal)

> An agent executes tools of a workflow run only after this gateway dispatched it in that run.

```psl
dispatched before execution_admitted
```

monitor: 3 states, 3 letters; verdicts `PSV`

## `gateway.P4_within_dispatch` (temporal)

> An agent executes tools of a workflow run only while its dispatch in that run is in flight.

```psl
never { dispatch_ended ; (!dispatched)[*] ; execution_admitted }
```

monitor: 3 states, 3 letters; verdicts `PPV`

## `identity.spiffe-b-agent-verified` (constraint)

> A request that the gateway authenticated with SPIFFE scheme B as an agent is decided only if the signed authentication assertion shows both verified factors (workload SVID and agent credential) and names the same agent as the request subject.

```psl
always (authz_request && auth.scheme == "B" && auth.subject_kind == "agent" -> auth.factor.workload_identity && auth.factor.agent_credential && auth.agent_bound)
```

atomic propositions: `auth.agent_bound`, `auth.factor.agent_credential`, `auth.factor.workload_identity`, `auth.scheme == "B"`, `auth.subject_kind == "agent"`, `authz_request`

## `identity.spiffe-b-service-io-only` (constraint)

> A caller authenticated as a service (verified workload SVID, controlled service map, no agent credential) can only obtain decisions for the MAS input and output channels, never for an agent route or a tool.

```psl
always (authz_request && auth.scheme == "B" && auth.subject_kind == "service" -> auth.factor.workload_identity && (resource.runtime_id == "mas_input_channel" || resource.runtime_id == "mas_output_channel"))
```

atomic propositions: `auth.factor.workload_identity`, `auth.scheme == "B"`, `auth.subject_kind == "service"`, `authz_request`, `resource.runtime_id == "mas_input_channel"`, `resource.runtime_id == "mas_output_channel"`

## `identity.spiffe-b-known-subject-kind` (constraint)

> A scheme B authentication result names its subject kind (agent or service); anything else is denied.

```psl
never (authz_request && auth.scheme == "B" && auth.subject_kind != "agent" && auth.subject_kind != "service")
```

atomic propositions: `auth.scheme == "B"`, `auth.subject_kind != "agent"`, `auth.subject_kind != "service"`, `authz_request`

## `intent.front-office-router-allowed-targets` (constraint)

> front_office_router may only transfer to its declared sub-agents. Any other transfer target is a routing failure (F_route). Corresponds to evaluator check: required_transfers_present and forbidden_tools_absent (applied to routes).

```psl
always (authz_request && resource.target_type == "subject" && subject.runtime_id == "front_office_router" -> (resource.runtime_id == "front_office_transaction_workflow" || resource.runtime_id == "customer_service_chatbot_workflow"))
```

obligations: {"parameters": {}, "type": "audit_log"}
atomic propositions: `authz_request`, `resource.runtime_id == "customer_service_chatbot_workflow"`, `resource.runtime_id == "front_office_transaction_workflow"`, `resource.target_type == "subject"`, `subject.runtime_id == "front_office_router"`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#front-office-router-allowed-targets

## `intent.mid-office-router-allowed-targets` (constraint)

> mid_office_router may only transfer to mid-office sub-workflows.

```psl
always (authz_request && resource.target_type == "subject" && subject.runtime_id == "mid_office_router" -> (resource.runtime_id == "mid_office_planning_workflow" || resource.runtime_id == "representative_assistant_workflow"))
```

obligations: {"parameters": {}, "type": "audit_log"}
atomic propositions: `authz_request`, `resource.runtime_id == "mid_office_planning_workflow"`, `resource.runtime_id == "representative_assistant_workflow"`, `resource.target_type == "subject"`, `subject.runtime_id == "mid_office_router"`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#mid-office-router-allowed-targets

## `intent.back-office-router-allowed-targets` (constraint)

> back_office_router may only transfer to the EOD workflow.

```psl
always (authz_request && resource.target_type == "subject" && subject.runtime_id == "back_office_router" -> resource.runtime_id == "back_office_eod_workflow")
```

obligations: {"parameters": {}, "type": "audit_log"}
atomic propositions: `authz_request`, `resource.runtime_id == "back_office_eod_workflow"`, `resource.target_type == "subject"`, `subject.runtime_id == "back_office_router"`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#back-office-router-allowed-targets

## `intent.no-cross-domain-transfers` (constraint)

> No agent may transfer control across domain boundaries (front→back, mid→front, etc.) without going through user_proxy_agent. Prevents unauthorized domain escalation (F_route).

```psl
always (authz_request && resource.target_type == "subject" -> !(request.cross_domain && subject.runtime_id != "user_proxy_agent"))
```

obligations: {"parameters": {}, "type": "audit_log"}
atomic propositions: `authz_request`, `request.cross_domain`, `resource.target_type == "subject"`, `subject.runtime_id != "user_proxy_agent"`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#no-cross-domain-transfers

## `intent.execute-transfer-caller-restriction` (constraint)

> execute_transfer may only be called by transaction_processing_agent. No other agent in the system has authority to move money. Corresponds to evaluator check: required_tools_present and forbidden_tools_absent.

```psl
always (authz_request && resource.runtime_id == "banking_transfer" && action == "execute" && subject.runtime_id == "transaction_processing_agent" -> subject.runtime_id == "transaction_processing_agent" && args.source_account.nonempty && args.destination_account.nonempty && args.amount.finite_nonzero)
```

obligations: {"parameters": {}, "type": "audit_log"}, {"parameters": {}, "type": "emit_financial_event"}
atomic propositions: `action == "execute"`, `args.amount.finite_nonzero`, `args.destination_account.nonempty`, `args.source_account.nonempty`, `authz_request`, `resource.runtime_id == "banking_transfer"`, `subject.runtime_id == "transaction_processing_agent"`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#execute-transfer-caller-restriction

## `intent.execute-transfer-non-caller-block` (constraint)

> All agents other than transaction_processing_agent are denied from calling execute_transfer. Hard block — no exceptions.

```psl
never (authz_request && resource.runtime_id == "banking_transfer" && action == "execute" && subject.runtime_id != "transaction_processing_agent")
```

atomic propositions: `action == "execute"`, `authz_request`, `resource.runtime_id == "banking_transfer"`, `subject.runtime_id != "transaction_processing_agent"`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#execute-transfer-non-caller-block

## `intent.apply-ledger-updates-pipeline-gate` (constraint)

> apply_ledger_updates requires that the full EOD pipeline has run: validation must confirm readiness and processing must have produced posting instructions. Prevents ledger writes without upstream validation. Corresponds to evaluator check: required_result_keys_present.

```psl
always (authz_request && resource.runtime_id == "ledger" && action == "update" && subject.runtime_id == "ledger_update_agent" -> subject.runtime_id == "ledger_update_agent" && args.posting_instructions.nonempty)
```

obligations: {"parameters": {}, "type": "audit_log"}, {"parameters": {}, "type": "emit_ledger_event"}
atomic propositions: `action == "update"`, `args.posting_instructions.nonempty`, `authz_request`, `resource.runtime_id == "ledger"`, `subject.runtime_id == "ledger_update_agent"`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#apply-ledger-updates-pipeline-gate

## `intent.update-transaction-status-rationale-required` (constraint)

> update_transaction_status requires a non-empty rationale field. Status changes without documented reasoning are non-compliant. Corresponds to evaluator check: expected_decision_matched.

```psl
always (authz_request && resource.runtime_id == "update_transaction_status" && subject.runtime_id == "decision_making_agent" -> subject.runtime_id == "decision_making_agent" && (args.status == "APPROVED" || args.status == "REJECTED" || args.status == "MANUAL_REVIEW") && args.rationale.length >= 20)
```

obligations: {"parameters": {}, "type": "audit_log"}
atomic propositions: `args.rationale.length >= 20`, `args.status == "APPROVED"`, `args.status == "MANUAL_REVIEW"`, `args.status == "REJECTED"`, `authz_request`, `resource.runtime_id == "update_transaction_status"`, `subject.runtime_id == "decision_making_agent"`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#update-transaction-status-rationale-required

## `intent.resolve-ledger-entry-valid-amount` (constraint)

> resolve_ledger_entry correction_amount must be a non-zero finite number. A zero correction is a no-op and indicates an upstream error.

```psl
always (authz_request && resource.runtime_id == "resolve_ledger_entry" && subject.runtime_id == "exception_agent" -> subject.runtime_id == "exception_agent" && args.correction_amount.finite_nonzero && args.note.nonempty)
```

obligations: {"parameters": {}, "type": "audit_log"}, {"parameters": {}, "type": "emit_ledger_event"}
atomic propositions: `args.correction_amount.finite_nonzero`, `args.note.nonempty`, `authz_request`, `resource.runtime_id == "resolve_ledger_entry"`, `subject.runtime_id == "exception_agent"`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#resolve-ledger-entry-valid-amount

## `intent.submit-manual-review-decision-agent-only` (constraint)

> submit_manual_review may only be called by decision_making_agent. Monitoring and fraud agents must not escalate directly — they must surface findings and let the decision agent act.

```psl
always (authz_request && resource.runtime_id == "submit_manual_review" && subject.runtime_id == "decision_making_agent" -> subject.runtime_id == "decision_making_agent")
```

obligations: {"parameters": {}, "type": "audit_log"}
atomic propositions: `authz_request`, `resource.runtime_id == "submit_manual_review"`, `subject.runtime_id == "decision_making_agent"`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#submit-manual-review-decision-agent-only

## `intent.tool-argument-json-validity` (constraint)

> All tool arguments must be valid structured data before the tool PEP forwards the call. Malformed arguments are a signal for F_format failure. Corresponds to evaluator check: tool_arguments_valid_json.

```psl
always (authz_request && resource.target_type != "subject" -> args.well_formed)
```

atomic propositions: `args.well_formed`, `authz_request`, `resource.target_type != "subject"`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#tool-argument-json-validity

## `intent.require-validation-before-ledger` (constraint)

> ledger_update_agent must not write bo_ledger_update_report unless the validation checkpoint confirmed readiness. Amounts in the processing report must be consistent with the batch totals. Corresponds to evaluator check: mismatch_amount_consistent.

```psl
always (authz_request && resource.runtime_id == "ledger" && action == "update" && subject.runtime_id == "ledger_update_agent" -> args.posting_instructions.nonempty)
```

obligations: {"parameters": {}, "type": "audit_log"}
atomic propositions: `action == "update"`, `args.posting_instructions.nonempty`, `authz_request`, `resource.runtime_id == "ledger"`, `subject.runtime_id == "ledger_update_agent"`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#require-validation-before-ledger

## `intent.require-valid-session` (constraint)

> Every inbound request must carry a valid session_id and user_role. Requests without a session context are dropped before reaching user_proxy_agent. Corresponds to evaluator check: expectation_defined.

```psl
always (input_received -> session.id_present && (user.role == "customer" || user.role == "internal_rep" || user.role == "ops_scheduler" || user.role == "system" || user.role == "auditor"))
```

obligations: {"parameters": {}, "type": "audit_log"}
atomic propositions: `input_received`, `session.id_present`, `user.role == "auditor"`, `user.role == "customer"`, `user.role == "internal_rep"`, `user.role == "ops_scheduler"`, `user.role == "system"`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#require-valid-session

## `intent.block-prompt-injection-patterns` (constraint)

> Input containing known prompt injection patterns (override system prompt, ignore instructions, claim authority waiver) must be denied at the input PEP before any agent processes it. Directly addresses F_DPI failure type.

```psl
always (input_received -> !input.prompt_injection_detected)
```

obligations: {"parameters": {}, "type": "audit_log"}
atomic propositions: `input.prompt_injection_detected`, `input_received`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#block-prompt-injection-patterns

## `intent.trigger-eod-reconciliation-system-only` (constraint)

> trigger_eod_reconciliation may only be called by system-role sessions. Customer or representative sessions must not be able to kick off EOD.

```psl
always (tool_call && tool.name == "trigger_eod_reconciliation" -> (user.role == "system" || user.role == "ops_scheduler"))
```

obligations: {"parameters": {}, "type": "audit_log"}, {"parameters": {}, "type": "emit_batch_event"}
atomic propositions: `tool.name == "trigger_eod_reconciliation"`, `tool_call`, `user.role == "ops_scheduler"`, `user.role == "system"`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#trigger-eod-reconciliation-system-only

## `intent.no-account-id-in-output` (constraint)

> Final agent outputs must not contain raw account IDs. Corresponds to evaluator check: no_account_id_leak (F_pii).

```psl
always (output_emitted -> !output.contains.account_id)
```

obligations: {"parameters": {}, "type": "audit_log"}
atomic propositions: `output.contains.account_id`, `output_emitted`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#no-account-id-in-output

## `intent.no-ssn-in-output` (constraint)

> Final agent outputs must not contain Social Security Numbers. Corresponds to evaluator check: no_ssn_leak (F_pii).

```psl
always (output_emitted -> !output.contains.ssn)
```

obligations: {"parameters": {}, "type": "audit_log"}, {"parameters": {}, "type": "alert_privacy_team"}
atomic propositions: `output.contains.ssn`, `output_emitted`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#no-ssn-in-output

## `intent.no-email-in-output` (constraint)

> Final agent outputs must not contain raw email addresses. Corresponds to evaluator check: no_email_leak (F_pii).

```psl
always (output_emitted -> !output.contains.email)
```

obligations: {"parameters": {}, "type": "audit_log"}
atomic propositions: `output.contains.email`, `output_emitted`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#no-email-in-output

## `intent.no-phone-in-output` (constraint)

> Final agent outputs must not contain phone numbers. Corresponds to evaluator check: no_phone_leak (F_pii).

```psl
always (output_emitted -> !output.contains.phone)
```

obligations: {"parameters": {}, "type": "audit_log"}
atomic propositions: `output.contains.phone`, `output_emitted`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#no-phone-in-output

## `intent.no-sensitive-amount-in-output` (constraint)

> Final outputs must not expose raw internal financial amounts that were not explicitly part of the user's query scope. Corresponds to evaluator check: no_sensitive_amount_exposure (F_pii).

```psl
always (output_emitted -> !output.contains.unexplained_internal_amount)
```

obligations: {"parameters": {}, "type": "audit_log"}
atomic propositions: `output.contains.unexplained_internal_amount`, `output_emitted`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#no-sensitive-amount-in-output

## `intent.required-text-terms-in-decision-output` (constraint)

> The decision_making_agent output must contain all required terms for the active scenario (decision, confidence, rationale). Missing terms indicate hallucination or incomplete reasoning. Corresponds to evaluator check: required_text_terms_present.

```psl
always (harness_check -> output.required_terms_present)
```

obligations: {"parameters": {}, "type": "audit_log"}
atomic propositions: `harness_check`, `output.required_terms_present`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#required-text-terms-in-decision-output

## `intent.expected-status-must-match` (constraint)

> For scenarios with a known expected status, the agent output must match the expected value. Mismatch signals a failure mode. Corresponds to evaluator check: expected_status_matched.

```psl
always (harness_check -> output.status_matches_expectation)
```

obligations: {"parameters": {}, "type": "audit_log"}
atomic propositions: `harness_check`, `output.status_matches_expectation`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#expected-status-must-match

## `intent.execute-transfer-caller-restriction.order` (temporal)

> execute_transfer may only be called by transaction_processing_agent. No other agent in the system has authority to move money. Corresponds to evaluator check: required_tools_present and forbidden_tools_absent.

```psl
((agent_routed && route.to == "customer_service_agent") before (tool_admitted && tool.name == "execute_transfer" && tool.agent == "transaction_processing_agent"))
```

monitor: 3 states, 10 letters; verdicts `PSV`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#execute-transfer-caller-restriction

## `intent.apply-ledger-updates-pipeline-gate.order` (temporal)

> apply_ledger_updates requires that the full EOD pipeline has run: validation must confirm readiness and processing must have produced posting instructions. Prevents ledger writes without upstream validation. Corresponds to evaluator check: required_result_keys_present.

```psl
((tool_succeeded && tool.name == "validate_eod_readiness") before (tool_admitted && tool.name == "apply_ledger_updates" && tool.agent == "ledger_update_agent")) && ((tool_succeeded && tool.name == "validate_eod_readiness" && result.ready) before (tool_admitted && tool.name == "apply_ledger_updates" && tool.agent == "ledger_update_agent")) && ((tool_succeeded && tool.name == "get_eod_batch") before (tool_admitted && tool.name == "apply_ledger_updates" && tool.agent == "ledger_update_agent"))
```

monitor: 5 states, 64 letters; verdicts `PVPPS`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#apply-ledger-updates-pipeline-gate

## `intent.resolve-ledger-entry-valid-amount.order` (temporal)

> resolve_ledger_entry correction_amount must be a non-zero finite number. A zero correction is a no-op and indicates an upstream error.

```psl
((tool_succeeded && tool.name == "get_reconciliation_data") before (tool_admitted && tool.name == "resolve_ledger_entry" && tool.agent == "exception_agent"))
```

monitor: 3 states, 24 letters; verdicts `PVS`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#resolve-ledger-entry-valid-amount

## `intent.submit-manual-review-decision-agent-only.order` (temporal)

> submit_manual_review may only be called by decision_making_agent. Monitoring and fraud agents must not escalate directly — they must surface findings and let the decision agent act.

```psl
((tool_succeeded && tool.agent == "transaction_monitoring_agent") before (tool_admitted && tool.name == "submit_manual_review" && tool.agent == "decision_making_agent")) && ((tool_succeeded && tool.agent == "fraud_detection_agent") before (tool_admitted && tool.name == "submit_manual_review" && tool.agent == "decision_making_agent")) && ((tool_succeeded && tool.agent == "compliance_agent") before (tool_admitted && tool.name == "submit_manual_review" && tool.agent == "decision_making_agent"))
```

monitor: 9 states, 96 letters; verdicts `PVPPPPPPS`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#submit-manual-review-decision-agent-only

## `intent.require-upstream-reports-before-decision.order` (temporal)

> decision_making_agent must not produce fo_decision_report unless all three upstream specialist reports are present in session state. Corresponds to evaluator checks: required_result_keys_present and expected_decision_matched.

```psl
((tool_succeeded && tool.agent == "transaction_monitoring_agent") before (agent_routed && route.to == "decision_making_agent")) && ((tool_succeeded && tool.agent == "fraud_detection_agent") before (agent_routed && route.to == "decision_making_agent")) && ((tool_succeeded && tool.agent == "compliance_agent") before (agent_routed && route.to == "decision_making_agent"))
```

monitor: 9 states, 18 letters; verdicts `PVPPPPPPS`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#require-upstream-reports-before-decision

## `intent.require-validation-before-ledger.order` (temporal)

> ledger_update_agent must not write bo_ledger_update_report unless the validation checkpoint confirmed readiness. Amounts in the processing report must be consistent with the batch totals. Corresponds to evaluator check: mismatch_amount_consistent.

```psl
((tool_succeeded && tool.name == "validate_eod_readiness" && result.ready) before (tool_admitted && tool.name == "apply_ledger_updates" && tool.agent == "ledger_update_agent"))
```

monitor: 3 states, 32 letters; verdicts `PVS`
source: legacy/citi_p3/manifest_spec/manifest/policy_intent.yaml#require-validation-before-ledger

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
