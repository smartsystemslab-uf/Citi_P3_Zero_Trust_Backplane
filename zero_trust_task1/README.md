# Zero Trust Backplane — README

This folder contains the zero-trust intermediate representation for the Citi Banking ADK proof-of-concept.
It documents the manifest files produced for Phase 1 of the zero-trust design, plus the schema and I/O specification used to validate and consume those manifests.

## Goal

The zero-trust manifest task defines a security-aware model of the system:
- what agents exist
- what tools they may call
- what APIs are exposed
- what databases those APIs touch
- what workflows and transfer paths are allowed
- what trust boundaries must be enforced
- what authorization rules should apply
- what identity claims are carried by the policy decision process

This README explains each file and the work that has been done in this folder.

## Top-level manifest files

### `manifest/agents.yaml`
- Contains the agent inventory for the Citi Banking ADK.
- Describes each agent’s domain, role, risk tier, authorized tools, authorized transfer targets, required prior state, PEP type, and trust level.
- Captures both front-office, mid-office, and back-office agents as well as the root entry agent.
- Establishes the system’s agent-level routing and least-privilege model.

### `manifest/tools.yaml`
- Defines ADK and MCP tools as callable resources.
- Records tool risk level, action type, side effects, PII exposure, compliance tags, and whether a live decision is required.
- Lists which agents are allowed to call each tool.
- Explicitly marks high-risk operations such as `execute_transfer` and `submit_manual_review`.
- Provides the source-of-truth for tool-based enforcement decisions.

### `manifest/apis.yaml`
- Describes the backend HTTP API surface exposed by `citi_banking_backend`.
- Includes endpoint metadata such as method, path, risk level, required authentication, audit requirements, and allowed callers.
- Maps API calls to the database tables they read or write.
- Supports the policy model for API-level authorization and data-plane enforcement.

### `manifest/databases.yaml`
- Enumerates the system’s data assets, including `customers`, `accounts`, `transactions`, `policies`, `rules`, and `audit_logs`.
- Classifies each table by sensitivity, financial content, PII, and audit nature.
- Declares allowed SQL operations and which API endpoints may access each table.
- Marks audit logs as append-only / immutable and enforces strict access controls.

### `manifest/workflows.yaml`
- Defines the major agent workflows in the ADK.
- Includes front-office transaction risk/execution, customer-service chatbot, mid-office planning, representative assistant, and back-office EOD reconciliation.
- Captures entry agents, execution order, parallel steps, success/failure exit conditions, risk tiers, and required user roles.
- Provides the workflow-level context needed by route PEPs and pipeline gate enforcement.

### `manifest/interaction_edges.yaml`
- Represents the full directed relationship graph of the system.
- Covers agent-to-agent transfers, agent-to-tool calls, tool-to-API invocations, and API-to-database access.
- Specifies the risk level and whether a PEP is required for each edge.
- Describes the enforcement type for each edge: `route_pep`, `tool_pep`, `api_pep`, or `data_pep`.
- Forms the contract used by a future generator to create enforcement stubs.

### `manifest/trust_boundaries.yaml`
- Defines the network/security perimeters for the zero-trust design.
- Includes external boundary, front office, mid office, back office, backend API, MCP server, and database tier.
- States which boundaries may ingress to each other, which PEPs are required, and the network policy assumptions.
- Captures the intended deployment security posture for each service boundary.

### `manifest/policy_intent.yaml`
- Contains the high-level authorization policy rules for the system.
- Uses a default-deny stance: anything not explicitly allowed is denied.
- Includes rules for input validation, routing restrictions, tool caller restrictions, and critical action gating.
- Defines decision outcomes, obligations, and fail behavior for policy decisions.
- Is designed to be compiled later into an enforceable PDP policy bundle.

### `manifest/identity_context.yaml`
- Defines the identity/context model used by PEPs and PDPs.
- Specifies required claims such as `session_id`, `agent_id`, `user_role`, and `workflow_state`.
- Includes optional claims for `risk_context`, `user_id`, and `device_context`.
- Defines how identity context is downscoped as it flows between domains.
- Documents the PDP request/response contract for future enforcement.

## Schema and specification files

### `schema/zt_manifest_schema.yaml`
- The master schema for all zero-trust manifests.
- Defines entity types such as `subject`, `tool`, `api`, `database`, `workflow`, `interaction_edge`, `trust_boundary`, `policy_rule`, `identity_context`, and `operation_class`.
- Ensures manifest files are structurally valid and consistent.
- Supports schema validation as the first phase of manifest correctness.

### `spec/io_specification.yaml`
- Defines the I/O contracts for the zero-trust pipeline.
- Documents Phase 1 validator behavior and expected inputs/outputs.
- Describes planned Phase 2 manifest scanner, Phase 3 PEP generator, and Phase 4 PDP integration.
- Helps future tooling understand how manifest and schema files are consumed.

## What has been done

- Phase 1 manifests have been written for the Citi Banking ADK zero-trust model.
- The manifest set covers agents, tools, APIs, databases, workflows, interaction edges, trust boundaries, policy intent, and identity context.
- A schema file has been provided to validate those manifests.
- An I/O specification has been provided to define how the validator and future generators should consume the files.
- The design is ready for a Phase 1 validator implementation and for Phase 2/3 planning.

## How to use this folder

1. Review and maintain manifest files when the ADK or backend changes.
2. Use `schema/zt_manifest_schema.yaml` to validate manifest structure and required fields.
3. Use `spec/io_specification.yaml` as a contract for future tooling:
   - manifest scanner (Phase 2)
   - PEP generator (Phase 3)
   - PDP decision format (Phase 4)
4. Keep `policy_intent.yaml` synchronized with system enforcement expectations and evaluator rules.

## Notes

- This README is intended as a guide to the zero-trust manifest task, not as runtime code.
- No enforcement code is present in this folder yet; the files are the declarative security model for the system.
