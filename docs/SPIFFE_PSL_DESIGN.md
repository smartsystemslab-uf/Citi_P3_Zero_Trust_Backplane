# SPIFFE (scheme B) + PSL policies in the Zero Trust Backplane -- design

Branch `feature/spiffe-psl`. Decisions by the project owner (2026-11-02):

* **Identity:** SPIFFE scheme B only -- X.509-SVID workload identity (mTLS) **plus** a separate
  agent credential (agent certificate bound to the workload SPIFFE ID, RFC 9421 message
  signature, registry state, replay window).
* **Policies:** every natural-language / YAML policy becomes a **PSL** policy (IEEE 1850).
  Decision semantics change from Task 4's "highest priority wins" to **deny-overrides**: every
  applicable rule must hold; a single violated rule refuses the request. Every resulting
  behaviour change is listed (differential report), none is silent.

The design reuses code that was verified in the experiment projects
(`D:\Lab\Citi_P3_MCP_PSL_Monitor`: PSL compiler/runtime, scheme-B authenticators, SPIRE deployment,
MCP gateway), adapted to this repository.

## 1. Starting point (as found on `main`, commit 919860e2)

| item | state |
|---|---|
| SPIFFE | placeholders only: `identity_context.yaml` "deferred to Phase 4", `trusted_issuers.yaml` dev PEM keys with `TODO ... SPIFFE trust roots`; the native runtime sends `auth_factors: {workload_identity: true}` as a self-asserted claim |
| Task 1 `policy_intent.yaml` | 24 rules, 45 conditions in controlled natural language; header says "compiled into OPA Rego in Phase 3" -- **no code reads it; none of these rules is enforced** |
| Task 4 `policy_store/*.yaml` | 16 signed structured policies (subject/resource/action/workflow/risk/auth/approval/time matchers, effect, priority, obligations), evaluated by `PolicyEngine` (highest priority, then strongest effect) plus a hard-coded critical-write rule in `engine.py` |
| native runtime | runs the Task 4 PDP in-process (FastAPI TestClient) inside the CITI-MAS process; generates `native_mas_runtime.yaml` from the 105 Task 3 placements |
| tests | 69 passed, 2 skipped (interface 4, Task 2 11, Task 3 10+2s, Task 4 23, Task 5 16, integrated_demo 5) |

## 2. PSL as the Backplane policy language

### 2.1 Language

Same core as the verified monitor (IEEE 1850-2010, Verilog flavour, simple subset; see
`zero_trust_psl/docs/PSL_SUPPORTED_SUBSET.md`), extended in the **Boolean layer** only:

* hierarchical field references (Verilog hierarchical names): `subject.id`, `resource.critical`,
  `security.auth_strength`, `param.amount`;
* comparisons with literals: `==`, `!=`, `<`, `<=`, `>`, `>=` against `"string"`, integers,
  `true`/`false`;
* named Boolean/temporal properties: `property NAME = ...;` used by name.

Every field must be declared in the **field catalogue** (`policy_fields.yaml`) with its type and
its *trusted source* (verified request, verified security context, identity registry, resource
catalogue, trusted runtime event, trusted checker). Unknown fields, type errors and unsupported
syntax are compile errors.

### 2.2 Annotations

Policy metadata lives in structured comments directly above a declaration (comments are ignored by
any other PSL tool, so the files stay plain PSL):

```
// @rule   policy.ledger.report_deny_update
// @nl     Explicitly deny report-agent ledger writes.
// @on_violation DENY
// @source zero_trust_pdp_task4_secure/legacy_policy_store/ledger_access.yaml
P_report_no_ledger_update: assert never (authz_request && subject.id == "agent.back_office.report"
                                          && resource.id == "resource.back_office.ledger" && action == "update");
```

`@on_violation` ∈ {DENY (default), REAUTHENTICATE, MANUAL_REVIEW}; permissions carry
`@permit` and `@obligation type(key=value, ...)`; `@runtime` restricts a rule to the runtimes
that can supply its fields (`pdp`, `native`, `gateway`, `harness`).

### 2.3 Two kinds of rules

| kind | form | evaluated by | compiled to |
|---|---|---|---|
| request rules | `always (authz_request -> b)`, `never (authz_request && b)` with Boolean `b` | PDP, per request | Boolean predicate (no automaton) |
| workflow rules | temporal (`before`, `next`, SERE, `never {..}`) over trusted runtime events | PEP-side monitor per workflow run / operation | automaton (as in the monitor experiment) |

For request rules the automaton of `always b` is exactly "stay while b holds, violate when it does
not", so the compiler evaluates `b` directly; the reference interpreter checks that both agree.

### 2.4 Decision: deny-overrides

For a verified request the PDP evaluates every applicable rule:

1. **Default deny** -- the generated rule `R_default_deny: assert always (authz_request -> permitted)`
   where `permitted` is the disjunction of all `@permit` properties. No permission → DENY.
2. **Constraints** -- every other request rule. A violated rule contributes its `@on_violation`.
3. **Outcome** = the strictest contributed outcome, DENY > REAUTHENTICATE > MANUAL_REVIEW (Task 4's
   precedence); if nothing is violated → ALLOW, or ALLOW_WITH_OBLIGATIONS when the permissions that
   hold carry obligations (union of their obligations).
4. The response lists every violated rule id (`reason`, `matched_policy_ids`) and the permissions
   that held -- auditable, no priorities.

Structural checks stay before policy evaluation (unknown subject/resource, undefined action →
DENY), as today.

### 2.5 Signing and regeneration

PSL policy files are signed with the existing `policy.prototype` key (detached `.sig.json`, same
format as the YAML bundles) and verified before use. Compiled artifacts carry the SHA-256 of the
sources, field catalogue and compiler; a mismatch refuses to load (`MonitorStale`).

## 3. Conversion of the existing policies

| source | method | output |
|---|---|---|
| Task 4 `policy_store/*.yaml` (16) | translator for the structured matchers + **semantic** handling of priority patterns (e.g. `*_pending_review` MANUAL_REVIEW + higher-priority `*_approved` ALLOW → permission + constraint "never (scope && !(approval && secondary))" with `@on_violation MANUAL_REVIEW`) | `policy_store/*.psl` |
| engine's hard-coded critical-write rule | explicit PSL constraint (`@on_violation MANUAL_REVIEW`) | `policy_store/core.psl` |
| Task 1 `policy_intent.yaml` (24 rules) | deterministic translator for the controlled grammar (`is present`, `== / !=`, `in [..]`, `NOT ( .. AND .. )`, `len(x) >= n`, `does not match pattern P`, ...); runtime names → canonical IDs through the unified bindings; `session_state.X` prerequisites → **temporal** rules over trusted events (not over agent-writable session state); phrases outside the grammar → explicit error, then a named trusted checker AP | `policy_store/intent_*.psl` |
| native generated bundle | generator emits PSL instead of YAML | `output/task4_policy_store/native_mas_runtime.psl` |

The old YAML files move to `legacy_policy_store/` and are used only by the differential test.

**Differential test:** old PDP vs PSL PDP on (a) every request of the existing test suites and
(b) the full cross product of known subjects × resources × actions × workflows × risk levels ×
auth strengths × approval flags × business-hours flag. Every differing decision is listed with the
rule that causes it.

## 4. SPIFFE scheme B (as implemented)

* `zero_trust_identity/` (package `zt_identity`) -- X.509-SVID acquisition (SPIFFE Workload API),
  mTLS with SPIFFE-ID peer verification, agent-credential issuer and registry, RFC 9421
  signer/verifier with content digest and replay window, controlled service map (ported from the
  experiments; scheme A and C0 removed). 25 unit tests (run inside the runtime image).
* `distributed_runtime/` (package `zt_distributed`) -- the MCP gateway PEP, one container per
  agent (13 original ADK agents: transaction monitoring, the customer-service chatbot path to
  `execute_transfer`, the EOD workflow), agent-credential issuer, ingress client, SPIRE server +
  agent (x509pop node attestation; docker label + compose project + per-workload UID selectors),
  compose generator, control CLI. Every hop is authenticated by both layers before any policy is
  consulted; see `distributed_runtime/README.md`.
* **Identity facts reach the PDP as PSL fields.** The gateway's backplane adapter puts the
  verification result into the IdP-signed authentication assertion (`authentication` block); the
  evidence verifier exposes `auth.scheme`, `auth.subject_kind`, `auth.factor.*` (factors are
  checked against the factor-weight table; `agent_credential` was added to
  `security_context.yaml`, mapping version `prototype-auth-factors-2`) and `auth.agent_bound`
  (assertion agent == request subject). `policy_store/identity.psl` requires, for scheme B:
  agents -- both factors and the binding; services -- only the MAS input/output channels; any
  other subject kind -- deny.
* **Gateway policies are PSL too:** check-only scopes `gateway_input` / `gateway_output` /
  `gateway_tool` (intent rules on session/role, prompt injection, PII in the final output,
  system-only EOD trigger) and the tool-path monitors P1-P6 (`policy_store/gateway_runtime.psl`,
  scopes `request_attempt`, `operation`, `workflow_batch`, `workflow_participation`). The
  `workflow_run` intent rules run in the engine's monitor at authorize / begin_tool / finish_tool.
  All of them are loaded from the one signed store the PDP verifies.
* **Deviation from the plan -- PDP edge:** the distributed runtime runs the Task 4 PDP in-process
  inside the gateway (as the native runtime does), so there is no network hop to the PDP to protect
  with mTLS; the PEP request proof and decision signatures are unchanged. A separately deployed PDP
  would need that edge.
* **Native in-process runtime:** all agents share one process, hence one workload identity; the
  agent layer of scheme B cannot separate agents there, and its fixed factor claim
  (`workload_identity`, `user_session`) stays -- its requests carry no `authentication` block, so
  `identity.psl` does not apply to them. The native runtime keeps working with the PSL policies
  (including the `workflow_run` monitor). This limit is stated, not hidden.

## 5. Verification

1. PSL unit tests (ported 105 + new Boolean-layer, annotation, field-catalogue, signing tests),
   reference interpreter cross-check.
2. Translation tests for both translators (every rule; unsupported phrases fail).
3. Differential report old vs new PDP.
4. Existing suites updated only where deny-overrides changes a decision (each change cited).
5. Distributed runtime end to end with real SPIRE SVIDs and agent certificates.
6. Controlled security cases (identity and policy layer).
7. Performance: old PDP vs PSL PDP decision latency; end-to-end overhead.

## 6. Status (2026-11-02, branch `feature/spiffe-psl`, not committed)

| check | result |
|---|---|
| zero_trust_psl | 143 passed (incl. guard-index equivalence vs exhaustive evaluation) |
| Task 4 PDP | 36 passed (incl. differential equivalence and 7 SPIFFE identity-rule tests) |
| Task 2 / Task 3 / Task 5 / interface / integrated_demo / native runtime | 11 / 12 / 16 / 4 / 5 / 6 passed |
| zero_trust_identity | 25 passed inside the runtime image (10 workload-layer tests also on the host) |
| distributed_runtime unit (host) | 60 passed (gateway monitors from the signed store, PSL guard, content checks) |
| distributed_runtime end to end (Docker, SPIRE) | 15 passed: identities, separate agent CA, read, transfer via customer-service path, direct transfer refused (`intent.execute-transfer-caller-restriction.order`), approval required, EOD clean + mismatch, EOD not ready, direct ledger post refused, knowledge path, 3 input-rule refusals, disable/enable with lease revocation, SVID + agent-certificate rotation |
| integrated demo modes 1 and 2 | ALL TASKS 1-5 INTEGRATED: PASS |
| differential (552,960 requests) | translated store: 0 differences; with intent rules: 128 stricter (all `intent.execute-transfer-caller-restriction`), 0 more permissive |
| performance | `docs/PSL_PERFORMANCE_REPORT.md`: same content x0.98 of legacy; deployed store (15 more rules) x1.6; native store (135 policies) x0.32, i.e. 3.1x faster |

Open items, decided by the project owner later:

* `intent.no-cross-domain-transfers` stays `@disabled` (13 conflicting routes: the Task 2 scanner
  puts mid-office workflow agents into domain `shared`); enabling it needs a data decision.
* The MAS repository tracks `citi_banking_adk/.env` and a `.venv`; the distributed runtime never
  copies them (staging excludes them, the image build fails if they appear).
