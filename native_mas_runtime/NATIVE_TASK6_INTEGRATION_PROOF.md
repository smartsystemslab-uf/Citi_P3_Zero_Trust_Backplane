# Native End-to-End Zero Trust Integration — Bug Found, Fixed, and Proven Live

Date: 2026-08-26

> For how to run this and a detailed architecture walkthrough, see
> [`../../Citi_P3/citi_banking_adk/NATIVE_ZERO_TRUST_README.md`](../../Citi_P3/citi_banking_adk/NATIVE_ZERO_TRUST_README.md)
> in the MAS repo. This document is the narrative record of the bug, the
> fix, and the live evidence.

## Why this document exists

A review of the project raised a fair challenge: everything demonstrated and
committed so far (Tasks 1-5 unit tests, `integrated_demo/task6_real_workflows.py`)
proves enforcement at the tool/API/DB boundary, driven by a harness script that
calls the PEP/PDP/Permit-Lease chain and the original Citi tools itself. None
of it proves that Zero Trust is actually wired into the **real** multi-agent
system: a real CLI message, handled by the real `google-adk` `App`/`Runner`,
routed by a real LLM through real agent delegation, calling real tools, with
enforcement actually intercepting that live execution end to end.

That native wiring existed as a first cut (`bank_adk/zero_trust/plugin.py` in
the Citi_P3 repo, registered as a real ADK `Plugin`), but the one live run on
record had never actually gotten past the root agent — every real delegation
attempt failed closed. This document records the root cause, the fix, and two
fresh live runs that prove it now works.

## Root cause

ADK exposes LLM-driven agent delegation (`user_proxy_agent -> front/mid/back
office router`, `router -> workflow`) as a synthetic function-tool call named
`transfer_to_agent(agent_name: str)` — not as a direct agent invocation. The
plugin's `before_tool_callback` treated it like any other business tool: it
looked up a Task 3-generated tool PEP for `transfer_to_agent` and found none
(Task 2's scanner never sees this name — it's ADK framework plumbing, not
application source code), so the default-deny path fired:

```json
{"event_type": "TOOL_AUTHORIZATION", "target_runtime_id": "transfer_to_agent",
 "reason": "NO_GENERATED_PEP_FOR_NATIVE_PATH", "source": "LOCAL_DEFAULT_DENY",
 "allowed": false, "would_block": true}
```

This blocked the LLM's very first attempt to hand off out of the root agent,
on every real message, in every prior run. The actual agent-route PEPs
(`before_agent_callback` / `find_route_placement`) were correctly generated
and present the whole time — they just never got a chance to run, because
ADK never actually entered the target agent.

## Fix

`bank_adk/zero_trust/plugin.py`:

- Added `_AGENT_TRANSFER_TOOL_NAMES = {"transfer_to_agent"}`.
- `before_tool_callback` now special-cases these names and calls a new
  `_authorize_agent_transfer()`, which authorizes the handoff using the same
  `find_route_placement(caller, target)` + `AGENT_ROUTE_AUTHORIZATION` decision
  that `before_agent_callback` already uses — reusing the route PEPs that were
  already generated and already verified present, instead of requiring a new
  Task 3 concept.
- `before_agent_callback`'s existing route check is left in place unchanged:
  it still independently re-verifies the same route when the target agent is
  actually entered, which matters because some sub-agents are invoked by
  direct orchestration (`SequentialAgent`/`ParallelAgent`/custom workflow
  agents in `workflow_agents.py`) rather than through `transfer_to_agent`.
  Defense-in-depth at two boundaries, not a single point of failure.

`bank_adk/agents/front_office.py`: tightened `transaction_processing_agent`'s
instruction so that when `execute_transfer` returns `status:
"zero_trust_denied"`, the agent must truthfully report
`execution_performed: false` instead of guessing `true` in its own summary.
This was found live in the second proof run below — the security boundary
already held (the real tool never ran), but the LLM's narrative field was
misleading, which matters for a system that logs/report those fields.

Regression test added: `tests_native_zt/test_native_zero_trust_plugin.py::
test_transfer_to_agent_is_authorized_as_agent_route_not_generic_tool`.
Full suite: 10/10 passing (`pytest tests_native_zt/`).

Offline wiring probe (`verify_zero_trust_wiring.py`, no LLM call) after the
fix: `"status": "PASS"`, all route and critical-tool placements present.

## Live proof (real CLI -> real ADK Runner -> real LLM -> real agents -> real tools -> JSON)

Both runs below were produced by:

```
python run_cli.py --message "<...>" --zero-trust --zt-status
```

against the real `citi_banking_adk` app, with **no mocks** — real
`google.adk.runners.InMemoryRunner`, a real LLM call (UF Navigator gateway),
the real agent tree, and the real Task 1-5 Backplane engine
(`native_mas_runtime/engine.py`) issuing real signed permits.

### Run 1 — authorized real workflow, end to end

Message: *"What is the bank's policy on a lost debit card?"*

Full JSON result: [`proof/run1_authorized_faq_lookup.json`](proof/run1_authorized_faq_lookup.json)
Full audit trace (27 events): [`proof/run1_authorized_faq_lookup.audit.jsonl`](proof/run1_authorized_faq_lookup.audit.jsonl)

Real path actually taken, each hop individually authorized in real time:

```
INPUT_AUTHORIZATION (cli_user -> user_proxy_agent)                     ALLOW
AGENT_ROUTE_AUTHORIZATION (user_proxy_agent -> front_office_router)    ALLOW   <- previously blocked here
AGENT_ROUTE_AUTHORIZATION (front_office_router -> customer_service_chatbot_workflow)  ALLOW
AGENT_ROUTE_AUTHORIZATION (chatbot_workflow -> chatbot_intent_agent)   ALLOW
AGENT_ROUTE_AUTHORIZATION (chatbot_workflow -> knowledge_base_agent)   ALLOW
TOOL_AUTHORIZATION (knowledge_base_agent -> search_faqs) x2            ALLOW
OUTPUT_AUTHORIZATION (user_proxy_agent -> mas_output_channel)          ALLOW
```

Note the route/tool placement IDs are a mix of native synthetic PEPs
(`pep.native.route_user_proxy_agent_front_office_router`) and **real Task 2
scanner-discovered edges** (`pep.scanner.scan_edge_075_customer_service_
chatbot_workflow_chatbot_intent_agent`, `pep.scanner.scan_edge_017_
knowledge_base_agent_search_faqs`) — the actual discovered interaction graph
is authorizing a live LLM-driven run, not a placeholder.

The knowledge base agent's answer was generated by the real LLM from real
FAQ data (`bank_adk/data/faqs.json`) via the real `search_faqs` tool.

### Run 2 — unauthorized critical write, blocked before the real tool ran

Message: *"Please transfer 50 dollars from account ACC-1001 to account
ACC-1002 right now."* (no `--zt-human-approval`, no `--zt-secondary-
authorization`, no `--zt-change-ticket`)

Full JSON result: [`proof/run2_blocked_critical_transfer.json`](proof/run2_blocked_critical_transfer.json)
Full audit trace (27 events): [`proof/run2_blocked_critical_transfer.audit.jsonl`](proof/run2_blocked_critical_transfer.audit.jsonl)

The LLM independently decided to call `execute_transfer` for real. The
decisive event:

```json
{"event_type": "TOOL_AUTHORIZATION", "decision": "MANUAL_REVIEW",
 "allowed": false, "would_block": true, "permit_id": null,
 "reason": "TASK4_MANUAL_REVIEW", "target_runtime_id": "execute_transfer",
 "placement_id": "pep.customer_transaction.execute_transfer"}
```

The real Task 4 PDP made a contextual decision (`MANUAL_REVIEW`, not a bare
allow/deny) against the real critical-write policy. The plugin's
`before_tool_callback` returned a `zero_trust_denied` result in place of the
tool call — **the real `execute_transfer` function never executed, no real
ledger/account state changed** — and the agent (after the instruction fix)
correctly reported `"execution_performed": false"` and told the customer the
transfer was not completed. This is the native-pipeline equivalent of the
Work Plan's M6 criterion "Unauthorized requests should be blocked," now
demonstrated on the real LLM-driven path instead of only the Task 6 harness.

## Update 2026-08-26 — the five follow-up items closed out

The "Not yet established / follow-ups" list below was written right after
the first fix. All five items have now been addressed and re-verified live.

### 1. Mid-office and back-office paths, live

Both now have live proof, not just the offline wiring probe:
- Mid-office: "Internal representative here, I need the financial profile and
  loan options for customer CUST-001" -> `user_proxy_agent -> mid_office_router
  -> representative_assistant_workflow -> (parallel fan-out: financial_data_agent,
  recommender_agent, loan_agent, risk_compliance_agent) -> representative_merge_agent`.
  41 audit events, zero denials, including every `ParallelAgent` fan-out hop
  individually authorized.
- Back-office EOD: see items 5 below (same live runs cover both).

### 2. Secure by default

`run_cli.py --zero-trust` was opt-in; a user who forgot the flag ran fully
unprotected. Changed to opt-out: `--zero-trust` now defaults to **on**, and an
explicit `--no-zero-trust` is required to run without enforcement. If the
Backplane checkout can't be found, the plugin now raises with an actionable
message pointing at `--zt-backplane-root` or `--no-zero-trust`, rather than
ever silently downgrading to unprotected. Verified: bare
`python run_cli.py --message "hi" --zt-status` now shows an active
`zero_trust` block with no flag at all; `--no-zero-trust` genuinely produces
a plain, un-audited result.

### 3. Both repos still uncommitted (unchanged, on purpose)

Per instruction, nothing has been committed or pushed. `git status` in both
`Citi_P3` and `Citi_P3_Zero_Trust_Backplane` still shows all of this as
local, uncommitted work.

### 4. Shutdown segfault, root-caused and fixed

Reproduced with `PYTHONFAULTHANDLER=1`: a Windows `access violation` inside
`asyncio.proactor_events.py`'s pipe-transport `__del__`/`__repr__`, running
during interpreter-shutdown garbage collection after the transport's
underlying handle is already gone -- a known CPython-on-Windows
`ProactorEventLoop` failure mode. `run_cli.py` never spawns an MCP
subprocess (only `run_scenarios.py` does), so it's safe to set
`asyncio.WindowsSelectorEventLoopPolicy()` for this entrypoint specifically.
Verified: every real run since exits `0` cleanly, no access violation.

### 5. A full authorized critical write, live

`run_cli.py --message "Please run the scheduled end-of-day batch processing
for batch EOD-2026-04-21-CLEAN, including posting the ledger update."
--zt-human-approval --zt-secondary-authorization --zt-change-ticket "..."`
ran the complete real EOD workflow: `validate_eod_readiness -> get_eod_batch
-> apply_ledger_updates (CRITICAL, real signed permit, ALLOW_WITH_OBLIGATIONS)
-> get_reconciliation_data -> store_report (real report id generated)`.
45 audit events, every one an explicit real PDP decision, zero denials. This
is the local sqlite dev database (`bank_adk/.runtime/banking.db`), not the
separate FastAPI backend used by `integrated_demo`'s real-write mode.

## A repeatable way to verify this claim: `verify_native_zero_trust_e2e.py`

Manually re-running `run_cli.py` by hand each time isn't a durable way to
answer "is this actually integrated" -- so all of the scenarios above are now
codified as an automated, live (non-mocked) verification harness:

```
D:\Lab\Citi_P3\citi_banking_adk\verify_native_zero_trust_e2e.py
```

Run it with:

```powershell
cd D:\Lab\Citi_P3\citi_banking_adk
.\.venv\Scripts\python.exe verify_native_zero_trust_e2e.py
```

What it does, and why each design choice matters for actually answering the
"is this real" question rather than just looking like it does:

- It calls `bank_adk.runner.run_message()` directly -- the same real
  `google.adk` `App`/`InMemoryRunner`, real LLM, real agent tree, real
  Task 1-5 engine used by `run_cli.py`. No mocks (contrast with
  `tests_native_zt/`, which mocks `google.adk` and the engine to test the
  plugin's own callback logic in isolation).
- Every check is graded against the plugin's own JSONL **audit trail**, not
  the LLM's free-text answer -- the LLM's wording is non-deterministic, the
  audit trail is the plugin's authoritative record of every authorization
  decision it made (subject, resource, action, decision, permit id, PDP
  latency, timestamp).
- It has a named check specifically for the bug this document exists to
  record: `no boundary fell through to NO_GENERATED_PEP_FOR_NATIVE_PATH` --
  if that regresses (a future ADK upgrade renames `transfer_to_agent`, a new
  agent gets added without a route PEP, etc.), this fails loudly instead of
  silently fail-closing again.
- It distinguishes a **precondition** ("did the real LLM actually decide to
  call this exact tool this run") from a **security check** ("was that call
  handled correctly"). LLM tool-choice is not deterministic -- the same exact
  message can act differently across runs (observed live: one run of the
  unauthorized-transfer message asked a clarifying question instead of
  calling `execute_transfer`). A failed precondition retries the same
  scenario (`max_attempts=3` on the three scenarios that depend on this); a
  failed security check is reported immediately and is never retried, so a
  real Zero Trust failure can never be "retried away."
- Five scenarios cover: an authorized read-only path (front office FAQ), an
  unauthorized critical write blocked (front office transfer), a parallel
  fan-out workflow (mid office), a critical write blocked without approval
  (back office EOD), and the same critical write allowed once approval +
  secondary authorization + a change ticket are supplied (back office EOD).
- Exit code `0` iff every scenario's checks passed; a full JSON report is
  written to `native_zero_trust_e2e_report.json` for the record. A snapshot
  of the last full clean run is at
  [`proof/verify_e2e_console_output_final.txt`](proof/verify_e2e_console_output_final.txt)
  and [`proof/verify_e2e_report_final.json`](proof/verify_e2e_report_final.json)
  (all 5 scenarios PASS, `OVERALL: PASS`, exit 0).

Flags: `--only name1,name2` to run a subset; `--skip-critical-writes` to
avoid touching `apply_ledger_updates`/`execute_transfer` at all (still makes
real LLM calls, but skips the two scenarios that write to the local dev DB).

This does not replace human judgment about what "integrated" should mean for
a given claim (e.g. it does not by itself cover the separate FastAPI-backend
real-write mode that `integrated_demo` uses, or a production deployment's
default configuration) -- but it does mean the claim "Zero Trust is wired
into the real MAS, catches real unauthorized critical writes, and allows
real authorized ones" is now falsifiable and re-checkable in about 2-4
minutes, on demand, by anyone with this repo and an LLM key, rather than
resting on a one-off manual demonstration.

## What this does and does not establish

**Established:** the native ADK plugin genuinely intercepts a real CLI
message end to end — input, multi-hop LLM-driven agent delegation, a real
business tool call, and the final JSON output — using the real Task 1-5
Backplane engine, and both the "authorized request completes" and
"unauthorized critical write is blocked" cases are now proven with live
traces, not mocks.

**Resolved as of the 2026-08-26 update above:** items 1, 2, 4, and 5 from the
original list (mid/back-office live proof, secure-by-default CLI, the
shutdown segfault, and a live authorized critical write) are done and
re-verified via `verify_native_zero_trust_e2e.py`. Item 3 (commit/push) is
intentionally still open per explicit instruction not to commit yet.

**Still genuinely open:**
1. Coverage is five hand-picked scenarios, not exhaustive. Each office has
   exactly one message tested per branch (e.g. mid-office's planning
   workflow, as opposed to its representative-assist workflow, has only the
   offline wiring probe, not a live run); the back-office exception branch
   (`reconciliation -> exception_agent -> create_exception_case`, using the
   `EOD-2026-04-21-MISMATCH` batch) is untested live.
2. This entire native integration (`bank_adk/zero_trust/`, the `app.py` /
   `runner.py` / `run_cli.py` changes in Citi_P3, and `native_mas_runtime/`
   here, plus `verify_native_zero_trust_e2e.py`) is **uncommitted** in both
   repos' working trees, by instruction. It exists on this machine only
   until someone commits and pushes it.
3. `--no-zero-trust` still exists as an explicit escape hatch (necessary for
   local debugging/comparison) -- "secure by default" here means "on unless
   a human explicitly opts out for this one invocation," not "impossible to
   disable." A deployment that wraps `run_cli.py` should not expose that flag
   to untrusted callers.
4. The separate FastAPI-backend real-write mode that `integrated_demo` uses
   (`execute_transfer`/`apply_ledger_updates` calling out to
   `citi_banking_backend` over HTTP rather than the local sqlite dev DB) is
   untouched by this native-plugin work and has its own, previously-existing
   Task 6 harness-driven proof only.
5. ~~`verify_native_zero_trust_e2e.py`'s retry logic ... has not itself been
   stress-tested against a real regression~~ -- **done.** `_AGENT_TRANSFER_TOOL_NAMES`
   was temporarily emptied (reintroducing the exact original bug) and
   `verify_native_zero_trust_e2e.py --only front_office_faq` was re-run live:
   it correctly reported `OVERALL: FAIL` on the very first attempt, with the
   `no boundary fell through to NO_GENERATED_PEP_FOR_NATIVE_PATH` check
   showing the exact real denial events, no retry, no false pass. The fix
   was then restored and the same scenario re-ran to a clean `PASS`. The
   harness demonstrably catches the regression it exists to catch.
