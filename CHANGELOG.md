# Changelog

## 1.1.0

Adds the **ZT Console**, a browser interface for setting up, running and testing a protected application. It is a new,
separate package (`packages/zt-console`). No existing package, profile, policy or test is changed and the protection
behaves exactly as in 1.0.1; the root README gains section 2.9 and a layout entry.

* **Set up, run and test from a browser:** create keys, build and check the bundle; send any message as any end-user
  role, in one or several turns; state the expected outcome (boundary, rule, answer text) and get a pass or fail; save
  tests, run batches and campaigns, export the results; stop a run in progress.
* **See every decision:** what each boundary decided, with the sentence of each rule that fired; the system (agents,
  tool classification), the policies and the audit log with chain verification; held approvals (signing from the page
  only in development mode, `--dev-approve`).
* It starts the real `zt-adk` command and reads the files the Backplane writes, and holds no protection logic. It drives
  the in-process runtime only, has no user login and is meant for one local user.
* **Documentation:** `packages/zt-console/docs/ZT_CONSOLE_GUI_USER_GUIDE.md` (configuration, every page, limitations,
  what stays in the terminal) and `ZT_CONSOLE_GUI_PLACEMENT.md` (how the GUI attaches to the Backplane), each also as PDF.

Tests: 51 API and unit tests (`packages/zt-console/tests`), a 24-step browser test and an accessibility audit
(`tests/e2e`, Chrome and Node required). Verified on macOS with Python 3.12, Chrome and the scripted playback model; a
live model, Linux and Windows were not run. The suite is separate from the CI job.

## 1.0.1

Fixes two defects found by running v1.0.0 on a new ADK application (a veterinary clinic MAS on
`gpt-oss-20b`, in-process and distributed).

* **MCP stdio servers started to resolve a toolset no longer keep running.** Discovery listed a
  toolset's tools in one event loop and closed the toolset in another; ADK cannot close an MCP
  session from a different loop, so the server process started for the listing stayed alive (one
  extra process per MCP toolset in every long-running gateway) and the log showed
  `Error cleaning up session stdio_session: original event loop is closed`. Listing and closing now
  run in the same loop (`zt_adk.discovery._list_and_close`).
* **The first call after an agent is re-enabled no longer fails.** `admin disable` then `enable`
  revokes the agent's certificate. The PEP correctly refused the next request signed with it
  (`agent_cert_revoked`) and the workload re-enrolled, but the refused tool call or route was lost and
  the model received a denial. The workload now waits for the re-enrollment and sends that request
  once more with the new certificate (new request id, same tool call and idempotency key). This is
  safe because the PEP refuses such a request at authentication, before authorization or execution.
  While the agent is still disabled the issuer refuses the enrollment and nothing is retried; any
  other refusal is never retried.

Tests: `test_toolset_is_listed_and_closed_in_one_event_loop`, `test_mcp_stdio_server_started_for_discovery_exits`
(zt-adk); `test_reenroll_*` (zt-identity); `tests/unit/test_agent_reenroll.py` (zt-distributed); the
functional disable/enable test now requires every call after re-enabling to succeed.

## 1.0.0

First release: generic Zero Trust protection for any Google ADK multi-agent system (ADK 1.x and 2.x,
agent trees and graph workflows), in-process (`ZeroTrustPlugin`) and distributed (one container per
agent, SPIFFE identities, gateway PEP and tool host), with signed PSL policies.
