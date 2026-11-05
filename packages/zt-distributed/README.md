# zt-distributed — distributed runtime (any ADK application, SPIFFE scheme B, signed PSL policies)

The distributed runtime runs every agent (and every graph workflow) of a protected ADK application in
its own container.
The Zero Trust Backplane sits between them as a network PEP, the gateway, so every hop passes
through it. The application is the one named by a `zt_adk.yaml` profile (see the main README,
§2–§3); it runs unchanged.

```text
ingress-client --mTLS(SVID)--> zt-gateway --mTLS--> wl-<agent> (one ADK agent or graph workflow per workload)
                                  ^   |
     agent --mTLS(SVID) + agent certificate + RFC 9421 signature (agent routes, MCP tools/call)
                                      +--> zt_adk engine: PDP + Permit Lease,
                                           signed PSL store of the bundle, tool host
SPIRE server/agent (x509pop node, docker + unix workload attestation) issues every SVID;
agent-issuer (its own Agent CA) issues agent certificates bound to the workload SVID.
```

## How the application is distributed

* **One image per application.** `zt-distributed build` stages the application
  (`distributed.app_paths`) and installs its requirements first; they decide the ADK version and
  every other version the application depends on. It then installs the Backplane packages with
  the versions the application installed as constraints: pip fits the Backplane around them or
  the build fails with the conflict -- it never changes a package the application installed.
  Inside the image, `zt_distributed.describe` imports the application and derives the deployment
  (one workload per agent and graph workflow, entry agents, workload UIDs, SPIFFE IDs). The
  deployment therefore always matches the code that will run.
* **One agent per workload.** A workload hosts exactly one agent of the application's tree
  (`remote.host_agent`). Everything around that agent is replaced by a remote proxy that calls
  the gateway, signed with the workload's credentials:

  | around the agent | replaced by |
  |---|---|
  | sub-agents, workflow steps, custom-agent children | `RemoteAgentProxy` |
  | the parent, for transfers | `RemoteLlmParentProxy` |
  | function tools, long-running and custom tools | `RemoteFunctionTool` |
  | the tools of a toolset (MCP, OpenAPI, custom) | `RemoteDeclaredTool`, one per tool the gateway's tool list declares for the agent |
  | `AgentTool`s | `RemoteAgentTool` |

  ADK runs the agent as usual: transfers, workflows, `output_key`, state, events.
* **Graph workflows (ADK 2.x).** A graph workflow runs in its own workload with ADK's node
  runner: its graph and its function, join and custom nodes run there. Each agent node, nested
  workflow and agent a function node starts with `ctx.run_node` is a `RemoteNodeProxy`: the node's
  workload runs it with ADK's node runner under the same node path and run id, with the node's
  input, isolation scope and branch, so input event, history filtering and output are the same as
  in one process (events of a nested workflow's own nodes are enqueued as their runners would).
  The graph's tool nodes run in the tool host as tools of the workflow.
* **The application's own plugins run in every workload.** Their agent, model and tool callbacks
  fire around the hosted agent as in one process. A run of the distributed application is
  coordinated by the gateway, not by one ADK Runner, so run-level callbacks (`on_user_message`,
  `before_run`, `on_event`, `after_run`) fire only for `AgentTool` invocations, which are a
  Runner run of their own.
* **A function the hosted agent does not have** (a hallucinated tool, another agent's tool) is
  refused in the workload instead of failing the invocation: the model receives a denial, the
  workload counts it (`undeclared_function_refused`) and reports an event. Nothing reaches the
  gateway: every tool a workload can call is a proxy of a call the gateway authorizes.
* **Tools run in the gateway's tool host.** The tool host uses the application's own tool
  objects, with a real ADK `ToolContext`; the state delta goes back to the caller. It resolves the
  application's toolsets itself, so no agent container connects to an MCP server or API. A
  workload sees its tools over MCP (Streamable HTTP, official SDK 1.x or 2.x: whatever the
  application installed; `zt_distributed.mcp_compat`), named `<agent>__<tool>`. The arguments
  reach the tool exactly as the model produced them, as in one process (no schema validation in
  front of the tool). The data volumes and secrets of the tools exist only in the gateway.
* **Conversations live at the gateway.** The ingress sends one message per turn. The gateway
  keeps the conversation and resumes at the agent ADK itself would choose.

## Identity: SPIFFE scheme B

* **Workload.** Each workload has an X.509-SVID from SPIRE, verified on every connection (mTLS).
  The selectors are the compose label, the compose project and a distinct UID per container.
* **Agent.** Each agent has a certificate from the agent issuer, a CA of its own and never the
  SPIRE CA. The certificate is bound to the workload's SPIFFE ID. Every HTTP request is signed
  (RFC 9421 with content digest, nonce and replay window).
* **Gateway checks.** The gateway checks the registry: whether the agent is enabled, its revoked
  serials and its allowed workloads.
* **PDP checks.** The verified result reaches the PDP inside a signed authentication assertion.
  The PDP re-checks it (`20_identity.psl`): a scheme-B agent request is decided only if both
  factors were verified and the assertion names the request's agent.
* **Registry changes.** `admin disable` or `admin enable` bumps the agent's identity version,
  which revokes its outstanding Permit Leases and blocks dispatch to a disabled agent.
* **A valid identity is not enough.** A workload is refused when it uses its own credentials for
  a tool or route that:
  * lies outside its generated placements;
  * lies outside a run the gateway dispatched to it;
  * violates the signed policies.

  `zt_distributed.probe` and the functional tests demonstrate this.

## Policies: the bundle's signed PSL store

`prepare` builds the protection bundle inside the image, from the image's application and its
staged profile, with fresh deployment keys. The gateway enforces it:

| where | PSL scope | rules |
|---|---|---|
| PDP (every route, tool, input and output authorization) | `pdp_request` | approvals, least-privilege permits, domains, identity, owner overlays |
| gateway ingress | `input_message`, `output_message` | session, roles, prompt injection, PII and secret detectors |
| gateway tool path | `tool_call`, `tool_result`, `agent_message` | role restrictions, result detectors, injection |
| engine monitors | `workflow_run` | workflow order, owner prerequisites |
| PSL guard (tool path) | `request_attempt`, `operation`, `workflow_participation` | `50_gateway_runtime.psl` properties (see below) |

The `50_gateway_runtime.psl` properties:

* identity;
* PDP decision and permit binding;
* no execution after a denial;
* at-most-once critical writes;
* participation;
* live lease and credential;
* write-ahead audit.

Every tool runs only with a single-use PSL admission ticket. Its pre-execution audit record is
written (with fsync for critical tools) before it starts.

## Run

The SPIRE release tarball must be downloaded once into `deploy/vendor/`; the steps are in
`deploy/vendor/README.md`. After that:

```powershell
zt-distributed build --project examples\helpdesk_mas\zt_adk.playback.yaml
zt-distributed prepare
zt-distributed start
zt-distributed run -m "Look up user alice" -m "Unlock the account of alice" --role employee
zt-distributed approvals list          # show | approve ID --approver NAME | deny | wait
zt-distributed admin disable account_agent
zt-distributed verify
zt-distributed stop                    # --purge also removes the volumes
python -m pytest packages\zt-distributed\tests\unit
python -m pytest packages\zt-distributed\tests\functional         # needs build + prepare
```

How the commands behave:

* **One application at a time.** `--project` names the application (a directory with
  `zt_adk.yaml`, or the file); later commands reuse it.
* **Only one compose project is touched.** That is the project named in
  `distributed.compose_project`, `citi_p3_ztbp` by default.
* **Secrets are never baked into the image.** `.env`, `.zt` and the dev keys are excluded at
  build time, and the image build fails if one slips in. Model keys (`secret_env_files`) reach
  only the agent workloads, and tool secrets (`tool_host_secret_env_files`) only the gateway;
  compose reads both at start.

### The application's side

All of this is configured in the profile's `distributed` section:

| need of the application | profile setting |
|---|---|
| backends its tools call | `services` |
| databases | `data_volumes` (with `tool_host_environment`) |
| one-time setup | `setup_command` |

The application's code stays as it is. A profile kept outside the application's tree works too:
`app_paths` may be absolute or use `${VAR}`. Such entries are staged under `_ext/`, and the
profile's paths are rewritten to match (`zt_distributed/staging.py`).

## Layout

```text
src/zt_distributed/  ctl (the zt-distributed command) and stack (image, compose, lifecycle), deployment
                  (describe), appload, staging, remote proxies + hosting (workload_runtime), agent_service,
                  gateway + gateway_engine, MCP server/client (mcp_compat: SDK 1.x / 2.x), PSL guard, prepare,
                  ingress client,
                  verify_state, probe, loopback (in-process wiring used by the hosting tests)
deploy/           runtime Dockerfile template (+ allowlist .dockerignore), SPIRE image and config,
                  vendored SPIRE release (the runtime's dependencies are in pyproject.toml)
tests/unit/       hosting == in-process (agent trees, toolsets, graph workflows), MCP layer, staging,
                  gateway monitors, PSL guard
tests/functional/ end-to-end tests against the Docker deployment of the example application
runtime/          generated (git-ignored): staged app, compose file, deployment, public material, state
results/          live logs and functional-test evidence
```
