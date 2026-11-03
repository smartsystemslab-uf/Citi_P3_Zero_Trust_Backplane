# Distributed runtime (SPIFFE scheme B + signed PSL policies)

The original CITI-MAS ADK agents (D:\Lab\Citi_P3, unchanged), each in its own container, with
the Zero Trust Backplane as a network PEP (the gateway) in front of every hop:

```
ingress-client --mTLS(SVID)--> zt-gateway --mTLS--> wl-<agent> (one ADK agent per workload)
                                  ^   |
     agent --mTLS(SVID) + agent cert + RFC 9421 signature (MCP tools/call, agent routes)
                                      +--> in-process Task 4 PDP + Task 5 Permit Lease
                                           (native_mas_runtime engine, signed PSL store)
SPIRE server/agent (x509pop node, docker+unix workload attestation) issues every SVID;
agent-issuer (separate Agent CA) issues agent certificates bound to the workload SVID.
```

## Identity: SPIFFE scheme B only

* **Workload**: X.509-SVID from SPIRE, verified by OpenSSL on every connection (mTLS),
  selectors = compose label + compose project + distinct UID per container.
* **Agent**: agent certificate from the agent-issuer (its own CA, never the SPIRE CA), bound
  to the workload SPIFFE ID; every HTTP request is signed (RFC 9421 + content digest, nonce,
  replay window); the gateway checks the registry (enabled, revoked serials, allowed workloads).
* The verified result goes to the PDP inside the IdP-signed authentication assertion; the PDP
  re-checks it (`policy_store/identity.psl`): a scheme-B agent request is decided only if both
  factors were verified and the assertion names the request's subject.
* Registry changes (disable / enable) bump the identity version and revoke outstanding Permit Leases.

## Policies: one signed PSL store

All decisions come from `zero_trust_pdp_task4_secure/policy_store` (signed, verified at load,
re-signed with a fresh deployment key by `prepare`):

| where | PSL scope | rules |
|---|---|---|
| PDP (every route / tool / input / output authorization) | `pdp_request` | Task 4 policies, generated least-privilege policies, `intent.psl` request rules, `identity.psl` |
| gateway ingress | `gateway_input` | valid session + allowed role; prompt-injection patterns |
| gateway response | `gateway_output` | no account id / SSN / e-mail / phone; unexplained amounts flagged |
| gateway tool path | `gateway_tool` | EOD trigger only for system sessions |
| engine monitor (authorize / begin_tool / finish_tool) | `workflow_run` | `intent.psl` prerequisites (e.g. customer-service step before `execute_transfer`, validated readiness before ledger posting) |
| gateway tool-path monitor | `request_attempt`, `operation`, `workflow_batch`, `workflow_participation` | `gateway_runtime.psl`: P1-P6 (identity, PDP, permit binding, no execution after denial, at-most-once critical writes, EOD preconditions, participation, live lease/credential, write-ahead audit) |

The MAS itself only ever sees hashes of input and output; the content rules are enforced at the
gateway, where the text is. Every business function runs only with a single-use PSL admission
ticket; the pre-execution audit record is written (fsync for critical tools) before it starts.

## Layout

```
zt_distributed/   gateway, agent service, PSL guard, gateway content checks, MCP server/client,
                  backplane adapter, prepare, verify_state, ingress client, scripted model fixture
deploy/           Dockerfiles (+ allowlist .dockerignore), SPIRE config, compose generator, locks
scripts/          ctl.py / ctl.ps1 (build, prepare, start, run, verify, admin, stop), stack.py,
                  stage_mas.py (read-only staging of the MAS repo as build input)
tests/unit/       host tests: gateway monitors from the signed store, PSL guard, content checks
tests/functional/ end-to-end tests against the Docker deployment
```

## Run

```powershell
.\distributed_runtime\scripts\ctl.ps1 build       # stage MAS input, build spire/backend/runtime images
.\distributed_runtime\scripts\ctl.ps1 prepare     # fresh keys, re-signed store, SPIRE entries, golden data
.\distributed_runtime\scripts\ctl.ps1 start
.\distributed_runtime\scripts\ctl.ps1 run write --count 2
.\distributed_runtime\scripts\ctl.ps1 verify
.\distributed_runtime\scripts\ctl.ps1 unit-test        # zero_trust_identity tests inside the image
.\distributed_runtime\scripts\ctl.ps1 functional-test
.\distributed_runtime\scripts\ctl.ps1 stop
```

Only compose project `citi_p3_ztbp` (containers `ztbp-*`) is touched. The MAS repository is
read, never modified: it tracks a `.env` and a `.venv`, so `stage_mas.py` copies its source
tree without secrets, venvs, caches, databases and run outputs into `runtime/build/` (git-ignored)
and records a provenance file; the images are built from that copy. The committed development
keys of `zero_trust_pdp_task4_secure/security/dev_keys` are excluded from the image; `prepare`
generates fresh keys into a Docker volume that only the gateway mounts.

The LLM is replaced by a deterministic model-output fixture (`scripted_model.py`); agents,
instructions, tools, the ADK runner, identities, PEP/PDP, Permit Leases and monitors are real.
