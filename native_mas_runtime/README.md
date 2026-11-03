# Native CITI-MAS Runtime Integration

This package is the runtime-facing layer for Task 6. It is **not** the external
workflow harness. It prepares Task 2 -> Task 5 artifacts and exposes the actual
PEP/PDP/Permit-Lease authorization calls used by the ADK plugin inside the
original CITI-MAS `App` / `InMemoryRunner` execution path.

The CITI-MAS repository imports `NativeMasBackplane` through the configured
Backplane root. The native ADK plugin then intercepts CLI input, actual agent
execution, actual tool invocation, and final JSON output.

See [`NATIVE_TASK6_INTEGRATION_PROOF.md`](NATIVE_TASK6_INTEGRATION_PROOF.md)
for the `transfer_to_agent` fail-closed bug that blocked every real
multi-agent handoff, the fix, and the live end-to-end runs (real CLI message
-> real ADK Runner -> real LLM -> real agents -> real tool -> JSON) proving
both authorized workflows completing and unauthorized/critical operations
being blocked or requiring approval.

For how to actually run this (exact commands, flags, and the automated live
verification harness) and a detailed walkthrough of the architecture -- the
bootstrap pipeline, the nine ADK lifecycle hooks and what each protects, the
Permit Lease design, the policy decision types, and the fail-closed layers --
see
[`../../Citi_P3/citi_banking_adk/NATIVE_ZERO_TRUST_README.md`](../../Citi_P3/citi_banking_adk/NATIVE_ZERO_TRUST_README.md)
in the MAS repo (that's also where `run_cli.py` and
`verify_native_zero_trust_e2e.py` live, since they run against the MAS).

## Scan cache and domains

The Task 2 scan of the MAS is cached in `<output_dir>/task2` (the ADK plugin bootstraps with
`refresh=False`; the default output directory is `native_mas_runtime/output`). The cache carries
`task2/scan_fingerprint.json` (SHA-256 of `zero_trust_task2/zt_scan.py`, line endings normalised,
and the MAS root). A cache written by a different scanner or for a different MAS root is rescanned
automatically; edits to the MAS source itself still need `refresh=True` (`--zt-refresh`).

Agent domains come from the scanner (path, or the office of the parent router for factory-built
workflow agents, see `zero_trust_task2/README.md`). Route targets recovered only from the
instantiated ADK tree are marked as agent route targets (`scanner_target_type: subject`), so the
route intent rules -- including `intent.no-cross-domain-transfers` -- apply to them as well; a
runtime route to an agent the scanner already catalogued gets the `invoke` action on that resource.
