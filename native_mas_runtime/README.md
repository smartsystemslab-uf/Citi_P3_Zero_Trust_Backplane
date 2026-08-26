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
multi-agent handoff, the fix, and two live end-to-end runs (real CLI message
-> real ADK Runner -> real LLM -> real agents -> real tool -> JSON) proving
both an authorized workflow completing and an unauthorized critical write
being blocked.
