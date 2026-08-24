# Task 2 Full-Function Upgrade Report

## Status

Task 2 has been upgraded from a repository-specific Python scanner into a generic, extensible static scanner for multi-agent systems.

## Completed capabilities

- Generic recursive repository discovery
- Python agent discovery
- Framework-specific/generic agent constructor inference
- Agent factory-return and symbol-alias resolution
- Tool registration and agent-referenced tool discovery
- Private-helper filtering
- Generic FastAPI/Flask-style route discovery
- OpenAPI/Swagger parser
- MCP static manifest parser
- MCP runtime-introspection gap reporting
- ORM/persistent-resource discovery
- Event/trigger discovery
- Agent-to-agent graph generation
- Agent-to-tool graph generation
- Tool-to-API graph generation
- API-to-data graph generation
- Event-to-agent graph generation
- Rule-based action/risk/data classification
- Unknown/unsupported interface detection
- `unresolved_interfaces.yaml`
- Scanner-resolution coverage reporting
- Strict unresolved CI mode
- Backward-compatible Task 2 draft manifest outputs

## Regression result on the current multi-agent testbed

The upgraded scanner discovered:

```text
36 agents
29 tools
18 APIs
6 databases
1 event
82 interaction edges
```

It also reported 6 unresolved MCP-to-HTTP targets whose corresponding backend routes are not present in the scanned source tree.

This is expected behavior for the upgraded scanner: the paths are surfaced explicitly instead of being silently omitted.

The resulting 82-edge graph was passed into Task 3. The existing integrated Task 1-5 demo completed successfully, confirming compatibility with downstream PEP generation, PDP policy compilation, and Permit Lease enforcement.

## Automated tests

```text
6/6 Task 2 scanner tests PASS
```

The tests validate generic layouts, custom agent constructors, aliases, OpenAPI, MCP, events, databases, unknown-interface reporting, and private helper filtering.

## Meaning of "full function"

Task 2 now implements the complete prototype behavior expected from a static scanner:

```text
Repository discovery
        ↓
Known scanner strategies
        ↓
ZT-IR entities + interaction graph
        ↓
Unrecognized security-relevant forms
        ↓
Explicit unresolved-interface report
```

It does not claim that arbitrary runtime-generated behavior can always be resolved statically. When static resolution is impossible, Task 2 now records the gap so that runtime introspection or a new scanner plugin can be added without treating the system model as complete.

## Runtime-source precision update

The scanner now excludes conventional test-only sources by default, resolves static tool-list aliases, recognizes dynamic tool collections without inventing fake tool IDs, and avoids treating scalar ORM identifiers as database models. These changes reduce false-positive unresolved findings while preserving true unresolved interfaces for review.

Validation: Task 2 scanner tests = 10/10 PASS; existing Task 1-5 integration remains compatible with the expanded scanner graph.
