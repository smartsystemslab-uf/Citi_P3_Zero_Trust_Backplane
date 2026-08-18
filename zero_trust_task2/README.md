# Task 2 — Generic Multi-Agent System Scanner and Interaction-Graph Generator

Task 2 automatically inspects a multi-agent system repository and converts the discovered architecture into draft Zero Trust Intermediate Representation (ZT-IR) artifacts for Task 3.

The upgraded scanner is intentionally **repository-agnostic**. It no longer assumes one fixed source-tree layout. It recursively discovers source and configuration files, applies multiple scanner strategies, and records interfaces it cannot resolve instead of silently dropping them.

## Task 2 goals

Task 2 is responsible for answering:

- Which agents and workflow components exist?
- Which tools can each agent invoke?
- Which APIs exist and which tools call them?
- Which persistent resources exist and which APIs access them?
- Which event or scheduled entry points exist?
- What are the agent-to-agent, agent-to-tool, tool-to-API, API-to-data, and event-to-agent interaction paths?
- What action, data type, risk, side effect, authentication assumption, trust boundary, and workflow context should be attached to each discovered edge?
- Which interfaces could not be statically resolved and therefore require manual review, a new scanner plugin, or runtime introspection?

## Major capabilities

### 1. Generic repository discovery

The scanner recursively examines the supplied repository instead of relying on hard-coded directories.

It automatically discovers:

- Python source files
- YAML / YML configuration files
- JSON configuration files
- OpenAPI / Swagger documents
- MCP-style manifests and server configurations

Common generated or environment directories are skipped automatically, including:

```text
.git
.venv
venv
node_modules
__pycache__
dist
build
site-packages
```

Additional directory names can be excluded with `--exclude-dir`.

### 2. Python agent discovery

The scanner recognizes common constructors such as:

```text
LlmAgent
SequentialAgent
ParallelAgent
Agent
BaseAgent
ConversableAgent
AssistantAgent
UserProxyAgent
RouterAgent
WorkflowAgent
```

It also recognizes framework-specific constructors when their structure strongly suggests an agent, for example:

```python
worker = CustomAgent(
    name="worker_agent",
    tools=[lookup_profile],
)
```

The scanner extracts:

- runtime agent identity
- source variable / symbol alias
- role
- domain
- tools
- child agents / sub-agents
- workflow relationships
- source location

### 3. Agent factory and alias resolution

A major upgrade is interprocedural alias resolution.

For example:

```python
workflow_alias = build_workflow(worker_agent=worker)
router = LlmAgent(
    name="router_agent",
    sub_agents=[workflow_alias],
)
```

If `build_workflow()` statically returns an agent named `generic_flow`, Task 2 resolves:

```text
workflow_alias -> generic_flow
```

This prevents a local Python variable name from being incorrectly treated as a different runtime identity.

The scanner also resolves unique factory-parameter bindings when possible.

### 4. Tool discovery

A public function can be recognized as a tool when it is:

- decorated with a known tool decorator,
- located in a tool/plugin/action/capability module, or
- explicitly referenced by a discovered agent.

Supported examples include:

```python
@tool
@mcp.tool()
@server.tool()
@function_tool
@register_tool
```

Private helper functions such as `_load()` are not treated as tools unless explicitly registered or referenced.

For each tool, Task 2 infers:

- action type
- read / write / state-change / high-impact write class
- side effects
- risk level
- audit requirement
- outbound HTTP calls
- source type

### 5. API discovery

Task 2 scans Python route decorators across the entire repository.

Supported patterns include FastAPI- and Flask-style forms such as:

```python
@app.get("/items/{item_id}")
@router.post("/actions")
@app.route("/items", methods=["GET", "POST"])
@router.api_route("/items", methods=["PATCH"])
```

The scanner extracts:

- HTTP method
- path
- operation identity
- domain
- side-effect classification
- risk
- inferred data access

Dynamic route paths that cannot be statically resolved are added to the unresolved-interface report.

### 6. OpenAPI / Swagger parsing

The scanner automatically recognizes structured specifications containing:

```yaml
openapi: 3.x
paths:
  ...
```

or Swagger equivalents.

It extracts operations from:

- `paths`
- HTTP methods
- `operationId`
- security declarations
- tags
- server URLs

These operations are merged with Python-discovered APIs while preserving stable operation IDs.

### 7. MCP manifest parsing

Task 2 can statically discover tools from MCP-style JSON/YAML manifests when tools are enumerated.

Example:

```yaml
protocol: mcp
name: example-server
tools:
  - name: get_record
    description: Fetch one record
```

It also recognizes server configurations such as:

```json
{
  "mcpServers": {
    "remote": {
      "command": "python",
      "args": ["server.py"]
    }
  }
}
```

When an MCP server is configured but does **not** statically enumerate its tools, the scanner records:

```text
mcp_runtime_introspection_required
```

This is deliberate: the interface is not silently treated as complete. A future runtime MCP `tools/list` scan can resolve it.

### 8. Database / persistent-resource discovery

Task 2 recognizes common ORM-style model declarations, including SQLAlchemy-, SQLModel-, and Django-like patterns.

For example:

```python
class Customer(Base):
    __tablename__ = "customers"
```

The scanner extracts:

- model name
- table/resource name
- fields
- sensitivity classification
- PII indicators
- high-impact data indicators
- audit-resource indicators

The scanner also maps ORM model names back to actual table IDs when building API-to-data edges.

### 9. Event and trigger discovery

Task 2 recognizes explicit event handlers and scheduled/trigger entry points, including patterns such as:

```python
@app.on_event("startup")
def startup():
    ...
```

and common listener / subscription / scheduled-job decorators.

When an event handler directly invokes a discovered agent, Task 2 produces an:

```text
event_to_agent
```

interaction edge.

### 10. Interaction-graph generation

The scanner currently generates these edge types:

```text
agent_to_agent
agent_to_tool
tool_to_api
api_to_database
event_to_agent
```

Each edge includes:

```text
caller / from_id
target / to_id
action
data_type
risk_level
side_effects
authentication_method
trust_boundary
workflow_context
PEP requirement
PEP type
HTTP method / DB operation when applicable
operation class
```

These fields provide Task 3 with the information needed for PEP placement.

## Risk and sensitivity inference

Task 2 uses deterministic rule-based inference rather than an ML classifier.

Examples:

```text
get_ / list_ / search_ / read_       -> read
calculate_ / forecast_ / analyze_    -> compute
create_ / update_ / persist_         -> state_change
transfer / ledger / payment write    -> financial/high-impact write
GET                                   -> read
POST / PUT / PATCH / DELETE           -> state change
```

Data classification is also inferred from resource and field names. Examples include customer/profile/account/transaction data, identity fields, audit data, and credential-like fields.

Task 3 performs its own sensitivity decision using this metadata plus the unified manifest. Task 2's `coverage_percent` is therefore **scanner-resolution coverage**, not PEP security coverage.

## Unresolved-interface detection

One of the most important upgrades is that unsupported patterns are no longer silently ignored.

Task 2 writes:

```text
unresolved_interfaces.yaml
```

Examples include:

- unknown agent constructors
- agent constructors without a stable identity
- agent references that cannot be resolved
- tool references that cannot be resolved
- dynamic HTTP destinations
- HTTP destinations without a discovered API
- dynamic API route definitions
- database/model references without a discovered resource
- MCP server configurations requiring runtime introspection
- structured interface configurations with an unknown schema
- Python or structured-file parse failures

Example finding:

```yaml
- category: unknown_agent_constructor
  file: src/custom_agent.py
  line: 18
  symbol: MysteryAgent
  suspected_type: agent_constructor
  confidence: medium
  reason: >
    Call name suggests an agent constructor but it did not expose
    recognized agent metadata.
```

This means a new or proprietary framework does not disappear from the scan. It becomes an explicit gap that can be reviewed or supported by adding another scanner strategy.

## Output files

The scanner preserves the original Task 2 output contract and adds event/unresolved artifacts.

```text
<output-parent>/
├── coverage_report.yaml
├── unresolved_interfaces.yaml
└── draft_manifests/
    ├── agents_draft.yaml
    ├── tools_draft.yaml
    ├── apis_draft.yaml
    ├── databases_draft.yaml
    ├── events_draft.yaml
    └── interaction_edges_draft.yaml
```

### `agents_draft.yaml`
Discovered agents, aliases, tools, routing relationships, and source metadata.

### `tools_draft.yaml`
Discovered callable capabilities, action types, risk, side effects, and outbound API calls.

### `apis_draft.yaml`
Python- and OpenAPI-discovered HTTP operations.

### `databases_draft.yaml`
Discovered persistent resources and sensitivity metadata.

### `events_draft.yaml`
Discovered event / trigger entry points.

### `interaction_edges_draft.yaml`
The ZT-IR interaction graph consumed by the integration layer and Task 3.

### `unresolved_interfaces.yaml`
Everything that appears security-relevant but cannot be safely mapped into the current ZT-IR automatically.

### `coverage_report.yaml`
Discovery counts plus scanner-resolution coverage.

## How to run

Task 2 requires Python 3.11+ and PyYAML.

From the Backplane project root:

```powershell
python zero_trust_task2/zt_scan.py `
  --repo-root "D:\path\to\multi_agent_system" `
  --output-dir "zero_trust_task2\output\draft_manifests"
```

Linux/macOS:

```bash
python zero_trust_task2/zt_scan.py \
  --repo-root /path/to/multi_agent_system \
  --output-dir zero_trust_task2/output/draft_manifests
```

Print unresolved findings directly in the terminal:

```bash
python zero_trust_task2/zt_scan.py \
  --repo-root /path/to/multi_agent_system \
  --output-dir zero_trust_task2/output/draft_manifests \
  --print-unresolved
```

Exclude an additional generated directory:

```bash
python zero_trust_task2/zt_scan.py \
  --repo-root /path/to/multi_agent_system \
  --output-dir zero_trust_task2/output/draft_manifests \
  --exclude-dir generated \
  --exclude-dir artifacts
```

## Strict unresolved mode

Normal mode always writes the scan results and returns successfully even when unresolved interfaces exist.

For CI/security-gate usage:

```bash
python zero_trust_task2/zt_scan.py \
  --repo-root /path/to/multi_agent_system \
  --output-dir zero_trust_task2/output/draft_manifests \
  --strict-unresolved
```

In strict mode, Task 2 still writes all output files, but exits with code `2` if any unresolved interfaces remain.

This is useful when the desired policy is:

> Do not declare the system model complete while any discovered interface remains unresolved.

## Using Task 2 with the integrated Backplane demo

The existing integration command remains compatible:

```powershell
python integrated_demo/run_demo.py --clean `
  --banking-repo "D:\path\to\multi_agent_system" `
  --scanner-graph
```

The command-line option retains its historical name for compatibility, but the scanner itself is generic and operates on a multi-agent system repository.

With `--scanner-graph`, Task 3 consumes the interaction graph generated by this upgraded Task 2 scanner.

## Validation

Task 2 includes scanner tests under:

```text
zero_trust_task2/tests/test_task2_scanner.py
```

Run:

```bash
python -m pytest -q zero_trust_task2/tests
```

The tests cover:

- arbitrary repository layouts
- framework-specific agent constructors
- factory / alias resolution
- agent-referenced tool discovery
- OpenAPI parsing
- MCP manifest parsing
- MCP runtime-introspection gaps
- event-to-agent discovery
- database discovery
- unresolved-interface reporting
- private-helper filtering

## Current static-analysis boundary

No static scanner can fully infer arbitrary runtime-generated architecture.

Examples that may remain unresolved include:

- interfaces constructed entirely through reflection
- runtime plugin loading from remote sources
- dynamically generated URLs with no stable path component
- agents created from encrypted or external configuration
- MCP servers that expose their tool list only at runtime
- framework behavior hidden behind code generation or native extensions

The important Task 2 behavior is therefore:

```text
Recognized form  -> convert to ZT-IR
Unknown form     -> preserve in unresolved_interfaces.yaml
```

rather than silently assuming an unknown path does not exist.
