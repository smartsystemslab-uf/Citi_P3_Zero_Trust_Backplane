# zt-scanner — static multi-agent system scanner and interaction-graph generator

The static scanner automatically inspects a multi-agent system repository and converts the discovered architecture into draft Zero Trust Intermediate Representation (ZT-IR) artifacts for the PEP generator (zt-pep).

Run it as `zt-scan --repo-root SRC --output-dir OUT` (or `python -m zt_scanner ...`); `zt-adk build` runs it to
cross-check the live object graph against the source.

The upgraded scanner is intentionally **repository-agnostic**. It no longer assumes one fixed source-tree layout. It recursively discovers source and configuration files, applies multiple scanner strategies, and records interfaces it cannot resolve instead of silently dropping them.

## Goals

The static scanner is responsible for answering:

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

If `build_workflow()` statically returns an agent named `generic_flow`, static scanner resolves:

```text
workflow_alias -> generic_flow
```

This prevents a local Python variable name from being incorrectly treated as a different runtime identity.

The scanner also resolves unique factory-parameter bindings when possible.

**Domain of factory-built agents.** An agent's domain (`front` / `mid` / `back` / `root` /
`shared`) comes from its source path. Factory-built workflow agents usually live in a generic
module (for example `agents/workflow_agents.py`), so the path alone says `shared` even though one
office's router attaches them. After alias resolution the scanner therefore gives such an agent
the office domain of its parents when it has at least one parent and **all** of its parents are
in the same office domain; this is iterated so nested workflows (router -> workflow -> parallel
agent) follow their parent. Parents in different domains, or only the root / `shared` parents,
leave the agent `shared` -- nothing is guessed. Every inherited domain is recorded on the agent
as `domain_source` ("inherited from parent agent(s): ..."). The PSL rule
`intent.no-cross-domain-transfers` depends on these domains.

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

For each tool, static scanner infers:

- action type
- read / write / state-change / high-impact write class
- side effects
- risk level
- audit requirement
- outbound HTTP calls
- source type

### 5. API discovery

The static scanner scans Python route decorators across the entire repository.

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

The static scanner can statically discover tools from MCP-style JSON/YAML manifests when tools are enumerated.

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

The static scanner recognizes common ORM-style model declarations, including SQLAlchemy-, SQLModel-, and Django-like patterns.

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

The static scanner recognizes explicit event handlers and scheduled/trigger entry points, including patterns such as:

```python
@app.on_event("startup")
def startup():
    ...
```

and common listener / subscription / scheduled-job decorators.

When an event handler directly invokes a discovered agent, static scanner produces an:

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

These fields provide PEP generator with the information needed for PEP placement.

## Risk and sensitivity inference

The static scanner uses deterministic rule-based inference rather than an ML classifier.

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

The PEP generator performs its own sensitivity decision using this metadata plus the unified manifest. the static scanner's `coverage_percent` is therefore **scanner-resolution coverage**, not PEP security coverage.

## Unresolved-interface detection

One of the most important upgrades is that unsupported patterns are no longer silently ignored.

The static scanner writes:

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

The scanner preserves the original static scanner output contract and adds event/unresolved artifacts.

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
The ZT-IR interaction graph consumed by the integration layer and PEP generator.

### `unresolved_interfaces.yaml`
Everything that appears security-relevant but cannot be safely mapped into the current ZT-IR automatically.

### `coverage_report.yaml`
Discovery counts plus scanner-resolution coverage.

## How to run

The static scanner requires Python 3.11+ and PyYAML.

From the Backplane project root:

```powershell
zt-scan `
  --repo-root "D:\path\to\multi_agent_system" `
  --output-dir "packages\zt-scanner\output\draft_manifests"
```

Linux/macOS:

```bash
zt-scan \
  --repo-root /path/to/multi_agent_system \
  --output-dir packages/zt-scanner/output/draft_manifests
```

Print unresolved findings directly in the terminal:

```bash
zt-scan \
  --repo-root /path/to/multi_agent_system \
  --output-dir packages/zt-scanner/output/draft_manifests \
  --print-unresolved
```

Exclude an additional generated directory:

```bash
zt-scan \
  --repo-root /path/to/multi_agent_system \
  --output-dir packages/zt-scanner/output/draft_manifests \
  --exclude-dir generated \
  --exclude-dir artifacts
```


### Runtime-only source filtering

By default, static scanner scans the runtime architecture and excludes conventional test/build sources such as `tests/`, `test_*.py`, `*_test.py`, `.venv/`, `build/`, and `dist/`. This prevents test fixtures and helper code from being mistaken for production agents, tools, or interfaces.

To intentionally include test sources while validating the scanner itself, add:

```powershell
--include-tests
```

### Tool collection aliases and dynamic tools

The scanner resolves static collection aliases such as:

```python
agent_tools = [tool_a, tool_b]
agent = LlmAgent(name="worker", tools=agent_tools)
```

into the real tool identities. Runtime-generated collections such as `agent_tools.append(wrapper)` are recognized as dynamic tool sources and are not misreported as a literal tool named `agent_tools` or `wrapper`.

### False-positive suppression

Database inference distinguishes ORM model arguments from scalar identifiers. For example, `db.get(BranchWorkload, branch_id)` records `BranchWorkload` as the model and does not report `branch_id` as a missing table. HTTP/tool discovery also ignores test-only sources by default.

## Strict unresolved mode

Normal mode always writes the scan results and returns successfully even when unresolved interfaces exist.

For CI/security-gate usage:

```bash
zt-scan \
  --repo-root /path/to/multi_agent_system \
  --output-dir packages/zt-scanner/output/draft_manifests \
  --strict-unresolved
```

In strict mode, static scanner still writes all output files, but exits with code `2` if any unresolved interfaces remain.

This is useful when the desired policy is:

> Do not declare the system model complete while any discovered interface remains unresolved.

## Using static scanner with the integrated Backplane demo

The existing integration command remains compatible:

```powershell
python legacy/citi_p3/integrated_demo/run_demo.py --clean `
  --banking-repo "D:\path\to\multi_agent_system" `
  --scanner-graph
```

The command-line option retains its historical name for compatibility, but the scanner itself is generic and operates on a multi-agent system repository.

With `--scanner-graph`, PEP generator consumes the interaction graph generated by this upgraded static scanner.

## Validation

The static scanner includes scanner tests under:

```text
packages/zt-scanner/tests/test_scanner.py
```

Run:

```bash
python -m pytest -q packages/zt-scanner/tests
# Expected for this version: 10 passed
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

The important static scanner behavior is therefore:

```text
Recognized form  -> convert to ZT-IR
Unknown form     -> preserve in unresolved_interfaces.yaml
```

rather than silently assuming an unknown path does not exist.
