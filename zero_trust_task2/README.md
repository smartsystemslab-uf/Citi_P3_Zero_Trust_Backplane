# Task 2: Zero Trust Scanner and Draft Manifest Generation

This file documents the Task 2 scanner work for the Citi Banking ADK repository.
It explains what the scanner does, why AST is used, and which tools and libraries support scan and generation.

## What Task 2 does

Task 2 builds a static scanner that inspects repository source code and derives a draft zero trust system model.
The scanner discovers:

- ADK agents and routing agents
- tools available to agents
- backend API endpoints
- database models and tables
- interaction edges between agents, tools, APIs, and databases

The scanner writes draft YAML manifests for these discovered entities and a draft interaction graph.

## Why we use AST

AST stands for Abstract Syntax Tree.
It is a structured, tree-based representation of Python source code.

We use AST because it allows the scanner to analyze code without executing it.
That means we can safely inspect repository files and extract agent/tool/API/database definitions from Python syntax.

The scanner uses AST to:

- identify function calls that create agents (`LlmAgent`, `SequentialAgent`, `ParallelAgent`)
- inspect function definitions for tool declarations
- parse FastAPI route decorators and handler signatures
- detect SQLAlchemy ORM model classes and table metadata
- extract constant values, list literals, and strings from code

Using AST is the right choice for static code discovery because it is accurate enough to understand syntax and direct definitions, while avoiding the risk and complexity of running repository code.

## Tools and libraries used by the scanner

### `ast`
- Purpose: parse Python source into a syntax tree.
- Why: enables safe, static analysis of Python code structure without executing it.
- What it is used for: walking the source tree, finding function calls, decorators, class definitions, and literal values.

### `yaml` (PyYAML)
- Purpose: serialize discovered entities into YAML manifest files.
- Why: the draft manifests are stored as YAML so they are human-readable and consumable by other tools.
- What it is used for: writing `agents_draft.yaml`, `tools_draft.yaml`, `apis_draft.yaml`, `databases_draft.yaml`, and `interaction_edges_draft.yaml`.

### `argparse`
- Purpose: parse command-line arguments for the scanner.
- Why: makes the scanner runnable with `--repo-root` and `--output-dir` options.
- What it is used for: accepting runtime configuration from the user.

### `pathlib.Path`
- Purpose: handle file system paths cleanly.
- Why: path handling is simpler, more readable, and cross-platform than manual string operations.
- What it is used for: locating source files, resolving repository root, and building output paths.

### `dataclasses`
- Purpose: define small structured data holders.
- Why: makes draft entities easy to store and pass between scanner components.
- What it is used for: representing discovered entities with `DraftEntity`.

### `typing`
- Purpose: add type annotations for readability and maintainability.
- Why: helps document the scanner’s expected inputs and outputs.
- What it is used for: typing lists, optionals, dictionaries, and function return types.

### `re`
- Purpose: simple regex matching for code patterns.
- Why: useful for text-based heuristics and pattern extraction when AST alone is not enough.
- What it is used for: inferring names, paths, or data access patterns from source text.

### `os`
- Purpose: support file system operations and environment-related behavior.
- Why: used in helper logic and path normalization, especially when scanning directories.
- What it is used for: deriving source directories and integrating with the underlying OS.


## How to run the scanner

From the repository root:

```bash
python3 zero_trust/output/zt_scan.py --repo-root /home/cyrielle/Documents/CITI/Citi-Bank-P3 --output-dir zero_trust/output/draft_manifests
```

This command scans the repository and refreshes the draft manifest outputs.

## Why these tools are used together

The scanner combines static code analysis with simple manifest generation.
AST gives us the structure of Python source code, and YAML gives us a readable output format.
Standard libraries like `argparse`, `pathlib`, and `dataclasses` make the scanner easier to configure, more robust, and simpler to maintain.

Together, these tools allow Task 2 to produce a draft security model from code without requiring the code to run.

## What the scanner generates

The scanner produces the following draft output files under `zero_trust/output/draft_manifests`:

- `agents_draft.yaml`
  - discovered ADK agents, domains, routing metadata, and authorized tools
- `tools_draft.yaml`
  - discovered tool functions and their action classifications
- `apis_draft.yaml`
  - discovered FastAPI endpoints and inferred API metadata
- `databases_draft.yaml`
  - discovered SQLAlchemy model tables and data sensitivity metadata
- `interaction_edges_draft.yaml`
  - discovered relationships between agents, tools, APIs, and databases with security metadata

Additionally, the scanner produces:

- `coverage_report.yaml`
  - a summary of what the scanner discovered and which source files were covered

### `zero_trust/output/coverage_report.yaml`

- Reports scanner coverage and discovery status.
- Records which entity types were found and whether important files were scanned.
- Useful for verifying that the scanner ran successfully and what portions of the codebase were included.

### `zero_trust/output/draft_manifests/agents_draft.yaml`

- Contains discovered agent entities.
- Includes agent identifiers, descriptions, authorized tool lists, and routing metadata.
- Represents the ADK agent surface as inferred from source.

### `zero_trust/output/draft_manifests/tools_draft.yaml`

- Contains discovered tool entities.
- Includes tool identifiers, action description, and metadata about the tool capability.
- Represents Agent-callable capabilities in the codebase.

### `zero_trust/output/draft_manifests/apis_draft.yaml`

- Contains discovered backend API endpoint entities.
- Includes route paths, HTTP methods, and inferred database access patterns.
- Represents the backend surface that agents and tools may invoke.

### `zero_trust/output/draft_manifests/databases_draft.yaml`

- Contains discovered database entities.
- Includes table names, sensitivity classification, and access attributes.
- Represents persistent data assets accessed by the system.

### `zero_trust/output/draft_manifests/interaction_edges_draft.yaml`

- Contains the inferred interaction graph.
- Covers agent-to-tool, tool-to-API, API-to-database, and agent-to-agent edges.
- Each edge includes security-related metadata such as:
  - action
  - data type
  - risk level
  - side effects
  - authentication method
  - trust boundary
  - workflow context


