from __future__ import annotations

import sys
from pathlib import Path

import yaml

TASK2_DIR = Path(__file__).resolve().parents[1]
if str(TASK2_DIR) not in sys.path:
    sys.path.insert(0, str(TASK2_DIR))

from zt_scan import run_scan  # noqa: E402


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_generic_repository_discovery_and_alias_resolution(tmp_path: Path) -> None:
    repo = tmp_path / "arbitrary_multi_agent_repo"
    write(
        repo / "src" / "actors" / "team.py",
        '''
class CustomAgent:
    def __init__(self, **kwargs):
        pass

def lookup_profile(customer_id: str):
    return customer_id

def build_flow(worker_agent):
    return SequentialAgent(name="generic_flow", sub_agents=[worker_agent])

worker = CustomAgent(
    name="worker_agent",
    description="Reads a profile",
    tools=[lookup_profile],
)
flow_alias = build_flow(worker_agent=worker)
router = LlmAgent(name="router_agent", sub_agents=[flow_alias])
''',
    )
    out = tmp_path / "out" / "draft_manifests"
    result = run_scan(repo, out)

    agents = {x.payload["agent_id"]: x.payload for x in result["agents"]}
    assert {"worker_agent", "generic_flow", "router_agent"}.issubset(agents)
    assert "flow_alias" in agents["generic_flow"].get("aliases", [])

    tools = {x.payload["tool_id"] for x in result["tools"]}
    assert "lookup_profile" in tools  # promoted because the agent references it

    edges = {(x.payload["edge_type"], x.payload["from_id"], x.payload["to_id"]) for x in result["edges"]}
    assert ("agent_to_tool", "worker_agent", "lookup_profile") in edges
    assert ("agent_to_agent", "router_agent", "generic_flow") in edges
    assert ("agent_to_agent", "generic_flow", "worker_agent") in edges


def test_openapi_and_mcp_manifest_parsers(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write(
        repo / "specs" / "openapi.yaml",
        '''
openapi: 3.0.3
info:
  title: Example Service
  version: 1.0.0
servers:
  - url: http://localhost:9000
paths:
  /records/{record_id}:
    get:
      operationId: get_record
      summary: Read record
      security:
        - bearerAuth: []
    patch:
      operationId: update_record
      summary: Update record
''',
    )
    write(
        repo / "config" / "mcp_manifest.yaml",
        '''
protocol: mcp
name: demo-mcp
tools:
  - name: get_record
    description: Fetch one record
    inputSchema:
      type: object
  - name: update_record
    description: Update one record
''',
    )
    out = tmp_path / "out" / "draft_manifests"
    result = run_scan(repo, out)

    api_ids = {x.payload["api_id"] for x in result["apis"]}
    assert {"get_record", "update_record"}.issubset(api_ids)
    tool_ids = {x.payload["tool_id"] for x in result["tools"]}
    assert {"get_record", "update_record"}.issubset(tool_ids)
    assert all(x.payload["source_type"] == "mcp_manifest" for x in result["tools"])


def test_unknown_interfaces_are_reported_not_silently_dropped(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write(
        repo / "agents.py",
        '''
def create():
    x = MysteryAgent(config=load_config())
    return x
''',
    )
    write(
        repo / "custom_system.yaml",
        '''
agents:
  - id: a
interfaces:
  - kind: proprietary_bus
''',
    )
    out = tmp_path / "out" / "draft_manifests"
    result = run_scan(repo, out)

    categories = {x.category for x in result["unresolved"]}
    assert "unknown_agent_constructor" in categories
    assert "unrecognized_interface_config" in categories
    report = yaml.safe_load((out.parent / "unresolved_interfaces.yaml").read_text(encoding="utf-8"))
    assert report["summary"]["total"] >= 2


def test_mcp_server_without_static_tools_requests_runtime_introspection(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write(
        repo / ".mcp.json",
        '''
{
  "mcpServers": {
    "remote": {
      "command": "python",
      "args": ["server.py"]
    }
  }
}
''',
    )
    out = tmp_path / "out" / "draft_manifests"
    result = run_scan(repo, out)
    assert any(x.category == "mcp_runtime_introspection_required" for x in result["unresolved"])


def test_event_and_database_discovery(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write(
        repo / "service.py",
        '''
class Base:
    pass

class Customer(Base):
    __tablename__ = "customers"
    customer_id = Column()
    ssn = Column()

worker = LlmAgent(name="worker_agent")

@app.on_event("startup")
def boot():
    worker.run()

@router.get("/customers/{customer_id}")
def get_customer(customer_id, db):
    return db.scalar(select(Customer))
''',
    )
    out = tmp_path / "out" / "draft_manifests"
    result = run_scan(repo, out)

    assert {x.payload["database_id"] for x in result["databases"]} == {"customers"}
    assert {x.payload["event_id"] for x in result["events"]} == {"event.startup"}
    edges = {(x.payload["edge_type"], x.payload["from_id"], x.payload["to_id"]) for x in result["edges"]}
    assert ("event_to_agent", "event.startup", "worker_agent") in edges
    assert any(x.payload["edge_type"] == "api_to_database" and x.payload["to_id"] == "customers" for x in result["edges"])


def test_private_helpers_are_not_tools(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write(
        repo / "pkg" / "tools" / "helpers.py",
        '''
def _load():
    return {}

def public_tool():
    return 1
''',
    )
    out = tmp_path / "out" / "draft_manifests"
    result = run_scan(repo, out)
    tool_ids = {x.payload["tool_id"] for x in result["tools"]}
    assert "public_tool" in tool_ids
    assert "_load" not in tool_ids


def test_runtime_discovery_excludes_test_sources_by_default(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write(
        repo / "app" / "runtime.py",
        '''
worker = LlmAgent(name="runtime_agent")
''',
    )
    write(
        repo / "tests" / "test_runtime.py",
        '''
fixture = LlmAgent()
''',
    )
    out = tmp_path / "out" / "draft_manifests"
    result = run_scan(repo, out)
    assert {x.payload["agent_id"] for x in result["agents"]} == {"runtime_agent"}
    assert not any("test_runtime.py" in x.file for x in result["unresolved"])

    out_with_tests = tmp_path / "out_with_tests" / "draft_manifests"
    result_with_tests = run_scan(repo, out_with_tests, include_tests=True)
    assert {x.payload["agent_id"] for x in result_with_tests["agents"]} == {"runtime_agent", "fixture"}


def test_tool_collection_alias_is_resolved_without_fake_tool_name(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write(
        repo / "agents.py",
        '''
def tool_a():
    return 1

def tool_b():
    return 2

agent_tools = [tool_a, tool_b]
worker = LlmAgent(name="worker_agent", tools=agent_tools)
''',
    )
    out = tmp_path / "out" / "draft_manifests"
    result = run_scan(repo, out)
    agents = {x.payload["agent_id"]: x.payload for x in result["agents"]}
    assert agents["worker_agent"]["authorized_tools"] == ["tool_a", "tool_b"]
    assert not any(x.category == "unresolved_tool_reference" and x.symbol == "agent_tools" for x in result["unresolved"])
    edges = {(x.payload["edge_type"], x.payload["from_id"], x.payload["to_id"]) for x in result["edges"]}
    assert ("agent_to_tool", "worker_agent", "tool_a") in edges
    assert ("agent_to_tool", "worker_agent", "tool_b") in edges


def test_dynamic_tool_collection_is_recognized_not_misread_as_tool(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write(
        repo / "agents.py",
        '''
def make_wrapper(name):
    return lambda: name

def build_agent(runtime_tools):
    agent_tools = []
    for item in runtime_tools:
        wrapper = make_wrapper(item)
        agent_tools.append(wrapper)
    return LlmAgent(name="dynamic_agent", tools=agent_tools)
''',
    )
    out = tmp_path / "out" / "draft_manifests"
    result = run_scan(repo, out)
    agent = next(x.payload for x in result["agents"] if x.payload["agent_id"] == "dynamic_agent")
    assert agent["authorized_tools"] == []
    assert agent["dynamic_tool_sources"] == ["agent_tools"]
    assert not any(x.category == "unresolved_tool_reference" and x.symbol == "agent_tools" for x in result["unresolved"])
    assert not any(x.category == "unresolved_tool_reference" and x.symbol == "wrapper" for x in result["unresolved"])


def test_session_get_only_treats_model_argument_as_database_reference(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write(
        repo / "service.py",
        '''
class Base:
    pass

class BranchWorkload(Base):
    __tablename__ = "branch_workloads"
    branch_id = Column()

@router.get("/branches/{branch_id}")
def get_branch_workload(branch_id, db):
    return db.get(BranchWorkload, branch_id)
''',
    )
    out = tmp_path / "out" / "draft_manifests"
    result = run_scan(repo, out)
    assert not any(x.category == "unresolved_database_reference" and x.symbol == "branch_id" for x in result["unresolved"])
    edges = {(x.payload["edge_type"], x.payload["from_id"], x.payload["to_id"]) for x in result["edges"]}
    assert ("api_to_database", "get_branch_workload", "branch_workloads") in edges


def test_same_named_repository_method_does_not_steal_registered_tool_source(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write(
        repo / "infra" / "repository.py",
        '''
class Repository:
    def get_eod_batch(self, batch_id):
        return {"batch_id": batch_id}
''',
    )
    write(
        repo / "tools" / "back_office_tools.py",
        '''
def get_eod_batch(batch_id):
    return {"batch_id": batch_id}
''',
    )
    write(
        repo / "agents.py",
        '''
from tools.back_office_tools import get_eod_batch
worker = LlmAgent(name="eod_processing_agent", tools=[get_eod_batch])
''',
    )
    out = tmp_path / "out" / "draft_manifests"
    result = run_scan(repo, out)
    tools = {x.payload["tool_id"]: x.payload for x in result["tools"]}
    assert "get_eod_batch" in tools
    reference = tools["get_eod_batch"]["source"]["reference"].replace("\\", "/")
    assert reference.startswith("tools/back_office_tools.py:")
