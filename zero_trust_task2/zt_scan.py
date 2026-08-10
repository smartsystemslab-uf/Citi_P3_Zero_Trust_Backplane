import argparse
import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml


# Zero-trust Task 2 scanner for the Citi Banking repo.
#
# This script parses repository Python sources to discover ADK agents, tools,
# backend APIs, and database models. It then assembles draft ZT-IR manifests
# and an interaction edge graph to support zero-trust analysis and PEP planning.


@dataclass
class DraftEntity:
    payload: Dict[str, Any]
    source_file: str
    source_line: int


# Helper utilities for AST inspection and extraction.
# These functions are generic helpers used by scanner classes below.
def node_value(node: ast.AST) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Str):
        return node.s
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        return node.attr
    if isinstance(node, ast.List):
        return [node_value(item) for item in node.elts]
    if isinstance(node, ast.Tuple):
        return [node_value(item) for item in node.elts]
    if isinstance(node, ast.Dict):
        return {node_value(k): node_value(v) for k, v in zip(node.keys, node.values)}
    return None


def keyword_value(key: str, keywords: List[ast.keyword]) -> Any:
    for kw in keywords:
        if kw.arg == key:
            return node_value(kw.value)
    return None


def extract_function_docstring(node: ast.AST) -> str:
    return ast.get_docstring(node) or ""


def is_call_to(node: ast.AST, name: str) -> bool:
    if not isinstance(node, ast.Call):
        return False
    if isinstance(node.func, ast.Name) and node.func.id == name:
        return True
    if isinstance(node.func, ast.Attribute) and node.func.attr == name:
        return True
    return False


def decorator_name(node: ast.expr) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def get_string(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Str):
        return node.s
    return None


def extract_string_list(node: ast.AST) -> List[str]:
    if isinstance(node, ast.List) or isinstance(node, ast.Tuple):
        return [v for v in (node_value(item) for item in node.elts) if isinstance(v, str)]
    return []


def normalize_method(name: str) -> str:
    return name.upper()


def normalize_path(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return path

# Scanner classes below inspect the codebase to discover zero-trust entities
# and relationships, then emit draft manifest payloads for manual review.
class AgentScanner(ast.NodeVisitor):
    """Scan ADK agent source files to discover agent definitions.

    This scanner finds LLM and workflow agent constructions and extracts
    metadata such as agent_id, description, authorized tools, routing
    transfers, domain, and source location.
    """

    def __init__(self, source_path: Path, repo_root: Path):
        self.source_path = source_path
        self.repo_root = repo_root.resolve()
        self.agents: List[DraftEntity] = []

    def visit_Call(self, node: ast.Call) -> Any:
        """Inspect each call expression and detect agent constructors."""
        if isinstance(node.func, ast.Name) and node.func.id in {"LlmAgent", "SequentialAgent", "ParallelAgent"}:
            self._maybe_add_agent(node)
        elif isinstance(node.func, ast.Attribute) and node.func.attr in {"LlmAgent", "SequentialAgent", "ParallelAgent"}:
            self._maybe_add_agent(node)
        self.generic_visit(node)

    def _maybe_add_agent(self, node: ast.Call) -> None:
        """Extract metadata for a detected agent call and append a draft entity."""
        name_value = keyword_value("name", node.keywords)
        if not isinstance(name_value, str):
            return

        desc = keyword_value("description", node.keywords) or keyword_value("instruction", node.keywords) or ""
        tools = extract_string_list(keyword_value("tools", node.keywords) or [])
        sub_agents = extract_string_list(keyword_value("sub_agents", node.keywords) or [])
        agent_type = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id

        role = "specialist"
        pep_type = "tool_pep"
        if agent_type in {"SequentialAgent", "ParallelAgent"}:
            role = "workflow"
            pep_type = "none"
        elif sub_agents:
            role = "router"
            pep_type = "route_pep"
        elif name_value.endswith("router") or name_value.endswith("agent") and "router" in name_value:
            role = "router"
            pep_type = "route_pep"

        domain = self._domain_from_filename()
        if name_value == "user_proxy_agent":
            domain = "root"

        payload = {
            "agent_id": name_value,
            "description": desc.strip().splitlines()[0] if desc else "Auto-discovered ADK agent",
            "domain": domain,
            "role": role,
            "risk_tier": "medium",
            "authorized_tools": tools,
            "authorized_transfers": sub_agents,
            "reads_from": [],
            "writes_to": [],
            "requires_prior_steps": [],
            "pep_type": pep_type,
            "trust_level": "low_trust",
            "status": "provisional",
            "source": {
                "provided_by": "task2_scanner",
                "reference": f"{self.source_path.relative_to(self.repo_root)}:{node.lineno}",
            },
        }
        self.agents.append(DraftEntity(payload, str(self.source_path), node.lineno))

    def _domain_from_filename(self) -> str:
        """Infer agent domain by the source filename or module name."""
        name = self.source_path.name
        if name == "root.py":
            return "root"
        if "front" in name:
            return "front"
        if "mid" in name:
            return "mid"
        if "back" in name:
            return "back"
        return "shared"


class ToolScanner(ast.NodeVisitor):
    """Scan tool modules to discover ADK and MCP tool functions."""

    def __init__(self, source_path: Path, repo_root: Path):
        self.source_path = source_path
        self.repo_root = repo_root.resolve()
        self.tools: List[DraftEntity] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        """Inspect function definitions and treat ADK or MCP functions as tools."""
        is_mcp = any(decorator_name(dec) == "tool" for dec in node.decorator_list)
        in_tools_dir = "bank_adk/tools" in str(self.source_path)
        if is_mcp or in_tools_dir:
            payload = self._build_tool(node, is_mcp)
            self.tools.append(DraftEntity(payload, str(self.source_path), node.lineno))
        self.generic_visit(node)

    def _build_tool(self, node: ast.FunctionDef, is_mcp: bool) -> Dict[str, Any]:
        """Build a draft tool manifest from a function definition."""
        tool_id = node.name
        doc = extract_function_docstring(node)
        first_line = doc.strip().splitlines()[0] if doc else f"Auto-discovered tool {tool_id}"
        source = "mcp" if is_mcp else "adk"
        domain = self._domain_from_filename()
        action_type = self._infer_action_type(tool_id, source)
        operation_class = self._map_operation_class(action_type)
        calls_api = self._find_http_calls(node)
        tool = {
            "tool_id": tool_id,
            "display_name": first_line,
            "source": source,
            "domain": domain,
            "action_type": action_type,
            "has_side_effects": action_type not in {"read", "compute"},
            "risk_level": 4 if action_type in {"financial_write", "state_change"} else 2,
            "requires_live_decision": tool_id in {
                "execute_transfer",
                "apply_ledger_updates",
                "update_transaction_status",
                "trigger_eod_reconciliation",
                "resolve_ledger_entry",
            },
            "audit_required": action_type not in {"read", "compute"},
            "allowed_callers": [],
            "calls_api": calls_api,
            "pii_fields": [],
            "compliance_tags": [],
            "idempotency_key": None,
            "operation_class": operation_class,
            "status": "provisional",
            "source": {
                "provided_by": "task2_scanner",
                "reference": f"{self.source_path.relative_to(self.repo_root)}:{node.lineno}",
            },
        }
        return tool

    def _domain_from_filename(self) -> str:
        """Map tool source file location to a logical domain."""
        path = str(self.source_path)
        if "customer_tools" in path:
            return "front"
        if "knowledge_tools" in path:
            return "shared"
        if "csr_tools" in path or "ops_tools" in path:
            return "mid"
        if "back_office_tools" in path:
            return "back"
        if "mcp_server.py" in path:
            return "shared"
        return "shared"

    def _infer_action_type(self, tool_id: str, source: str) -> str:
        """Infer action type from tool naming conventions."""
        if tool_id.startswith("get_") or tool_id.startswith("list_") or tool_id.startswith("search_"):
            return "read"
        if tool_id.startswith("evaluate_") or tool_id.startswith("propose_"):
            return "compute"
        if tool_id.startswith("execute_") or tool_id.startswith("apply_") or tool_id.startswith("resolve_"):
            return "financial_write" if "transfer" in tool_id or "ledger" in tool_id else "state_change"
        if tool_id.startswith("submit_") or tool_id.startswith("create_") or tool_id.startswith("trigger_"):
            return "state_change"
        return "compute"

    def _map_operation_class(self, action_type: str) -> str:
        """Convert a tool action type into an operation class."""
        if action_type == "read":
            return "read"
        if action_type == "compute":
            return "read"
        if action_type == "financial_write":
            return "financial"
        return "write"

    def _find_http_calls(self, node: ast.FunctionDef) -> List[str]:
        """Scan tool function bodies for outbound backend API calls."""
        paths: List[str] = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute) and child.func.attr in {"get", "post", "patch", "put", "delete"}:
                    if isinstance(child.func.value, ast.Name) and child.func.value.id in {"client", "httpx", "api_client"}:
                        path = self._extract_path_from_call(child)
                        if path:
                            paths.append(path)
        return list(dict.fromkeys(paths))

    def _extract_path_from_call(self, node: ast.Call) -> Optional[str]:
        """Extract a literal path string from an HTTP client call."""
        if node.args:
            value = node.args[0]
            path = get_string(value)
            if path:
                return path
        for kw in node.keywords:
            if kw.arg in {"url", "path", "json", "params"}:
                continue
        return None


class ApiScanner(ast.NodeVisitor):
    """Scan FastAPI route definitions and infer endpoint metadata."""

    def __init__(self, source_path: Path, repo_root: Path):
        self.source_path = source_path
        self.repo_root = repo_root.resolve()
        self.apis: List[DraftEntity] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        """Detect API route handlers declared with app.<method>(path)."""
        decorators = [decorator_name(dec) for dec in node.decorator_list if decorator_name(dec)]
        for dec in node.decorator_list:
            method, path = self._route_info(dec)
            if method and path:
                payload = self._build_api(node, method, path)
                self.apis.append(DraftEntity(payload, str(self.source_path), node.lineno))
        self.generic_visit(node)

    def _route_info(self, dec: ast.AST) -> Tuple[Optional[str], Optional[str]]:
        if not isinstance(dec, ast.Call):
            return None, None
        if isinstance(dec.func, ast.Attribute) and isinstance(dec.func.value, ast.Name) and dec.func.value.id == "app":
            method = dec.func.attr
            path = None
            if dec.args:
                path = get_string(dec.args[0])
            else:
                path = keyword_value("path", dec.keywords)
            return normalize_method(method), normalize_path(path) if path else None
        return None, None

    def _build_api(self, node: ast.FunctionDef, method: str, path: str) -> Dict[str, Any]:
        """Construct a draft API manifest from a route handler."""
        doc = extract_function_docstring(node)
        first_line = doc.strip().splitlines()[0] if doc else f"Auto-discovered API endpoint {node.name}"
        reads, writes = self._infer_database_access(node)
        action_type = self._infer_action_type(method, path)
        domain = self._infer_domain(path)
        api = {
            "api_id": node.name,
            "display_name": first_line,
            "service": "citi_banking_backend",
            "base_url": "http://localhost:8000",
            "path": path,
            "method": method,
            "domain": domain,
            "action_type": action_type,
            "has_side_effects": method != "GET",
            "risk_level": 4 if action_type in {"financial_write", "critical"} else 2,
            "requires_auth": True,
            "audit_required": method != "GET",
            "reads_tables": reads,
            "writes_tables": writes,
            "pii_fields": [],
            "compliance_tags": [],
            "idempotency_key": None,
            "operation_class": "financial" if action_type == "financial_write" else ("write" if method != "GET" else "read"),
            "allowed_callers": [],
            "status": "provisional",
            "source": {
                "provided_by": "task2_scanner",
                "reference": f"{self.source_path.relative_to(self.repo_root)}:{node.lineno}",
            },
        }
        return api

    def _route_info(self, dec: ast.AST) -> Tuple[Optional[str], Optional[str]]:
        if not isinstance(dec, ast.Call):
            return None, None
        if isinstance(dec.func, ast.Attribute) and isinstance(dec.func.value, ast.Name) and dec.func.value.id == "app":
            method = dec.func.attr
            path = None
            if dec.args:
                path = get_string(dec.args[0])
            else:
                path = keyword_value("path", dec.keywords)
            return normalize_method(method), normalize_path(path) if path else None
        return None, None

    def _infer_action_type(self, method: str, path: str) -> str:
        """Classify API endpoints into read, financial_write, or state_change."""
        if method == "GET":
            return "read"
        if "/banking-api/transfer" in path or "/reconcile" in path or "/resolve" in path:
            return "financial_write"
        return "state_change"

    def _infer_domain(self, path: str) -> str:
        """Infer a logical domain for the API endpoint based on its path."""
        if path.startswith("/customers") or path.startswith("/transactions") or path.startswith("/banking-api"):
            return "front"
        if path.startswith("/monitoring") or path.startswith("/mid-office"):
            return "mid"
        if path.startswith("/back-office"):
            return "back"
        return "shared"

    def _infer_database_access(self, node: ast.FunctionDef) -> Tuple[List[str], List[str]]:
        """Heuristically infer database reads and writes from the API function body."""
        reads: List[str] = []
        writes: List[str] = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                if child.func.attr == "scalar" or child.func.attr == "scalars":
                    for arg in child.args:
                        if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name) and arg.func.id == "select":
                            reads.extend(self._extract_models(arg))
                if child.func.attr in {"add", "commit", "delete", "patch"}:
                    if isinstance(child.func.value, ast.Name) and child.func.value.id == "db":
                        writes.append("unknown")
        return list(dict.fromkeys(reads)), list(dict.fromkeys(writes))

    def _extract_models(self, node: ast.Call) -> List[str]:
        """Extract referenced ORM model names from a SQLAlchemy select call."""
        models: List[str] = []
        for arg in node.args:
            if isinstance(arg, ast.Name):
                models.append(arg.id)
            if isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name):
                models.append(arg.attr)
        return models


class DatabaseScanner(ast.NodeVisitor):
    """Scan SQLAlchemy model classes and infer database table metadata."""

    def __init__(self, source_path: Path, repo_root: Path):
        self.source_path = source_path
        self.repo_root = repo_root.resolve()
        self.databases: List[DraftEntity] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        """Detect SQLAlchemy ORM model classes that inherit from Base."""
        if any(base.id == "Base" for base in node.bases if isinstance(base, ast.Name)):
            tablename = self._find_tablename(node)
            table_name = tablename or node.name.lower()
            classification = self._infer_classification(table_name)
            payload = {
                "database_id": table_name,
                "display_name": f"{node.name} table",
                "db_type": "relational",
                "engine": "SQLite",
                "table_name": table_name,
                "classification": classification,
                "contains_pii": table_name in {"customers"},
                "contains_financial": table_name in {"accounts", "transactions"},
                "contains_audit": table_name == "audit_logs",
                "allowed_operations": ["SELECT", "INSERT", "UPDATE", "DELETE"],
                "allowed_api_callers": [],
                "compliance_tags": [],
                "risk_level": 3,
                "immutable": table_name == "audit_logs",
                "status": "provisional",
                "source": {
                    "provided_by": "task2_scanner",
                    "reference": f"{self.source_path.relative_to(self.repo_root)}:{node.lineno}",
                },
            }
            self.databases.append(DraftEntity(payload, str(self.source_path), node.lineno))
        self.generic_visit(node)

    def _find_tablename(self, node: ast.ClassDef) -> Optional[str]:
        """Read __tablename__ from a model class, if present."""
        for child in node.body:
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name) and target.id == "__tablename__":
                        return get_string(child.value)
        return None

    def _infer_classification(self, table_name: str) -> str:
        """Assign a sensitivity classification to known tables."""
        if table_name in {"customers", "accounts", "transactions"}:
            return "confidential"
        if table_name in {"policies", "rules"}:
            return "internal"
        if table_name == "audit_logs":
            return "restricted"
        return "internal"


class InteractionEdgeBuilder:
    """Build draft interaction edges between discovered agents, tools, APIs, and databases."""

    def __init__(self, agents: List[DraftEntity], tools: List[DraftEntity], apis: List[DraftEntity], databases: List[DraftEntity]):
        self.agents = agents
        self.tools = tools
        self.apis = apis
        self.databases = databases
        self.edges: List[DraftEntity] = []

    def build_edges(self) -> None:
        """Create all configured edge layers for the interaction graph."""
        self._build_agent_to_tool_edges()
        self._build_tool_to_api_edges()
        self._build_api_to_database_edges()
        self._build_agent_to_agent_edges()

    def _build_agent_to_tool_edges(self) -> None:
        """Link agents to authorized tools based on agent metadata."""
        tool_ids = {tool.payload["tool_id"] for tool in self.tools}
        for agent in self.agents:
            if agent.payload["authorized_tools"]:
                for tool_id in agent.payload["authorized_tools"]:
                    if tool_id in tool_ids:
                        tool = self._get_tool(tool_id)
                        self._add_edge(
                            edge_type="agent_to_tool",
                            from_id=agent.payload["agent_id"],
                            to_id=tool_id,
                            risk_level=3,
                            pep_required=True,
                            pep_type="tool_pep",
                            http_method=None,
                            db_operation=None,
                            operation_class="write" if tool and tool.payload["action_type"] == "financial_write" else "read",
                            tool=tool,
                            api=None,
                            db=None,
                            from_entity=agent,
                        )

    def _build_tool_to_api_edges(self) -> None:
        """Link tools to backend API endpoints they invoke."""
        api_ids_by_path = {api.payload["path"]: api.payload["api_id"] for api in self.apis}
        for tool in self.tools:
            for path in tool.payload.get("calls_api", []):
                match_id = api_ids_by_path.get(path)
                if match_id:
                    api = self._get_api(match_id)
                    self._add_edge(
                        edge_type="tool_to_api",
                        from_id=tool.payload["tool_id"],
                        to_id=match_id,
                        risk_level=3,
                        pep_required=True,
                        pep_type="api_pep",
                        http_method=api.payload.get("method") if api else None,
                        db_operation=None,
                        operation_class="read",
                        tool=tool,
                        api=api,
                        db=None,
                        from_entity=None,
                    )

    def _build_api_to_database_edges(self) -> None:
        """Link API endpoints to the database tables they read or write."""
        for api in self.apis:
            for table in api.payload.get("reads_tables", []):
                db = self._get_database(table)
                self._add_edge(
                    edge_type="api_to_database",
                    from_id=api.payload["api_id"],
                    to_id=table,
                    risk_level=3,
                    pep_required=True,
                    pep_type="data_pep",
                    http_method=api.payload["method"],
                    db_operation="SELECT",
                    operation_class="read",
                    tool=None,
                    api=api,
                    db=db,
                    from_entity=None,
                )
            for table in api.payload.get("writes_tables", []):
                db = self._get_database(table)
                self._add_edge(
                    edge_type="api_to_database",
                    from_id=api.payload["api_id"],
                    to_id=table,
                    risk_level=4,
                    pep_required=True,
                    pep_type="data_pep",
                    http_method=api.payload["method"],
                    db_operation="INSERT",
                    operation_class="write",
                    tool=None,
                    api=api,
                    db=db,
                    from_entity=None,
                )

    def _build_agent_to_agent_edges(self) -> None:
        """Link agents to downstream agents when control transfer is authorized."""
        agent_ids = {agent.payload["agent_id"] for agent in self.agents}
        for agent in self.agents:
            for target in agent.payload.get("authorized_transfers", []):
                if target in agent_ids:
                    target_agent = self._get_agent(target)
                    self._add_edge(
                        edge_type="agent_to_agent",
                        from_id=agent.payload["agent_id"],
                        to_id=target,
                        risk_level=3,
                        pep_required=True,
                        pep_type="route_pep",
                        http_method=None,
                        db_operation=None,
                        operation_class="read",
                        tool=None,
                        api=None,
                        db=None,
                        from_entity=agent,
                        to_entity=target_agent,
                    )

    def _get_agent(self, agent_id: str) -> Optional[DraftEntity]:
        for agent in self.agents:
            if agent.payload["agent_id"] == agent_id:
                return agent
        return None

    def _get_tool(self, tool_id: str) -> Optional[DraftEntity]:
        for tool in self.tools:
            if tool.payload["tool_id"] == tool_id:
                return tool
        return None

    def _get_api(self, api_id: str) -> Optional[DraftEntity]:
        for api in self.apis:
            if api.payload["api_id"] == api_id:
                return api
        return None

    def _get_database(self, database_id: str) -> Optional[DraftEntity]:
        for db in self.databases:
            if db.payload["database_id"] == database_id:
                return db
        return None

    def _infer_workflow_context(self, from_id: str, to_id: str, edge_type: str, from_entity: Optional[DraftEntity], to_entity: Optional[DraftEntity]) -> str:
        workflow_tags = ["eod", "ledger", "reconcile", "back_office", "front_office", "mid_office", "planning", "forecast", "customer_service", "fraud", "transaction", "chatbot", "support"]
        combined = " ".join(filter(None, [from_id, to_id, edge_type])).lower()
        for tag in workflow_tags:
            if tag in combined:
                return tag
        if from_entity and from_entity.payload.get("domain"):
            return f"workflow_{from_entity.payload['domain']}"
        if to_entity and to_entity.payload.get("domain"):
            return f"workflow_{to_entity.payload['domain']}"
        return "shared"

    def _infer_data_type(self, edge_type: str, to_type: str, to_id: str, api: Optional[DraftEntity], db: Optional[DraftEntity], tool: Optional[DraftEntity]) -> str:
        if to_type == "database" and db is not None:
            classification = db.payload.get("classification", "internal")
            if classification == "confidential":
                if db.payload.get("contains_financial"):
                    return "financial"
                return "personal"
            if classification == "restricted":
                return "audit"
            return "internal"
        if to_type == "api" and api is not None:
            path = api.payload.get("path", "").lower()
            if "/customers" in path:
                return "personal"
            if "/transactions" in path or "/banking-api" in path:
                return "financial"
            if "/monitoring" in path:
                return "operational"
            return "service"
        if to_type == "tool" and tool is not None:
            action_type = tool.payload.get("action_type", "compute")
            if action_type == "financial_write":
                return "financial"
            if action_type == "read":
                return "operational"
            return "service"
        if edge_type == "agent_to_agent":
            return "workflow_control"
        return "unknown"

    def _infer_authentication_method(self, edge_type: str, tool: Optional[DraftEntity], api: Optional[DraftEntity]) -> str:
        if edge_type == "tool_to_api":
            return "api_token"
        if edge_type == "api_to_database":
            return "service_account"
        if edge_type == "agent_to_tool":
            if tool and tool.payload.get("source") == "mcp":
                return "mcp"
            return "in_process"
        if edge_type == "agent_to_agent":
            return "internal"
        return "unknown"

    def _infer_trust_boundary(self, edge_type: str, from_entity: Optional[DraftEntity], to_entity: Optional[DraftEntity]) -> str:
        if edge_type == "tool_to_api":
            return "service_mesh"
        if edge_type == "api_to_database":
            return "database"
        if edge_type == "agent_to_tool":
            return "mcp" if from_entity and from_entity.payload.get("role") == "router" else "internal"
        if edge_type == "agent_to_agent":
            return "internal"
        return "unknown"

    def _infer_action(self, edge_type: str, http_method: Optional[str], db_operation: Optional[str]) -> str:
        if edge_type == "agent_to_tool":
            return "call_tool"
        if edge_type in {"tool_to_api", "mcp_tool_to_api"}:
            return "invoke_api"
        if edge_type == "api_to_database":
            return f"db_{db_operation.lower()}" if db_operation else "db_access"
        if edge_type == "agent_to_agent":
            return "transfer_control"
        return "unknown"

    def _add_edge(
        self,
        edge_type: str,
        from_id: str,
        to_id: str,
        risk_level: int,
        pep_required: bool,
        pep_type: Optional[str],
        http_method: Optional[str],
        db_operation: Optional[str],
        operation_class: str,
        tool: Optional[DraftEntity] = None,
        api: Optional[DraftEntity] = None,
        db: Optional[DraftEntity] = None,
        from_entity: Optional[DraftEntity] = None,
        to_entity: Optional[DraftEntity] = None,
    ) -> None:
        edge_id = f"edge_{len(self.edges) + 1:03d}"
        from_type = "subject" if edge_type in {"agent_to_agent", "agent_to_tool"} else ("tool" if edge_type == "tool_to_api" else "api")
        to_type = "subject" if edge_type == "agent_to_agent" else ("tool" if edge_type == "agent_to_tool" else ("api" if edge_type == "tool_to_api" else "database"))
        action = self._infer_action(edge_type, http_method, db_operation)
        data_type = self._infer_data_type(edge_type, to_type, to_id, api, db, tool)
        side_effects = operation_class != "read"
        auth_method = self._infer_authentication_method(edge_type, tool, api)
        trust_boundary = self._infer_trust_boundary(edge_type, from_entity, to_entity)
        workflow_context = self._infer_workflow_context(from_id, to_id, edge_type, from_entity, to_entity)

        payload: Dict[str, Any] = {
            "edge_id": edge_id,
            "edge_type": edge_type,
            "from_id": from_id,
            "from_type": from_type,
            "to_id": to_id,
            "to_type": to_type,
            "action": action,
            "data_type": data_type,
            "risk_level": risk_level,
            "side_effects": side_effects,
            "authentication_method": auth_method,
            "trust_boundary": trust_boundary,
            "workflow_context": workflow_context,
            "pep_required": pep_required,
            "pep_type": pep_type,
            "trigger": None,
            "required_state": [],
            "http_method": http_method,
            "db_operation": db_operation,
            "operation_class": operation_class,
            "status": "provisional",
            "source": {
                "provided_by": "task2_scanner",
                "reference": "task2_scanner",
            },
        }
        self.edges.append(DraftEntity(payload, "task2_scanner", 0))


def parse_python_file(path: Path) -> ast.AST:
    """Parse a Python source file into an AST."""
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def scan_agents(source_files: Iterable[Path], repo_root: Path) -> List[DraftEntity]:
    """Scan agent source files and return discovered draft agent entities."""
    agents: List[DraftEntity] = []
    for source in source_files:
        tree = parse_python_file(source)
        scanner = AgentScanner(source, repo_root)
        scanner.visit(tree)
        agents.extend(scanner.agents)
    return agents


def scan_tools(source_files: Iterable[Path], repo_root: Path) -> List[DraftEntity]:
    """Scan tool source files and return discovered draft tool entities."""
    tools: List[DraftEntity] = []
    for source in source_files:
        tree = parse_python_file(source)
        scanner = ToolScanner(source, repo_root)
        scanner.visit(tree)
        tools.extend(scanner.tools)
    return tools


def scan_apis(source_files: Iterable[Path], repo_root: Path) -> List[DraftEntity]:
    """Scan backend API files and return discovered draft API entities."""
    apis: List[DraftEntity] = []
    for source in source_files:
        tree = parse_python_file(source)
        scanner = ApiScanner(source, repo_root)
        scanner.visit(tree)
        apis.extend(scanner.apis)
    return apis


def scan_databases(source_files: Iterable[Path], repo_root: Path) -> List[DraftEntity]:
    """Scan database model files and return discovered draft database entities."""
    databases: List[DraftEntity] = []
    for source in source_files:
        tree = parse_python_file(source)
        scanner = DatabaseScanner(source, repo_root)
        scanner.visit(tree)
        databases.extend(scanner.databases)
    return databases


def write_manifest(path: Path, root_key: str, entities: List[DraftEntity]) -> None:
    """Write a draft manifest YAML file for the discovered entities."""
    manifest = {
        "zt_ir_version": "1.0",
        "manifest_type": f"{root_key}_draft",
        root_key: [entity.payload for entity in entities],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")


def write_coverage_report(path: Path, agents: List[DraftEntity], tools: List[DraftEntity], apis: List[DraftEntity], databases: List[DraftEntity], edges: List[DraftEntity]) -> None:
    """Write a coverage report summarizing discovered entity counts."""
    report = {
        "discovered_agents": len(agents),
        "discovered_tools": len(tools),
        "discovered_apis": len(apis),
        "discovered_databases": len(databases),
        "discovered_edges": len(edges),
        "coverage_percent": None,
        "details": {
            "agents": [a.payload["agent_id"] for a in agents],
            "tools": [t.payload["tool_id"] for t in tools],
            "apis": [a.payload["api_id"] for a in apis],
            "databases": [d.payload["database_id"] for d in databases],
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(report, sort_keys=False), encoding="utf-8")


def find_source_files(repo_root: Path) -> Dict[str, List[Path]]:
    """Return the file paths that should be scanned for each entity type."""
    return {
        "agents": sorted(repo_root.glob("citi_banking_adk/bank_adk/agents/*.py")),
        "tools": sorted(list(repo_root.glob("citi_banking_adk/bank_adk/tools/*.py")) + [repo_root / "citi_banking_mcp_server" / "mcp_server.py"]),
        "apis": [repo_root / "citi_banking_backend" / "app" / "main.py"],
        "databases": [repo_root / "citi_banking_backend" / "app" / "models.py"],
    }


def main() -> None:
    """Entry point for the scanner CLI.

    It parses arguments, discovers source files, scans entities, builds the
    interaction edge graph, writes draft manifests, and writes a coverage report.
    """
    parser = argparse.ArgumentParser(description="ZT-IR Task 2 manifest scanner for the Citi Banking repo.")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Path to the repository root.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "output" / "draft_manifests",
        help="Directory where draft manifests and scan reports are written.",
    )
    args = parser.parse_args()

    sources = find_source_files(args.repo_root)
    agents = scan_agents(sources["agents"], args.repo_root)
    tools = scan_tools(sources["tools"], args.repo_root)
    apis = scan_apis(sources["apis"], args.repo_root)
    databases = scan_databases(sources["databases"], args.repo_root)

    edge_builder = InteractionEdgeBuilder(agents, tools, apis, databases)
    edge_builder.build_edges()
    edges = edge_builder.edges

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_manifest(args.output_dir / "agents_draft.yaml", "agents", agents)
    write_manifest(args.output_dir / "tools_draft.yaml", "tools", tools)
    write_manifest(args.output_dir / "apis_draft.yaml", "apis", apis)
    write_manifest(args.output_dir / "databases_draft.yaml", "databases", databases)
    write_manifest(args.output_dir / "interaction_edges_draft.yaml", "interaction_edges", edges)

    report_path = args.output_dir.parent / "coverage_report.yaml"
    write_coverage_report(report_path, agents, tools, apis, databases, edges)

    print(f"Scanner complete. Draft manifests written to: {args.output_dir}")
    print(f"Coverage report written to: {report_path}")


if __name__ == "__main__":
    main()
