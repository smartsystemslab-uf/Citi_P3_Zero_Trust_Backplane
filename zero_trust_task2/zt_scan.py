from __future__ import annotations

import argparse
import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

import yaml


# Task 2 generic static scanner for multi-agent systems.
#
# Design goals:
# - discover repository structure instead of assuming one project layout;
# - recognize common Python agent/tool/API/database/event patterns;
# - parse OpenAPI and MCP-style structured manifests;
# - preserve unknown or unsupported interface patterns in an unresolved report;
# - emit the same draft ZT-IR files consumed by Tasks 3-5.

DEFAULT_EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", ".idea", ".vscode", ".pytest_cache", ".mypy_cache",
    "__pycache__", ".venv", "venv", "env", "node_modules", "dist", "build",
    ".tox", ".nox", "site-packages", "coverage", "htmlcov",
}
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
KNOWN_AGENT_CONSTRUCTORS = {
    "LlmAgent", "SequentialAgent", "ParallelAgent", "Agent", "BaseAgent",
    "ConversableAgent", "AssistantAgent", "UserProxyAgent", "ChatAgent",
    "RouterAgent", "WorkflowAgent",
}
AGENT_FACTORY_NAMES = {"create_agent", "build_agent", "make_agent", "new_agent", "agent_factory"}
TOOL_DECORATORS = {
    "tool", "function_tool", "register_tool", "mcp_tool", "server.tool", "mcp.tool",
    "app.tool", "registry.tool", "kernel_function",
}
TOOL_DIR_NAMES = {"tool", "tools", "plugin", "plugins", "action", "actions", "capability", "capabilities", "functions"}
EVENT_DECORATOR_NAMES = {
    "on_event", "event_listener", "listener", "subscribe", "subscriber", "scheduled_job",
    "cron", "task", "receiver", "handler",
}


@dataclass
class DraftEntity:
    payload: Dict[str, Any]
    source_file: str
    source_line: int


@dataclass
class UnresolvedFinding:
    category: str
    file: str
    line: int
    symbol: Optional[str]
    suspected_type: str
    confidence: str
    reason: str
    severity: str = "warning"
    details: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        out = {
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "symbol": self.symbol,
            "suspected_type": self.suspected_type,
            "confidence": self.confidence,
            "reason": self.reason,
            "severity": self.severity,
        }
        if self.details:
            out["details"] = self.details
        return out


@dataclass
class RepositorySources:
    python_files: List[Path] = field(default_factory=list)
    structured_files: List[Path] = field(default_factory=list)
    openapi_files: List[Path] = field(default_factory=list)
    mcp_manifest_files: List[Path] = field(default_factory=list)
    generic_config_files: List[Path] = field(default_factory=list)
    skipped_files: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# AST / normalization helpers
# ---------------------------------------------------------------------------

def node_value(node: ast.AST | None) -> Any:
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = node_value(node.value)
        return f"{base}.{node.attr}" if isinstance(base, str) and base else node.attr
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [node_value(item) for item in node.elts]
    if isinstance(node, ast.Dict):
        return {node_value(k): node_value(v) for k, v in zip(node.keys, node.values)}
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        value = node_value(node.operand)
        return -value if isinstance(value, (int, float)) else None
    return None


def keyword_value(key: str, keywords: Sequence[ast.keyword]) -> Any:
    for kw in keywords:
        if kw.arg == key:
            return node_value(kw.value)
    return None


def keyword_node(key: str, keywords: Sequence[ast.keyword]) -> Optional[ast.AST]:
    for kw in keywords:
        if kw.arg == key:
            return kw.value
    return None


def extract_function_docstring(node: ast.AST) -> str:
    return ast.get_docstring(node) or ""


def callable_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = callable_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def decorator_qualified_name(node: ast.expr) -> str:
    target = node.func if isinstance(node, ast.Call) else node
    return callable_name(target)


def decorator_name(node: ast.expr) -> Optional[str]:
    name = decorator_qualified_name(node)
    return name.rsplit(".", 1)[-1] if name else None


def get_string(node: ast.AST | None) -> Optional[str]:
    value = node_value(node)
    return value if isinstance(value, str) else None


def extract_string_list(node: Any) -> List[str]:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values = [node_value(item) for item in node.elts]
    elif isinstance(node, (list, tuple, set)):
        values = list(node)
    elif isinstance(node, str):
        values = [node]
    else:
        return []
    return [str(v) for v in values if isinstance(v, str) and v]


def normalize_method(name: str) -> str:
    return name.upper()


def normalize_path(path: str) -> str:
    if not path:
        return "/"
    # Accept literal absolute URLs and reduce them to their request path.
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", path):
        parsed = urlsplit(path)
        path = parsed.path or "/"
    path = path.split("?", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    path = re.sub(r"/+", "/", path)
    return path


def normalize_path_template(path: str) -> str:
    """Normalize route variable names so /x/{id} matches /x/{transaction_id}."""
    return re.sub(r"\{[^{}]+\}", "{param}", normalize_path(path))


def extract_static_url_path(node: ast.AST | None) -> Tuple[Optional[str], bool]:
    """Extract the stable path portion of a literal/f-string/concatenated URL.

    Returns (path, dynamic). A dynamic URL can still yield a useful stable path,
    e.g. f"{base_url}/v1/transfers" -> ("/v1/transfers", True).
    """
    if node is None:
        return None, False
    literal = get_string(node)
    if literal is not None:
        return normalize_path(literal), False
    if isinstance(node, ast.JoinedStr):
        pieces: List[str] = []
        dynamic = False
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                pieces.append(value.value)
            else:
                pieces.append("{dynamic}")
                dynamic = True
        text = "".join(pieces)
        slash = text.find("/", text.find("{dynamic}") + len("{dynamic}")) if "{dynamic}" in text else text.find("/")
        if slash >= 0:
            stable = text[slash:].replace("{dynamic}", "{param}")
            return normalize_path(stable), dynamic
        return None, dynamic
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, ld = extract_static_url_path(node.left)
        right, rd = extract_static_url_path(node.right)
        if right and right.startswith("/"):
            return right, True
        if left and right:
            return normalize_path(left.rstrip("/") + "/" + right.lstrip("/")), ld or rd
        return left or right, True
    return None, True


def safe_relative(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def infer_domain_from_path(path: Path) -> str:
    text = path.as_posix().lower()
    if any(x in text for x in ("front_office", "front-office", "/front/", "customer_service")):
        return "front"
    if any(x in text for x in ("mid_office", "mid-office", "/mid/", "planning", "representative")):
        return "mid"
    if any(x in text for x in ("back_office", "back-office", "/back/", "eod", "reconciliation")):
        return "back"
    if path.name == "root.py" or "user_proxy" in text:
        return "root"
    return "shared"


def infer_action_type(name: str, method: Optional[str] = None, path: Optional[str] = None) -> str:
    lowered = name.lower()
    method_u = (method or "").upper()
    path_l = (path or "").lower()
    if method_u in {"GET", "HEAD", "OPTIONS"}:
        return "read"
    if lowered.startswith(("get_", "list_", "search_", "read_", "fetch_", "lookup_", "find_")):
        return "read"
    if lowered.startswith(("evaluate_", "propose_", "calculate_", "forecast_", "rank_", "validate_", "score_", "analyze_")):
        return "compute"
    financial_terms = ("transfer", "ledger", "payment", "withdraw", "deposit", "settle", "posting")
    mutation_terms = ("execute", "apply", "resolve", "update", "write", "post", "create", "submit", "persist")
    combined = f"{lowered} {path_l}"
    if any(term in combined for term in financial_terms) and (method_u not in {"", "GET", "HEAD", "OPTIONS"} or any(term in lowered for term in mutation_terms)):
        return "financial_write"
    if method_u in {"POST", "PUT", "PATCH", "DELETE"}:
        return "state_change"
    if lowered.startswith(("execute_", "apply_", "resolve_", "update_", "write_", "store_", "submit_", "create_", "trigger_", "persist_", "delete_")):
        return "state_change"
    if lowered.endswith(("_update", "_write", "_create", "_delete")):
        return "state_change"
    return "compute"


def operation_class(action_type: str) -> str:
    if action_type in {"read", "compute"}:
        return "read"
    if action_type == "financial_write":
        return "financial"
    return "write"


def infer_risk_level(action_type: str, name: str = "", classification: Optional[str] = None) -> int:
    if action_type == "financial_write":
        return 4
    if action_type == "state_change":
        return 3
    sensitive_terms = ("customer", "profile", "transaction", "account", "identity", "credential", "policy", "audit")
    if classification in {"restricted", "regulated"}:
        return 4
    if classification == "confidential":
        return 3
    if action_type == "read" and any(term in name.lower() for term in sensitive_terms):
        return 3
    return 2


def infer_data_classification(name: str, columns: Sequence[str] = ()) -> str:
    text = " ".join([name, *columns]).lower()
    regulated_terms = ("ssn", "social_security", "tax_id", "passport", "credential", "secret", "token")
    confidential_terms = ("customer", "account", "transaction", "balance", "payment", "ledger", "loan", "profile")
    audit_terms = ("audit", "security_log")
    if any(term in text for term in regulated_terms):
        return "regulated"
    if any(term in text for term in audit_terms):
        return "restricted"
    if any(term in text for term in confidential_terms):
        return "confidential"
    return "internal"


def dedupe_entities(items: Iterable[DraftEntity], id_key: str) -> List[DraftEntity]:
    out: List[DraftEntity] = []
    seen: set[str] = set()
    for item in items:
        ident = str(item.payload.get(id_key) or "")
        if not ident or ident in seen:
            continue
        seen.add(ident)
        out.append(item)
    return out


class UnresolvedCollector:
    def __init__(self, repo_root: Path):
        self.repo_root = repo_root.resolve()
        self.findings: List[UnresolvedFinding] = []
        self._keys: set[Tuple[Any, ...]] = set()

    def add(
        self,
        *,
        category: str,
        file: Path | str,
        line: int = 0,
        symbol: Optional[str] = None,
        suspected_type: str,
        confidence: str,
        reason: str,
        severity: str = "warning",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        file_path = file if isinstance(file, Path) else Path(str(file))
        file_text = safe_relative(file_path, self.repo_root) if file_path.is_absolute() or isinstance(file, Path) else str(file)
        key = (category, file_text, line, symbol, suspected_type, reason)
        if key in self._keys:
            return
        self._keys.add(key)
        self.findings.append(UnresolvedFinding(
            category=category,
            file=file_text,
            line=line,
            symbol=symbol,
            suspected_type=suspected_type,
            confidence=confidence,
            reason=reason,
            severity=severity,
            details=details or {},
        ))


# ---------------------------------------------------------------------------
# Generic repository discovery
# ---------------------------------------------------------------------------

def _is_excluded(path: Path, repo_root: Path, excluded_dirs: set[str]) -> bool:
    try:
        rel = path.relative_to(repo_root)
    except ValueError:
        rel = path
    return any(part in excluded_dirs for part in rel.parts)


def _load_structured(path: Path) -> Any:
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def _looks_like_openapi(data: Any, path: Path) -> bool:
    if isinstance(data, dict) and isinstance(data.get("paths"), dict) and ("openapi" in data or "swagger" in data):
        return True
    return path.name.lower() in {"openapi.yaml", "openapi.yml", "openapi.json", "swagger.yaml", "swagger.yml", "swagger.json"}


def _looks_like_mcp_manifest(data: Any, path: Path) -> bool:
    name = path.name.lower()
    if "mcp" in name and path.suffix.lower() in {".json", ".yaml", ".yml"}:
        return True
    if not isinstance(data, dict):
        return False
    if any(key in data for key in ("mcpServers", "mcp_servers")):
        return True
    if data.get("protocol") == "mcp" or data.get("type") == "mcp":
        return True
    # A dedicated manifest with a top-level tools collection is considered MCP-like
    # only when metadata suggests a server/protocol. This avoids treating arbitrary
    # application YAML as MCP.
    meta_text = " ".join(str(data.get(k, "")) for k in ("name", "server", "protocol", "transport")).lower()
    return "mcp" in meta_text and "tools" in data


def discover_repository(repo_root: Path, collector: UnresolvedCollector, excluded_dirs: Optional[set[str]] = None) -> RepositorySources:
    root = repo_root.resolve()
    excluded = set(DEFAULT_EXCLUDED_DIRS)
    if excluded_dirs:
        excluded.update(excluded_dirs)
    result = RepositorySources()

    for path in root.rglob("*"):
        if not path.is_file() or _is_excluded(path, root, excluded):
            continue
        suffix = path.suffix.lower()
        if suffix == ".py":
            result.python_files.append(path)
            continue
        if suffix not in {".yaml", ".yml", ".json"}:
            continue
        # Skip very large generated payloads; record that the structured file was not inspected.
        try:
            if path.stat().st_size > 5 * 1024 * 1024:
                result.skipped_files.append(safe_relative(path, root))
                continue
            data = _load_structured(path)
        except Exception as exc:
            collector.add(
                category="structured_parse_error", file=path, suspected_type="structured_config",
                confidence="high", reason=f"Could not parse structured file: {exc}", severity="warning"
            )
            continue
        result.structured_files.append(path)
        if _looks_like_openapi(data, path):
            result.openapi_files.append(path)
        elif _looks_like_mcp_manifest(data, path):
            result.mcp_manifest_files.append(path)
        else:
            result.generic_config_files.append(path)

    result.python_files.sort()
    result.structured_files.sort()
    result.openapi_files.sort()
    result.mcp_manifest_files.sort()
    result.generic_config_files.sort()
    return result


# ---------------------------------------------------------------------------
# Python scanners
# ---------------------------------------------------------------------------

class AgentScanner(ast.NodeVisitor):
    """Discover known and generic agent constructors without executing code."""

    def __init__(self, source_path: Path, repo_root: Path, collector: UnresolvedCollector):
        self.source_path = source_path
        self.repo_root = repo_root.resolve()
        self.collector = collector
        self.agents: List[DraftEntity] = []
        self._processed_calls: set[int] = set()

    def visit_Assign(self, node: ast.Assign) -> Any:
        if isinstance(node.value, ast.Call):
            fallback = None
            for target in node.targets:
                if isinstance(target, ast.Name):
                    fallback = target.id
                    break
            self._inspect_agent_call(node.value, fallback_name=fallback)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if isinstance(node.value, ast.Call):
            fallback = node.target.id if isinstance(node.target, ast.Name) else None
            self._inspect_agent_call(node.value, fallback_name=fallback)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        self._inspect_agent_call(node, fallback_name=None)
        self.generic_visit(node)

    def _inspect_agent_call(self, node: ast.Call, fallback_name: Optional[str]) -> None:
        if id(node) in self._processed_calls:
            return
        constructor = callable_name(node.func)
        short = constructor.rsplit(".", 1)[-1]
        kw_names = {kw.arg for kw in node.keywords if kw.arg}
        agent_signal = bool(kw_names & {"name", "agent_id", "tools", "functions", "sub_agents", "agents", "instruction", "system_prompt", "model", "description"})
        known = short in KNOWN_AGENT_CONSTRUCTORS or short in AGENT_FACTORY_NAMES
        generic = (short.endswith("Agent") or short.lower().endswith("_agent")) and agent_signal
        if not (known or generic):
            # Preserve likely agent constructors that are not understood well enough.
            if "agent" in short.lower() and short[:1].isupper() and isinstance(node.func, (ast.Name, ast.Attribute)):
                self.collector.add(
                    category="unknown_agent_constructor",
                    file=self.source_path,
                    line=getattr(node, "lineno", 0),
                    symbol=constructor,
                    suspected_type="agent_constructor",
                    confidence="medium",
                    reason="Call name suggests an agent constructor but it did not expose recognized agent metadata.",
                    details={"keywords": sorted(x for x in kw_names if x)},
                )
            return

        name_value = keyword_value("name", node.keywords) or keyword_value("agent_id", node.keywords) or fallback_name
        if not isinstance(name_value, str) or not name_value:
            self.collector.add(
                category="agent_identity_unresolved",
                file=self.source_path,
                line=getattr(node, "lineno", 0),
                symbol=constructor,
                suspected_type="agent",
                confidence="high",
                reason="Agent-like constructor was found, but a stable runtime identity could not be inferred.",
            )
            self._processed_calls.add(id(node))
            return

        desc = (
            keyword_value("description", node.keywords)
            or keyword_value("instruction", node.keywords)
            or keyword_value("system_prompt", node.keywords)
            or ""
        )
        tools: List[str] = []
        for key in ("tools", "functions", "capabilities"):
            tools.extend(extract_string_list(keyword_value(key, node.keywords) or []))
        sub_agents: List[str] = []
        for key in ("sub_agents", "agents", "children", "delegates"):
            sub_agents.extend(extract_string_list(keyword_value(key, node.keywords) or []))
        # Custom workflow wrappers often name their child agents with keywords such
        # as validation_agent=..., fraud_agent=..., processing_agent=..., etc.
        # Preserve those relationships even when the constructor is framework-specific.
        for kw in node.keywords:
            if kw.arg and kw.arg != "name" and (kw.arg.endswith("_agent") or kw.arg in {"agent", "router", "worker"}):
                value = node_value(kw.value)
                if isinstance(value, str):
                    sub_agents.append(value)
        tools = list(dict.fromkeys(tools))
        sub_agents = [x for x in dict.fromkeys(sub_agents) if x != name_value]

        agent_type = short
        role = "specialist"
        pep_type = "tool_pep"
        if "Sequential" in agent_type or "Parallel" in agent_type or "Workflow" in agent_type:
            role = "workflow"
            pep_type = "none"
        elif sub_agents or "Router" in agent_type or "router" in name_value.lower():
            role = "router"
            pep_type = "route_pep"

        payload = {
            "agent_id": name_value,
            "symbol_name": fallback_name or name_value,
            "description": str(desc).strip().splitlines()[0] if desc else "Auto-discovered agent",
            "domain": "root" if name_value == "user_proxy_agent" else infer_domain_from_path(self.source_path),
            "role": role,
            "agent_type": agent_type,
            "detection_method": "known_constructor" if known else "generic_agent_constructor",
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
                "reference": f"{safe_relative(self.source_path, self.repo_root)}:{getattr(node, 'lineno', 0)}",
            },
        }
        self.agents.append(DraftEntity(payload, str(self.source_path), getattr(node, "lineno", 0)))
        self._processed_calls.add(id(node))


class ToolScanner(ast.NodeVisitor):
    """Discover decorated tools, public functions in tool modules, and agent-referenced functions."""

    def __init__(self, source_path: Path, repo_root: Path, collector: UnresolvedCollector, referenced_tools: set[str]):
        self.source_path = source_path
        self.repo_root = repo_root.resolve()
        self.collector = collector
        self.referenced_tools = referenced_tools
        self.tools: List[DraftEntity] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._visit_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._visit_function(node)
        self.generic_visit(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        decorators = {decorator_qualified_name(dec) for dec in node.decorator_list}
        decorated = any(name in TOOL_DECORATORS or name.rsplit(".", 1)[-1] in {"tool", "function_tool", "register_tool", "kernel_function"} for name in decorators)
        parts = {p.lower() for p in self.source_path.parts}
        in_tool_module = bool(parts & TOOL_DIR_NAMES) or "mcp" in self.source_path.name.lower()
        referenced = node.name in self.referenced_tools
        if node.name.startswith("_") and not decorated and not referenced:
            return
        if not (decorated or in_tool_module or referenced):
            return

        source_type = "mcp" if decorated and any("mcp" in d or d.endswith(".tool") or d == "tool" for d in decorators) or "mcp" in self.source_path.as_posix().lower() else "python"
        action_type = infer_action_type(node.name)
        http_calls = self._find_http_calls(node)
        tool = {
            "tool_id": node.name,
            "display_name": (extract_function_docstring(node).strip().splitlines() or [f"Auto-discovered tool {node.name}"])[0],
            "source_type": source_type,
            "source": source_type,  # backward-compatible field used by integration code
            "domain": infer_domain_from_path(self.source_path),
            "action_type": action_type,
            "has_side_effects": action_type not in {"read", "compute"},
            "risk_level": infer_risk_level(action_type, node.name),
            "requires_live_decision": action_type in {"financial_write", "state_change"},
            "audit_required": action_type not in {"read", "compute"},
            "allowed_callers": [],
            "calls_api": [x[1] for x in http_calls if x[1]],
            "calls_api_methods": [{"method": x[0], "path": x[1]} for x in http_calls if x[1]],
            "pii_fields": [],
            "compliance_tags": [],
            "idempotency_key": None,
            "operation_class": operation_class(action_type),
            "status": "provisional",
            "detection_method": "decorator" if decorated else ("agent_reference" if referenced else "tool_module"),
            "source": {
                "provided_by": "task2_scanner",
                "reference": f"{safe_relative(self.source_path, self.repo_root)}:{node.lineno}",
            },
        }
        self.tools.append(DraftEntity(tool, str(self.source_path), node.lineno))

    def _find_http_calls(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> List[Tuple[str, Optional[str]]]:
        calls: List[Tuple[str, Optional[str]]] = []
        for child in ast.walk(node):
            if not isinstance(child, ast.Call) or not isinstance(child.func, ast.Attribute):
                continue
            method = child.func.attr.lower()
            if method not in HTTP_METHODS and method not in {"request"}:
                continue
            base = callable_name(child.func.value).lower()
            likely_http = any(token in base for token in ("client", "httpx", "requests", "session", "aiohttp", "api"))
            if not likely_http:
                continue
            method_name = method.upper()
            if method == "request":
                candidate = keyword_value("method", child.keywords)
                if isinstance(candidate, str):
                    method_name = candidate.upper()
            url_node = child.args[0] if child.args else keyword_node("url", child.keywords)
            path, dynamic = extract_static_url_path(url_node)
            if path:
                calls.append((method_name, path))
            if dynamic and not path:
                self.collector.add(
                    category="dynamic_http_target",
                    file=self.source_path,
                    line=getattr(child, "lineno", 0),
                    symbol=node.name,
                    suspected_type="tool_to_api",
                    confidence="high",
                    reason="Outbound HTTP call was found but its target URL/path is fully dynamic.",
                    details={"method": method_name},
                )
        # stable order + dedupe
        seen: set[Tuple[str, Optional[str]]] = set()
        out = []
        for item in calls:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out


class ApiScanner(ast.NodeVisitor):
    """Discover FastAPI/Flask-like route decorators on any Python module."""

    def __init__(self, source_path: Path, repo_root: Path, collector: UnresolvedCollector):
        self.source_path = source_path
        self.repo_root = repo_root.resolve()
        self.collector = collector
        self.apis: List[DraftEntity] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._visit_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._visit_function(node)
        self.generic_visit(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        routes: List[Tuple[str, str]] = []
        for dec in node.decorator_list:
            routes.extend(self._route_info(dec, node))
        for index, (method, path) in enumerate(routes):
            api_id = node.name if len(routes) == 1 else f"{node.name}_{method.lower()}"
            self.apis.append(DraftEntity(self._build_api(node, api_id, method, path), str(self.source_path), node.lineno))

    def _route_info(self, dec: ast.AST, node: ast.AST) -> List[Tuple[str, str]]:
        if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
            return []
        method = dec.func.attr.lower()
        owner = callable_name(dec.func.value)
        if method in HTTP_METHODS:
            raw_node = dec.args[0] if dec.args else keyword_node("path", dec.keywords) or keyword_node("rule", dec.keywords)
            path, dynamic = extract_static_url_path(raw_node)
            if path:
                return [(method.upper(), path)]
            if dynamic:
                self.collector.add(
                    category="dynamic_api_route", file=self.source_path, line=getattr(node, "lineno", 0),
                    symbol=callable_name(dec.func), suspected_type="api_route", confidence="high",
                    reason="HTTP route decorator was found but the route path is dynamic."
                )
            return []
        if method in {"api_route", "route"}:
            raw_node = dec.args[0] if dec.args else keyword_node("path", dec.keywords) or keyword_node("rule", dec.keywords)
            path, dynamic = extract_static_url_path(raw_node)
            methods = extract_string_list(keyword_value("methods", dec.keywords) or [])
            if not methods and method == "route":
                methods = ["GET"]
            if path:
                return [(m.upper(), path) for m in methods if m.lower() in HTTP_METHODS]
            if dynamic:
                self.collector.add(
                    category="dynamic_api_route", file=self.source_path, line=getattr(node, "lineno", 0),
                    symbol=f"{owner}.{method}", suspected_type="api_route", confidence="high",
                    reason="Generic route decorator was found but its route path is dynamic."
                )
        return []

    def _build_api(self, node: ast.FunctionDef | ast.AsyncFunctionDef, api_id: str, method: str, path: str) -> Dict[str, Any]:
        action_type = infer_action_type(api_id, method, path)
        reads, writes = self._infer_database_access(node)
        return {
            "api_id": api_id,
            "display_name": (extract_function_docstring(node).strip().splitlines() or [f"Auto-discovered API endpoint {api_id}"])[0],
            "service": self.source_path.parent.name or "service",
            "base_url": None,
            "path": path,
            "method": method,
            "domain": infer_domain_from_path(self.source_path),
            "action_type": action_type,
            "has_side_effects": method not in {"GET", "HEAD", "OPTIONS"},
            "risk_level": infer_risk_level(action_type, api_id),
            "requires_auth": True,
            "audit_required": method not in {"GET", "HEAD", "OPTIONS"},
            "reads_tables": reads,
            "writes_tables": writes,
            "pii_fields": [],
            "compliance_tags": [],
            "idempotency_key": None,
            "operation_class": operation_class(action_type),
            "allowed_callers": [],
            "status": "provisional",
            "source_type": "python_route",
            "source": {
                "provided_by": "task2_scanner",
                "reference": f"{safe_relative(self.source_path, self.repo_root)}:{node.lineno}",
            },
        }

    def _infer_database_access(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> Tuple[List[str], List[str]]:
        reads: List[str] = []
        writes: List[str] = []
        variable_models: Dict[str, str] = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Assign) and isinstance(child.value, ast.Call):
                model = self._model_from_constructor(child.value)
                if model:
                    for target in child.targets:
                        if isinstance(target, ast.Name):
                            variable_models[target.id] = model
            if not isinstance(child, ast.Call):
                continue
            # select(Model), update(Model), delete(Model), insert(Model)
            func_short = callable_name(child.func).rsplit(".", 1)[-1]
            if func_short in {"select", "query", "get"}:
                reads.extend(self._extract_models(child))
            if func_short in {"update", "delete", "insert"}:
                writes.extend(self._extract_models(child))
            if isinstance(child.func, ast.Attribute):
                attr = child.func.attr
                if attr in {"scalar", "scalars", "execute"}:
                    for arg in child.args:
                        if isinstance(arg, ast.Call):
                            nested = callable_name(arg.func).rsplit(".", 1)[-1]
                            if nested in {"select", "query"}:
                                reads.extend(self._extract_models(arg))
                            if nested in {"update", "delete", "insert"}:
                                writes.extend(self._extract_models(arg))
                if attr == "add" and child.args:
                    arg = child.args[0]
                    if isinstance(arg, ast.Call):
                        model = self._model_from_constructor(arg)
                        if model:
                            writes.append(model)
                    elif isinstance(arg, ast.Name) and arg.id in variable_models:
                        writes.append(variable_models[arg.id])
                if attr in {"delete", "merge"} and child.args:
                    arg = child.args[0]
                    if isinstance(arg, ast.Name) and arg.id in variable_models:
                        writes.append(variable_models[arg.id])
        return list(dict.fromkeys(reads)), list(dict.fromkeys(writes))

    @staticmethod
    def _model_from_constructor(node: ast.Call) -> Optional[str]:
        name = callable_name(node.func).rsplit(".", 1)[-1]
        return name if name and name[:1].isupper() else None

    @staticmethod
    def _extract_models(node: ast.Call) -> List[str]:
        models = []
        for arg in node.args:
            name = callable_name(arg)
            if name:
                models.append(name.rsplit(".", 1)[-1])
        return models


class DatabaseScanner(ast.NodeVisitor):
    """Discover SQLAlchemy, SQLModel, and Django-style model/table declarations."""

    def __init__(self, source_path: Path, repo_root: Path):
        self.source_path = source_path
        self.repo_root = repo_root.resolve()
        self.databases: List[DraftEntity] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        tablename = self._find_tablename(node)
        base_names = {callable_name(base).rsplit(".", 1)[-1] for base in node.bases}
        model_like = bool(tablename) or bool(base_names & {"Base", "Model", "SQLModel"})
        if node.name in {"Base", "DeclarativeBase"} and not tablename:
            model_like = False
        if model_like:
            table_name = tablename or self._to_table_name(node.name)
            columns = self._column_names(node)
            classification = infer_data_classification(table_name, columns)
            contains_pii = classification in {"regulated", "confidential"} and any(x in " ".join(columns).lower() for x in ("name", "email", "ssn", "address", "customer", "phone"))
            contains_financial = any(term in f"{table_name} {' '.join(columns)}".lower() for term in ("account", "transaction", "balance", "amount", "ledger", "payment", "loan"))
            contains_audit = "audit" in table_name.lower()
            payload = {
                "database_id": table_name,
                "model_name": node.name,
                "display_name": f"{node.name} table",
                "db_type": "relational",
                "engine": "unknown",
                "table_name": table_name,
                "classification": classification,
                "contains_pii": contains_pii,
                "contains_financial": contains_financial,
                "contains_audit": contains_audit,
                "columns": columns,
                "allowed_operations": ["SELECT", "INSERT", "UPDATE", "DELETE"],
                "allowed_api_callers": [],
                "compliance_tags": [],
                "risk_level": infer_risk_level("read", table_name, classification),
                "immutable": contains_audit,
                "status": "provisional",
                "source": {
                    "provided_by": "task2_scanner",
                    "reference": f"{safe_relative(self.source_path, self.repo_root)}:{node.lineno}",
                },
            }
            self.databases.append(DraftEntity(payload, str(self.source_path), node.lineno))
        self.generic_visit(node)

    @staticmethod
    def _find_tablename(node: ast.ClassDef) -> Optional[str]:
        for child in node.body:
            if isinstance(child, (ast.Assign, ast.AnnAssign)):
                targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                value = child.value
                for target in targets:
                    if isinstance(target, ast.Name) and target.id in {"__tablename__", "table_name"}:
                        return get_string(value)
        return None

    @staticmethod
    def _column_names(node: ast.ClassDef) -> List[str]:
        names: List[str] = []
        for child in node.body:
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name) and not target.id.startswith("_"):
                        names.append(target.id)
            if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name) and not child.target.id.startswith("_"):
                names.append(child.target.id)
        return list(dict.fromkeys(names))

    @staticmethod
    def _to_table_name(name: str) -> str:
        snake = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
        return snake if snake.endswith("s") else snake + "s"


class EventScanner(ast.NodeVisitor):
    """Discover explicit event handlers, subscriptions, schedules, and trigger functions."""

    def __init__(self, source_path: Path, repo_root: Path, agent_aliases: Dict[str, str]):
        self.source_path = source_path
        self.repo_root = repo_root.resolve()
        self.agent_aliases = agent_aliases
        self.events: List[DraftEntity] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._visit_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._visit_function(node)
        self.generic_visit(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        decorators = [dec for dec in node.decorator_list if decorator_name(dec)]
        event_dec: Optional[ast.expr] = None
        for dec in decorators:
            if decorator_name(dec) in EVENT_DECORATOR_NAMES:
                event_dec = dec
                break
        trigger_name = node.name.lower()
        parts = {p.lower() for p in self.source_path.parts}
        tool_like_module = bool(parts & TOOL_DIR_NAMES) or "mcp" in self.source_path.as_posix().lower()
        tool_decorated = any(decorator_name(dec) in {"tool", "function_tool", "register_tool"} for dec in node.decorator_list)
        explicit_trigger_fn = (
            not tool_like_module
            and not tool_decorated
            and trigger_name.startswith("trigger_")
            and any(x in trigger_name for x in ("event", "eod", "schedule", "batch", "reconcile"))
        )
        if event_dec is None and not explicit_trigger_fn:
            return

        event_name = node.name
        trigger_type = "function_trigger" if explicit_trigger_fn else decorator_name(event_dec) or "event"
        if isinstance(event_dec, ast.Call):
            candidate = node_value(event_dec.args[0]) if event_dec.args else keyword_value("event_type", event_dec.keywords) or keyword_value("name", event_dec.keywords)
            if isinstance(candidate, str):
                event_name = candidate
        target_agents: List[str] = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                callee = callable_name(child.func)
                root = callee.split(".", 1)[0]
                runtime = self.agent_aliases.get(root)
                if runtime:
                    target_agents.append(runtime)
        event_id = f"event.{re.sub(r'[^a-zA-Z0-9_]+', '_', event_name).strip('_').lower()}"
        payload = {
            "event_id": event_id,
            "event_name": event_name,
            "handler": node.name,
            "trigger_type": trigger_type,
            "domain": infer_domain_from_path(self.source_path),
            "target_agents": list(dict.fromkeys(target_agents)),
            "risk_level": 3 if any(x in event_name.lower() for x in ("eod", "ledger", "transfer", "payment")) else 2,
            "status": "provisional",
            "source": {
                "provided_by": "task2_scanner",
                "reference": f"{safe_relative(self.source_path, self.repo_root)}:{node.lineno}",
            },
        }
        self.events.append(DraftEntity(payload, str(self.source_path), node.lineno))


# ---------------------------------------------------------------------------
# Structured spec scanners
# ---------------------------------------------------------------------------

def scan_openapi_files(paths: Iterable[Path], repo_root: Path, collector: UnresolvedCollector) -> List[DraftEntity]:
    apis: List[DraftEntity] = []
    for path in paths:
        try:
            doc = _load_structured(path) or {}
        except Exception as exc:
            collector.add(category="openapi_parse_error", file=path, suspected_type="openapi", confidence="high", reason=str(exc), severity="error")
            continue
        if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict):
            collector.add(category="openapi_missing_paths", file=path, suspected_type="openapi", confidence="high", reason="OpenAPI document does not contain a valid paths mapping.")
            continue
        servers = doc.get("servers") if isinstance(doc.get("servers"), list) else []
        base_url = None
        if servers and isinstance(servers[0], dict) and isinstance(servers[0].get("url"), str):
            base_url = servers[0]["url"]
        for route, operations in doc["paths"].items():
            if not isinstance(route, str) or not isinstance(operations, dict):
                continue
            for method, operation in operations.items():
                if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                    continue
                operation_id = operation.get("operationId") or f"{method.lower()}_{re.sub(r'[^a-zA-Z0-9]+', '_', route).strip('_')}"
                action_type = infer_action_type(str(operation_id), method, route)
                tags = operation.get("tags") if isinstance(operation.get("tags"), list) else []
                tag_text = " ".join(str(x) for x in tags).lower()
                domain = "front" if "front" in tag_text else "mid" if "mid" in tag_text else "back" if "back" in tag_text else "shared"
                security = operation.get("security", doc.get("security"))
                payload = {
                    "api_id": str(operation_id),
                    "display_name": str(operation.get("summary") or operation.get("description") or operation_id).splitlines()[0],
                    "service": str((doc.get("info") or {}).get("title") or path.stem),
                    "base_url": base_url,
                    "path": normalize_path(route),
                    "method": method.upper(),
                    "domain": domain,
                    "action_type": action_type,
                    "has_side_effects": method.upper() not in {"GET", "HEAD", "OPTIONS"},
                    "risk_level": infer_risk_level(action_type, str(operation_id)),
                    "requires_auth": bool(security),
                    "audit_required": method.upper() not in {"GET", "HEAD", "OPTIONS"},
                    "reads_tables": [],
                    "writes_tables": [],
                    "pii_fields": [],
                    "compliance_tags": [str(x) for x in tags],
                    "idempotency_key": None,
                    "operation_class": operation_class(action_type),
                    "allowed_callers": [],
                    "status": "provisional",
                    "source_type": "openapi",
                    "source": {"provided_by": "task2_scanner", "reference": safe_relative(path, repo_root)},
                }
                apis.append(DraftEntity(payload, str(path), 0))
    return apis


def _iter_manifest_tools(doc: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any], str]]:
    def from_collection(collection: Any, server_name: str) -> Iterable[Tuple[str, Dict[str, Any], str]]:
        if isinstance(collection, list):
            for item in collection:
                if isinstance(item, dict) and isinstance(item.get("name"), str):
                    yield item["name"], item, server_name
        elif isinstance(collection, dict):
            for name, item in collection.items():
                if isinstance(item, dict):
                    payload = dict(item)
                    payload.setdefault("name", name)
                    yield str(name), payload, server_name
                else:
                    yield str(name), {"name": name}, server_name

    yield from from_collection(doc.get("tools"), str(doc.get("name") or doc.get("server") or "mcp"))
    servers = doc.get("mcpServers") or doc.get("mcp_servers") or doc.get("servers")
    if isinstance(servers, dict):
        for server_name, server in servers.items():
            if isinstance(server, dict):
                yield from from_collection(server.get("tools") or server.get("capabilities"), str(server_name))
    elif isinstance(servers, list):
        for server in servers:
            if isinstance(server, dict):
                yield from from_collection(server.get("tools") or server.get("capabilities"), str(server.get("name") or "mcp"))


def scan_mcp_manifest_files(paths: Iterable[Path], repo_root: Path, collector: UnresolvedCollector) -> List[DraftEntity]:
    tools: List[DraftEntity] = []
    for path in paths:
        try:
            doc = _load_structured(path) or {}
        except Exception as exc:
            collector.add(category="mcp_manifest_parse_error", file=path, suspected_type="mcp_manifest", confidence="high", reason=str(exc), severity="error")
            continue
        if not isinstance(doc, dict):
            collector.add(category="mcp_manifest_shape_unknown", file=path, suspected_type="mcp_manifest", confidence="high", reason="MCP manifest root is not a mapping.")
            continue
        found = 0
        for tool_id, item, server_name in _iter_manifest_tools(doc):
            found += 1
            action_type = infer_action_type(tool_id)
            description = str(item.get("description") or f"MCP manifest tool {tool_id}")
            payload = {
                "tool_id": tool_id,
                "display_name": description.splitlines()[0],
                "source_type": "mcp_manifest",
                "source": "mcp",
                "mcp_server": server_name,
                "domain": "shared",
                "action_type": action_type,
                "has_side_effects": action_type not in {"read", "compute"},
                "risk_level": infer_risk_level(action_type, tool_id),
                "requires_live_decision": action_type in {"financial_write", "state_change"},
                "audit_required": action_type not in {"read", "compute"},
                "allowed_callers": [],
                "calls_api": [],
                "calls_api_methods": [],
                "pii_fields": [],
                "compliance_tags": [],
                "idempotency_key": None,
                "operation_class": operation_class(action_type),
                "input_schema": item.get("inputSchema") or item.get("input_schema"),
                "status": "provisional",
                "detection_method": "mcp_manifest",
                "source": {"provided_by": "task2_scanner", "reference": safe_relative(path, repo_root)},
            }
            tools.append(DraftEntity(payload, str(path), 0))
        if found == 0:
            collector.add(
                category="mcp_runtime_introspection_required",
                file=path,
                suspected_type="mcp_manifest",
                confidence="high",
                reason="MCP server configuration was found, but it does not statically enumerate tools. Runtime MCP tool-list introspection is required to complete this interface.",
                details={"top_level_keys": sorted(str(k) for k in doc.keys())},
            )
    return tools


def scan_suspicious_generic_configs(paths: Iterable[Path], repo_root: Path, collector: UnresolvedCollector) -> None:
    interesting_keys = {"agents", "agent", "tools", "tool", "routes", "workflows", "workflow", "interfaces", "endpoints", "events", "triggers"}
    for path in paths:
        try:
            doc = _load_structured(path)
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        keys = {str(k).lower() for k in doc.keys()}
        hit = sorted(keys & interesting_keys)
        if hit:
            collector.add(
                category="unrecognized_interface_config",
                file=path,
                suspected_type="structured_interface_config",
                confidence="medium",
                reason="Structured configuration appears to describe agents/tools/workflows/interfaces, but no installed Task 2 parser recognizes its schema.",
                details={"matching_keys": hit},
            )


# ---------------------------------------------------------------------------
# Interaction graph + unresolved reference resolution
# ---------------------------------------------------------------------------

class InteractionEdgeBuilder:
    def __init__(
        self,
        agents: List[DraftEntity],
        tools: List[DraftEntity],
        apis: List[DraftEntity],
        databases: List[DraftEntity],
        events: List[DraftEntity],
        collector: UnresolvedCollector,
    ):
        self.agents = agents
        self.tools = tools
        self.apis = apis
        self.databases = databases
        self.events = events
        self.collector = collector
        self.edges: List[DraftEntity] = []
        self._agent_alias: Dict[str, DraftEntity] = {}
        for agent in agents:
            all_aliases = [agent.payload.get("agent_id"), agent.payload.get("symbol_name"), *agent.payload.get("aliases", [])]
            for alias in all_aliases:
                if alias:
                    self._agent_alias[str(alias)] = agent
        self._db_alias: Dict[str, DraftEntity] = {}
        for db in databases:
            for alias in (db.payload.get("database_id"), db.payload.get("table_name"), db.payload.get("model_name")):
                if alias:
                    self._db_alias[str(alias)] = db

    def build_edges(self) -> None:
        self._build_agent_to_tool_edges()
        self._build_tool_to_api_edges()
        self._build_api_to_database_edges()
        self._build_agent_to_agent_edges()
        self._build_event_to_agent_edges()

    def _build_agent_to_tool_edges(self) -> None:
        tool_ids = {tool.payload["tool_id"] for tool in self.tools}
        for agent in self.agents:
            for tool_id in agent.payload.get("authorized_tools", []):
                if tool_id not in tool_ids:
                    self.collector.add(
                        category="unresolved_tool_reference", file=agent.source_file, line=agent.source_line,
                        symbol=tool_id, suspected_type="tool", confidence="high",
                        reason=f"Agent {agent.payload['agent_id']} references a tool that was not discovered."
                    )
                    continue
                tool = self._get_tool(tool_id)
                op = tool.payload.get("operation_class", "read") if tool else "read"
                self._add_edge(
                    edge_type="agent_to_tool", from_id=agent.payload["agent_id"], to_id=tool_id,
                    risk_level=max(2, int(tool.payload.get("risk_level", 2)) if tool else 2),
                    pep_required=True, pep_type="tool_pep", http_method=None, db_operation=None,
                    operation_class=op, tool=tool, from_entity=agent,
                )

    def _build_tool_to_api_edges(self) -> None:
        api_by_path: Dict[str, List[DraftEntity]] = {}
        for api in self.apis:
            api_by_path.setdefault(normalize_path_template(str(api.payload.get("path") or "/")), []).append(api)
        for tool in self.tools:
            calls = tool.payload.get("calls_api_methods") or [{"method": None, "path": x} for x in tool.payload.get("calls_api", [])]
            for call in calls:
                path = normalize_path_template(str(call.get("path") or "/"))
                method = str(call.get("method") or "").upper() or None
                candidates = api_by_path.get(path, [])
                if method:
                    method_candidates = [x for x in candidates if str(x.payload.get("method") or "").upper() == method]
                    if method_candidates:
                        candidates = method_candidates
                if not candidates:
                    self.collector.add(
                        category="unresolved_api_target", file=tool.source_file, line=tool.source_line,
                        symbol=path, suspected_type="api", confidence="high",
                        reason=f"Tool {tool.payload['tool_id']} calls an HTTP path that does not match a discovered API/OpenAPI endpoint.",
                        details={"method": method},
                    )
                    continue
                api = candidates[0]
                self._add_edge(
                    edge_type="tool_to_api", from_id=tool.payload["tool_id"], to_id=api.payload["api_id"],
                    risk_level=max(int(tool.payload.get("risk_level", 2)), int(api.payload.get("risk_level", 2))),
                    pep_required=True, pep_type="api_pep", http_method=api.payload.get("method"), db_operation=None,
                    operation_class=str(api.payload.get("operation_class") or "read"), tool=tool, api=api,
                )

    def _build_api_to_database_edges(self) -> None:
        for api in self.apis:
            for raw in api.payload.get("reads_tables", []):
                db = self._db_alias.get(str(raw))
                if not db:
                    self.collector.add(
                        category="unresolved_database_reference", file=api.source_file, line=api.source_line,
                        symbol=str(raw), suspected_type="database", confidence="medium",
                        reason=f"API {api.payload['api_id']} appears to read a model/table that was not discovered."
                    )
                    continue
                self._add_edge(
                    edge_type="api_to_database", from_id=api.payload["api_id"], to_id=db.payload["database_id"],
                    risk_level=max(2, int(db.payload.get("risk_level", 2))), pep_required=True, pep_type="data_pep",
                    http_method=api.payload.get("method"), db_operation="SELECT", operation_class="read", api=api, db=db,
                )
            for raw in api.payload.get("writes_tables", []):
                db = self._db_alias.get(str(raw))
                if not db:
                    self.collector.add(
                        category="unresolved_database_reference", file=api.source_file, line=api.source_line,
                        symbol=str(raw), suspected_type="database", confidence="medium",
                        reason=f"API {api.payload['api_id']} appears to write a model/table that was not discovered."
                    )
                    continue
                self._add_edge(
                    edge_type="api_to_database", from_id=api.payload["api_id"], to_id=db.payload["database_id"],
                    risk_level=max(3, int(db.payload.get("risk_level", 2))), pep_required=True, pep_type="data_pep",
                    http_method=api.payload.get("method"), db_operation="UPDATE", operation_class="write", api=api, db=db,
                )

    def _build_agent_to_agent_edges(self) -> None:
        for agent in self.agents:
            for target in agent.payload.get("authorized_transfers", []):
                target_agent = self._agent_alias.get(str(target))
                if not target_agent:
                    self.collector.add(
                        category="unresolved_agent_reference", file=agent.source_file, line=agent.source_line,
                        symbol=target, suspected_type="agent", confidence="high",
                        reason=f"Agent {agent.payload['agent_id']} references a downstream agent that was not discovered."
                    )
                    continue
                runtime_target = str(target_agent.payload["agent_id"])
                self._add_edge(
                    edge_type="agent_to_agent", from_id=agent.payload["agent_id"], to_id=runtime_target,
                    risk_level=2, pep_required=True, pep_type="route_pep", http_method=None, db_operation=None,
                    operation_class="read", from_entity=agent, to_entity=target_agent,
                )

    def _build_event_to_agent_edges(self) -> None:
        agent_ids = {agent.payload["agent_id"] for agent in self.agents}
        for event in self.events:
            for target in event.payload.get("target_agents", []):
                if target not in agent_ids:
                    continue
                self._add_edge(
                    edge_type="event_to_agent", from_id=event.payload["event_id"], to_id=target,
                    risk_level=int(event.payload.get("risk_level", 2)), pep_required=True, pep_type="event_pep",
                    http_method=None, db_operation=None, operation_class="read", to_entity=self._get_agent(target),
                    trigger=str(event.payload.get("trigger_type") or "event"),
                )

    def _get_agent(self, agent_id: str) -> Optional[DraftEntity]:
        return self._agent_alias.get(agent_id)

    def _get_tool(self, tool_id: str) -> Optional[DraftEntity]:
        return next((x for x in self.tools if x.payload["tool_id"] == tool_id), None)

    def _infer_workflow_context(self, from_id: str, to_id: str, edge_type: str, from_entity: Optional[DraftEntity], to_entity: Optional[DraftEntity]) -> str:
        tags = ["eod", "ledger", "reconcile", "back_office", "front_office", "mid_office", "planning", "forecast", "customer_service", "fraud", "transaction", "chatbot", "support"]
        combined = f"{from_id} {to_id} {edge_type}".lower()
        for tag in tags:
            if tag in combined:
                return tag
        for entity in (from_entity, to_entity):
            if entity and entity.payload.get("domain"):
                return f"workflow_{entity.payload['domain']}"
        return "shared"

    @staticmethod
    def _infer_data_type(edge_type: str, to_type: str, api: Optional[DraftEntity], db: Optional[DraftEntity], tool: Optional[DraftEntity]) -> str:
        if to_type == "database" and db:
            classification = db.payload.get("classification", "internal")
            if db.payload.get("contains_financial"):
                return "financial"
            if db.payload.get("contains_pii") or classification in {"regulated", "confidential"}:
                return "personal"
            if db.payload.get("contains_audit"):
                return "audit"
            return "internal"
        if to_type == "api" and api:
            path = str(api.payload.get("path") or "").lower()
            if any(x in path for x in ("customer", "profile", "identity")):
                return "personal"
            if any(x in path for x in ("transaction", "transfer", "ledger", "payment")):
                return "financial"
            return "service"
        if to_type == "tool" and tool:
            if tool.payload.get("action_type") == "financial_write":
                return "financial"
            return "operational" if tool.payload.get("action_type") == "read" else "service"
        if edge_type == "agent_to_agent":
            return "workflow_control"
        if edge_type == "event_to_agent":
            return "event_control"
        return "unknown"

    @staticmethod
    def _infer_authentication_method(edge_type: str, tool: Optional[DraftEntity]) -> str:
        if edge_type == "tool_to_api":
            return "api_auth_unknown"
        if edge_type == "api_to_database":
            return "service_identity_unknown"
        if edge_type == "agent_to_tool":
            return "mcp_or_workload_identity" if tool and str(tool.payload.get("source")).startswith("mcp") else "in_process_identity"
        if edge_type == "agent_to_agent":
            return "workload_identity"
        if edge_type == "event_to_agent":
            return "event_source_identity"
        return "unknown"

    @staticmethod
    def _infer_trust_boundary(edge_type: str, tool: Optional[DraftEntity]) -> str:
        if edge_type == "tool_to_api":
            return "service_boundary"
        if edge_type == "api_to_database":
            return "data_boundary"
        if edge_type == "agent_to_tool":
            return "mcp_boundary" if tool and str(tool.payload.get("source")).startswith("mcp") else "agent_tool_boundary"
        if edge_type == "agent_to_agent":
            return "agent_boundary"
        if edge_type == "event_to_agent":
            return "event_boundary"
        return "unknown"

    @staticmethod
    def _infer_action(edge_type: str, http_method: Optional[str], db_operation: Optional[str]) -> str:
        if edge_type == "agent_to_tool":
            return "call_tool"
        if edge_type == "tool_to_api":
            return "invoke_api"
        if edge_type == "api_to_database":
            return f"db_{str(db_operation or 'access').lower()}"
        if edge_type == "agent_to_agent":
            return "transfer_control"
        if edge_type == "event_to_agent":
            return "trigger_agent"
        return "unknown"

    def _add_edge(
        self,
        *,
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
        trigger: Optional[str] = None,
    ) -> None:
        edge_id = f"edge_{len(self.edges) + 1:03d}"
        if edge_type == "event_to_agent":
            from_type, to_type = "event", "subject"
        else:
            from_type = "subject" if edge_type in {"agent_to_agent", "agent_to_tool"} else ("tool" if edge_type == "tool_to_api" else "api")
            to_type = "subject" if edge_type == "agent_to_agent" else ("tool" if edge_type == "agent_to_tool" else ("api" if edge_type == "tool_to_api" else "database"))
        payload = {
            "edge_id": edge_id,
            "edge_type": edge_type,
            "from_id": from_id,
            "from_type": from_type,
            "to_id": to_id,
            "to_type": to_type,
            "action": self._infer_action(edge_type, http_method, db_operation),
            "data_type": self._infer_data_type(edge_type, to_type, api, db, tool),
            "risk_level": min(4, max(1, int(risk_level))),
            "side_effects": operation_class != "read",
            "authentication_method": self._infer_authentication_method(edge_type, tool),
            "trust_boundary": self._infer_trust_boundary(edge_type, tool),
            "workflow_context": self._infer_workflow_context(from_id, to_id, edge_type, from_entity, to_entity),
            "pep_required": pep_required,
            "pep_type": pep_type,
            "trigger": trigger,
            "required_state": [],
            "http_method": http_method,
            "db_operation": db_operation,
            "operation_class": operation_class,
            "status": "provisional",
            "source": {"provided_by": "task2_scanner", "reference": "task2_scanner"},
        }
        self.edges.append(DraftEntity(payload, "task2_scanner", 0))


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------

def parse_python_file(path: Path, collector: Optional[UnresolvedCollector] = None) -> Optional[ast.AST]:
    try:
        return ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    except (UnicodeDecodeError, SyntaxError) as exc:
        if collector:
            collector.add(
                category="python_parse_error", file=path, line=getattr(exc, "lineno", 0) or 0,
                suspected_type="python_source", confidence="high", reason=str(exc), severity="error"
            )
        return None


def scan_agents(source_files: Iterable[Path], repo_root: Path, collector: Optional[UnresolvedCollector] = None) -> List[DraftEntity]:
    collector = collector or UnresolvedCollector(repo_root)
    agents: List[DraftEntity] = []
    for source in source_files:
        tree = parse_python_file(source, collector)
        if tree is None:
            continue
        scanner = AgentScanner(source, repo_root, collector)
        scanner.visit(tree)
        agents.extend(scanner.agents)
    return dedupe_entities(agents, "agent_id")



def discover_agent_aliases(
    source_files: Iterable[Path],
    repo_root: Path,
    agents: List[DraftEntity],
    collector: Optional[UnresolvedCollector] = None,
) -> Dict[str, str]:
    """Resolve common interprocedural aliases without executing repository code.

    This handles patterns such as::

        workflow = build_workflow(agent_a=fraud_agent)
        router = LlmAgent(sub_agents=[workflow])

    where build_workflow() returns an agent whose canonical runtime ``name`` is
    different from the caller-side variable name. It also resolves unique
    factory-parameter bindings (e.g. ``merger_agent`` -> ``representative_merge_agent``).
    """
    collector = collector or UnresolvedCollector(repo_root)
    aliases: Dict[str, str] = {}
    for agent in agents:
        runtime = str(agent.payload.get("agent_id") or "")
        for alias in (runtime, agent.payload.get("symbol_name")):
            if alias:
                aliases[str(alias)] = runtime

    function_defs: Dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    factory_returns: Dict[str, str] = {}
    trees: List[ast.AST] = []

    for source in source_files:
        tree = parse_python_file(source, collector)
        if tree is None:
            continue
        trees.append(tree)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            function_defs[node.name] = node
            local_agent_symbols: Dict[str, str] = {}
            for child in node.body:
                if isinstance(child, ast.Assign) and isinstance(child.value, ast.Call):
                    runtime_name = keyword_value("name", child.value.keywords) or keyword_value("agent_id", child.value.keywords)
                    if isinstance(runtime_name, str):
                        for target in child.targets:
                            if isinstance(target, ast.Name):
                                local_agent_symbols[target.id] = runtime_name
                if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name) and isinstance(child.value, ast.Call):
                    runtime_name = keyword_value("name", child.value.keywords) or keyword_value("agent_id", child.value.keywords)
                    if isinstance(runtime_name, str):
                        local_agent_symbols[child.target.id] = runtime_name
            for ret in [x for x in ast.walk(node) if isinstance(x, ast.Return)]:
                if isinstance(ret.value, ast.Call):
                    runtime_name = keyword_value("name", ret.value.keywords) or keyword_value("agent_id", ret.value.keywords)
                    if isinstance(runtime_name, str):
                        factory_returns[node.name] = runtime_name
                        break
                if isinstance(ret.value, ast.Name) and ret.value.id in local_agent_symbols:
                    factory_returns[node.name] = local_agent_symbols[ret.value.id]
                    break

    # Resolve aliases iteratively because factory arguments can themselves be aliases.
    parameter_proposals: Dict[str, set[str]] = {}
    for _ in range(3):
        changed = False
        for tree in trees:
            for node in ast.walk(tree):
                if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                    continue
                value = node.value
                if not isinstance(value, ast.Call):
                    continue
                called = callable_name(value.func).rsplit(".", 1)[-1]
                if called not in factory_returns:
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                runtime_return = factory_returns[called]
                for target in targets:
                    if isinstance(target, ast.Name) and aliases.get(target.id) != runtime_return:
                        aliases[target.id] = runtime_return
                        changed = True

                func = function_defs.get(called)
                if not func:
                    continue
                params = [arg.arg for arg in func.args.args]
                bindings: Dict[str, ast.AST] = {}
                for param, arg_node in zip(params, value.args):
                    bindings[param] = arg_node
                for kw in value.keywords:
                    if kw.arg:
                        bindings[kw.arg] = kw.value
                for param, arg_node in bindings.items():
                    actual = node_value(arg_node)
                    if isinstance(actual, str):
                        runtime_actual = aliases.get(actual, actual if actual in aliases.values() else None)
                        if runtime_actual:
                            parameter_proposals.setdefault(param, set()).add(runtime_actual)
        if not changed:
            break

    # Only accept parameter aliases when all observed callsites agree. Conflicting
    # bindings remain unresolved rather than guessing.
    for param, candidates in parameter_proposals.items():
        if len(candidates) == 1:
            aliases[param] = next(iter(candidates))

    # Store aliases on the entity for downstream graph construction/debugging.
    by_runtime = {str(a.payload.get("agent_id")): a for a in agents}
    for alias, runtime in aliases.items():
        entity = by_runtime.get(runtime)
        if entity and alias != runtime:
            entity.payload.setdefault("aliases", [])
            if alias not in entity.payload["aliases"]:
                entity.payload["aliases"].append(alias)
    return aliases

def scan_tools(source_files: Iterable[Path], repo_root: Path, referenced_tools: Optional[set[str]] = None, collector: Optional[UnresolvedCollector] = None) -> List[DraftEntity]:
    collector = collector or UnresolvedCollector(repo_root)
    tools: List[DraftEntity] = []
    referenced = referenced_tools or set()
    for source in source_files:
        tree = parse_python_file(source, collector)
        if tree is None:
            continue
        scanner = ToolScanner(source, repo_root, collector, referenced)
        scanner.visit(tree)
        tools.extend(scanner.tools)
    return dedupe_entities(tools, "tool_id")


def scan_apis(source_files: Iterable[Path], repo_root: Path, collector: Optional[UnresolvedCollector] = None) -> List[DraftEntity]:
    collector = collector or UnresolvedCollector(repo_root)
    apis: List[DraftEntity] = []
    for source in source_files:
        tree = parse_python_file(source, collector)
        if tree is None:
            continue
        scanner = ApiScanner(source, repo_root, collector)
        scanner.visit(tree)
        apis.extend(scanner.apis)
    return dedupe_entities(apis, "api_id")


def scan_databases(source_files: Iterable[Path], repo_root: Path, collector: Optional[UnresolvedCollector] = None) -> List[DraftEntity]:
    collector = collector or UnresolvedCollector(repo_root)
    databases: List[DraftEntity] = []
    for source in source_files:
        tree = parse_python_file(source, collector)
        if tree is None:
            continue
        scanner = DatabaseScanner(source, repo_root)
        scanner.visit(tree)
        databases.extend(scanner.databases)
    return dedupe_entities(databases, "database_id")


def scan_events(source_files: Iterable[Path], repo_root: Path, agent_aliases: Dict[str, str], collector: Optional[UnresolvedCollector] = None) -> List[DraftEntity]:
    collector = collector or UnresolvedCollector(repo_root)
    events: List[DraftEntity] = []
    for source in source_files:
        tree = parse_python_file(source, collector)
        if tree is None:
            continue
        scanner = EventScanner(source, repo_root, agent_aliases)
        scanner.visit(tree)
        events.extend(scanner.events)
    return dedupe_entities(events, "event_id")


def write_manifest(path: Path, root_key: str, entities: List[DraftEntity]) -> None:
    manifest = {"zt_ir_version": "1.0", "manifest_type": f"{root_key}_draft", root_key: [entity.payload for entity in entities]}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True), encoding="utf-8")


def write_json_file(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False, ensure_ascii=False) + "\n", encoding="utf-8")


def write_inventory_and_graph_json(
    output_parent: Path,
    agents: List[DraftEntity],
    tools: List[DraftEntity],
    apis: List[DraftEntity],
    databases: List[DraftEntity],
    events: List[DraftEntity],
    edges: List[DraftEntity],
) -> None:
    """Write the JSON deliverables named in the original Task 2 work plan."""
    write_json_file(output_parent / "agent_inventory.json", {
        "zt_ir_version": "1.0",
        "agents": [x.payload for x in agents],
    })
    write_json_file(output_parent / "tool_inventory.json", {
        "zt_ir_version": "1.0",
        "tools": [x.payload for x in tools],
    })
    write_json_file(output_parent / "resource_inventory.json", {
        "zt_ir_version": "1.0",
        "apis": [x.payload for x in apis],
        "databases": [x.payload for x in databases],
        "events": [x.payload for x in events],
    })
    write_json_file(output_parent / "interaction_graph.json", {
        "zt_ir_version": "1.0",
        "nodes": {
            "agents": [x.payload for x in agents],
            "tools": [x.payload for x in tools],
            "apis": [x.payload for x in apis],
            "databases": [x.payload for x in databases],
            "events": [x.payload for x in events],
        },
        "interaction_edges": [x.payload for x in edges],
    })


def _graph_node_id(kind: str, runtime_id: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", f"{kind}_{runtime_id}")


def write_graph_visualizations(
    output_parent: Path,
    agents: List[DraftEntity],
    tools: List[DraftEntity],
    apis: List[DraftEntity],
    databases: List[DraftEntity],
    events: List[DraftEntity],
    edges: List[DraftEntity],
) -> None:
    """Write dependency-free Mermaid and Graphviz DOT interaction diagrams."""
    lookup: Dict[Tuple[str, str], str] = {}
    labels: Dict[str, str] = {}
    kinds: Dict[str, str] = {}

    for kind, items, key in (
        ("agent", agents, "agent_id"),
        ("tool", tools, "tool_id"),
        ("api", apis, "api_id"),
        ("database", databases, "database_id"),
        ("event", events, "event_id"),
    ):
        for item in items:
            runtime = str(item.payload.get(key) or "unknown")
            node_id = _graph_node_id(kind, runtime)
            lookup[(kind, runtime)] = node_id
            # Task 2 edges use subject for agents. Add that alias too.
            if kind == "agent":
                lookup[("subject", runtime)] = node_id
            labels[node_id] = runtime
            kinds[node_id] = kind

    # Mermaid
    mermaid = ["flowchart LR"]
    for node_id, label in labels.items():
        safe_label = label.replace('"', "'")
        mermaid.append(f'    {node_id}["{safe_label}\n({kinds[node_id]})"]')
    for edge in edges:
        p = edge.payload
        src = lookup.get((str(p.get("from_type")), str(p.get("from_id"))))
        dst = lookup.get((str(p.get("to_type")), str(p.get("to_id"))))
        if not src or not dst:
            continue
        edge_label = str(p.get("edge_type") or "interaction")
        mermaid.append(f"    {src} -->|{edge_label}| {dst}")
    (output_parent / "interaction_graph.mmd").write_text("\n".join(mermaid) + "\n", encoding="utf-8")

    # Graphviz DOT
    dot = ["digraph Task2InteractionGraph {", "  rankdir=LR;", "  node [shape=box];"]
    for node_id, label in labels.items():
        safe_label = label.replace('"', '\"')
        dot.append(f'  {node_id} [label="{safe_label}\n({kinds[node_id]})"];')
    for edge in edges:
        p = edge.payload
        src = lookup.get((str(p.get("from_type")), str(p.get("from_id"))))
        dst = lookup.get((str(p.get("to_type")), str(p.get("to_id"))))
        if not src or not dst:
            continue
        edge_label = str(p.get("edge_type") or "interaction").replace('"', '\"')
        dot.append(f'  {src} -> {dst} [label="{edge_label}"];')
    dot.append("}")
    (output_parent / "interaction_graph.dot").write_text("\n".join(dot) + "\n", encoding="utf-8")


def write_unresolved_report(path: Path, collector: UnresolvedCollector) -> None:
    findings = [x.as_dict() for x in collector.findings]
    report = {
        "zt_ir_version": "1.0",
        "manifest_type": "unresolved_interfaces",
        "summary": {
            "total": len(findings),
            "errors": sum(1 for x in findings if x["severity"] == "error"),
            "warnings": sum(1 for x in findings if x["severity"] == "warning"),
            "categories": sorted({x["category"] for x in findings}),
        },
        "unresolved_interfaces": findings,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(report, sort_keys=False, allow_unicode=True), encoding="utf-8")
    write_json_file(path.with_suffix(".json"), report)


def write_coverage_report(
    path: Path,
    agents: List[DraftEntity],
    tools: List[DraftEntity],
    apis: List[DraftEntity],
    databases: List[DraftEntity],
    events: List[DraftEntity],
    edges: List[DraftEntity],
    sources: RepositorySources,
    collector: UnresolvedCollector,
) -> None:
    resolved = len(agents) + len(tools) + len(apis) + len(databases) + len(events) + len(edges)
    unresolved = len(collector.findings)
    coverage = round(100.0 * resolved / (resolved + unresolved), 2) if resolved + unresolved else 100.0
    report = {
        "discovered_agents": len(agents),
        "discovered_tools": len(tools),
        "discovered_apis": len(apis),
        "discovered_databases": len(databases),
        "discovered_events": len(events),
        "discovered_edges": len(edges),
        "unresolved_interfaces": unresolved,
        "coverage_percent": coverage,
        "coverage_definition": "Resolved scanner entities/edges divided by resolved plus unresolved interface findings; this is scanner-resolution coverage, not security/PEP coverage.",
        "source_discovery": {
            "python_files": len(sources.python_files),
            "structured_files": len(sources.structured_files),
            "openapi_file_count": len(sources.openapi_files),
            "mcp_manifest_count": len(sources.mcp_manifest_files),
            "generic_config_count": len(sources.generic_config_files),
            "skipped_large_structured_files": sources.skipped_files,
        },
        "details": {
            "agents": [a.payload["agent_id"] for a in agents],
            "tools": [t.payload["tool_id"] for t in tools],
            "apis": [a.payload["api_id"] for a in apis],
            "databases": [d.payload["database_id"] for d in databases],
            "events": [e.payload["event_id"] for e in events],
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(report, sort_keys=False, allow_unicode=True), encoding="utf-8")
    write_json_file(path.with_suffix(".json"), report)


def find_source_files(repo_root: Path) -> Dict[str, List[Path]]:
    """Backward-compatible helper now backed by generic repository discovery.

    Existing callers still receive agent/tool/api/database lists. Each Python
    list intentionally contains the whole discovered Python source set because
    entity scanners themselves decide whether a file contains a relevant pattern.
    """
    collector = UnresolvedCollector(repo_root)
    sources = discover_repository(repo_root, collector)
    return {
        "agents": list(sources.python_files),
        "tools": list(sources.python_files),
        "apis": list(sources.python_files),
        "databases": list(sources.python_files),
        "events": list(sources.python_files),
        "openapi": list(sources.openapi_files),
        "mcp_manifests": list(sources.mcp_manifest_files),
    }


def run_scan(repo_root: Path, output_dir: Path, *, excluded_dirs: Optional[set[str]] = None) -> Dict[str, Any]:
    repo_root = repo_root.resolve()
    output_dir = output_dir.resolve()
    collector = UnresolvedCollector(repo_root)
    sources = discover_repository(repo_root, collector, excluded_dirs=excluded_dirs)

    agents = scan_agents(sources.python_files, repo_root, collector)
    agent_aliases = discover_agent_aliases(sources.python_files, repo_root, agents, collector)
    referenced_tools = {tool for agent in agents for tool in agent.payload.get("authorized_tools", [])}
    python_tools = scan_tools(sources.python_files, repo_root, referenced_tools, collector)
    manifest_tools = scan_mcp_manifest_files(sources.mcp_manifest_files, repo_root, collector)
    tools = dedupe_entities([*python_tools, *manifest_tools], "tool_id")

    python_apis = scan_apis(sources.python_files, repo_root, collector)
    openapi_apis = scan_openapi_files(sources.openapi_files, repo_root, collector)
    apis = dedupe_entities([*python_apis, *openapi_apis], "api_id")

    databases = scan_databases(sources.python_files, repo_root, collector)
    events = scan_events(sources.python_files, repo_root, agent_aliases, collector)
    scan_suspicious_generic_configs(sources.generic_config_files, repo_root, collector)

    builder = InteractionEdgeBuilder(agents, tools, apis, databases, events, collector)
    builder.build_edges()
    edges = builder.edges

    output_dir.mkdir(parents=True, exist_ok=True)
    write_manifest(output_dir / "agents_draft.yaml", "agents", agents)
    write_manifest(output_dir / "tools_draft.yaml", "tools", tools)
    write_manifest(output_dir / "apis_draft.yaml", "apis", apis)
    write_manifest(output_dir / "databases_draft.yaml", "databases", databases)
    write_manifest(output_dir / "events_draft.yaml", "events", events)
    write_manifest(output_dir / "interaction_edges_draft.yaml", "interaction_edges", edges)

    output_parent = output_dir.parent
    write_inventory_and_graph_json(output_parent, agents, tools, apis, databases, events, edges)
    write_graph_visualizations(output_parent, agents, tools, apis, databases, events, edges)

    unresolved_path = output_parent / "unresolved_interfaces.yaml"
    write_unresolved_report(unresolved_path, collector)
    coverage_path = output_dir.parent / "coverage_report.yaml"
    write_coverage_report(coverage_path, agents, tools, apis, databases, events, edges, sources, collector)

    return {
        "agents": agents,
        "tools": tools,
        "apis": apis,
        "databases": databases,
        "events": events,
        "edges": edges,
        "sources": sources,
        "unresolved": collector.findings,
        "coverage_path": coverage_path,
        "unresolved_path": unresolved_path,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generic Task 2 Zero Trust scanner for multi-agent systems.")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent, help="Path to the multi-agent system repository root.")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent / "output" / "draft_manifests", help="Directory where draft manifests are written.")
    parser.add_argument("--exclude-dir", action="append", default=[], help="Additional directory name to exclude from repository discovery. May be repeated.")
    parser.add_argument("--strict-unresolved", action="store_true", help="Exit with status 2 after writing reports when unresolved interfaces remain.")
    parser.add_argument("--print-unresolved", action="store_true", help="Print unresolved interface findings to stdout.")
    args = parser.parse_args()

    result = run_scan(args.repo_root, args.output_dir, excluded_dirs=set(args.exclude_dir))
    print(f"Scanner complete. Draft manifests written to: {args.output_dir.resolve()}")
    print(f"Coverage report written to: {result['coverage_path']}")
    print(f"Unresolved-interface report written to: {result['unresolved_path']}")
    print(
        "Discovery summary: "
        f"agents={len(result['agents'])}, tools={len(result['tools'])}, apis={len(result['apis'])}, "
        f"databases={len(result['databases'])}, events={len(result['events'])}, "
        f"edges={len(result['edges'])}, unresolved={len(result['unresolved'])}"
    )
    if args.print_unresolved:
        for item in result["unresolved"]:
            print(f"UNRESOLVED [{item.category}] {item.file}:{item.line} {item.symbol or ''} - {item.reason}")
    if args.strict_unresolved and result["unresolved"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
