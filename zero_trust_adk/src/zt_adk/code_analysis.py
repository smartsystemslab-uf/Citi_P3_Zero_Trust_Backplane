"""Side-effect analysis of tool implementations (AST of the live function objects).

The analysis starts at the tool's function and follows calls into the application's own
code (functions, methods of the application's classes, module functions reached through
the function's globals), up to ``MAX_DEPTH`` levels. Library and standard-library code is
not entered; calls into it are classified by what they are (HTTP client, database driver,
file system, subprocess, mail, ...). The result is evidence, not a verdict:
``classify.classify_tool`` combines it with the tool's name, the system owner's
declarations (``zt_adk.yaml``) and conservative defaults.
"""
from __future__ import annotations

import ast
import inspect
import re
import sys
import sysconfig
import textwrap
import types
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

MAX_DEPTH = 4
HTTP_WRITE = {"post", "put", "patch", "delete"}
HTTP_READ = {"get", "head", "options"}
HTTP_RECEIVER_HINTS = ("requests", "httpx", "client", "http", "session", "aiohttp", "api", "urllib3")
SQL_RE = re.compile(r"^\s*(SELECT|INSERT|UPDATE|DELETE|REPLACE|MERGE|UPSERT|CREATE|DROP|ALTER|TRUNCATE|WITH)\b",
                    re.IGNORECASE)
SQL_WRITE = {"INSERT", "UPDATE", "REPLACE", "MERGE", "UPSERT", "CREATE", "ALTER"}
SQL_DELETE = {"DELETE", "DROP", "TRUNCATE"}
ORM_WRITE = {"add", "add_all", "merge", "bulk_save_objects", "bulk_insert_mappings", "bulk_update_mappings",
             "insert_one", "insert_many", "update_one", "update_many", "replace_one", "save", "put_item",
             "update_item", "set", "hset", "lpush", "rpush", "sadd", "zadd", "incr", "expire"}
ORM_DELETE = {"delete_one", "delete_many", "delete_item", "drop", "hdel", "srem", "zrem", "flushdb"}
ORM_RECEIVER_HINTS = ("session", "db", "conn", "cursor", "collection", "table", "repo", "store", "redis",
                      "client", "engine", "bucket", "blob")
FILE_WRITE_METHODS = {"write_text", "write_bytes", "touch", "mkdir", "makedirs", "rename", "replace", "symlink_to",
                      "copy", "copy2", "copyfile", "copytree", "move", "dump"}
FILE_DELETE_METHODS = {"unlink", "rmdir", "remove", "rmtree", "removedirs"}
FILE_READ_METHODS = {"read_text", "read_bytes", "iterdir", "glob", "rglob", "listdir", "scandir", "walk", "load"}
EXEC_CALLS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output",
              "subprocess.check_call", "os.system", "os.popen", "os.execv", "os.execve", "os.execvp",
              "os.spawnv", "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell"}
EXEC_BUILTINS = {"eval", "exec", "compile", "__import__"}
MAIL_TOKENS = {"smtplib", "sendmail", "sendgrid", "twilio", "slack", "webhook", "sns", "sqs", "pubsub", "kafka"}
MESSAGE_CALLS = {"send_message", "send_email", "send_mail", "sendmail", "publish", "produce", "send_sms", "notify",
                 "post_message", "chat_postmessage"}
SEND_RECEIVER_TOKENS = {"producer", "queue", "topic", "channel", "socket", "sns", "sqs", "pubsub", "kafka", "smtp",
                        "server", "mailer", "client", "bot"}


@dataclass
class CodeEvidence:
    analyzed: bool = False                      # source of the entry function was available
    functions: list[str] = field(default_factory=list)
    http_methods: set[str] = field(default_factory=set)
    sql: set[str] = field(default_factory=set)
    db_write: bool = False
    db_delete: bool = False
    db_read: bool = False
    file_write: bool = False
    file_delete: bool = False
    file_read: bool = False
    process_exec: bool = False
    messaging: bool = False
    state_write: bool = False                   # tool_context.state / callback state
    control_flow: set[str] = field(default_factory=set)   # transfer_to_agent / escalate set by the tool
    unresolved_calls: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)
    depth: int = 0                              # call depth the operation evidence comes from
    indirect: dict[str, Any] = field(default_factory=dict)   # deeper evidence (e.g. lazy initialisation)

    def has_operation(self) -> bool:
        return bool(self.http_methods or self.sql or self.db_write or self.db_delete or self.db_read
                    or self.file_write or self.file_delete or self.file_read or self.process_exec
                    or self.messaging or self.state_write or self.control_flow)

    @property
    def side_effect(self) -> bool:
        return bool(self.http_methods & HTTP_WRITE or self.db_write or self.db_delete or self.file_write
                    or self.file_delete or self.process_exec or self.messaging or self.state_write
                    or self.sql & (SQL_WRITE | SQL_DELETE))

    @property
    def destructive(self) -> bool:
        return bool("delete" in self.http_methods or self.db_delete or self.file_delete
                    or self.sql & SQL_DELETE)

    @property
    def external_write(self) -> bool:
        """A side effect outside the ADK session (state writes alone are session-local)."""
        return self.side_effect and not (self.state_write and not (
            self.http_methods & HTTP_WRITE or self.db_write or self.db_delete or self.file_write
            or self.file_delete or self.process_exec or self.messaging or self.sql & (SQL_WRITE | SQL_DELETE)))

    @property
    def reads(self) -> bool:
        return bool(self.http_methods & HTTP_READ or self.db_read or self.file_read or "SELECT" in self.sql)

    def as_dict(self) -> dict[str, Any]:
        return {
            "analyzed": self.analyzed, "functions": self.functions[:50],
            "http_methods": sorted(self.http_methods), "sql": sorted(self.sql),
            "db_write": self.db_write, "db_delete": self.db_delete, "db_read": self.db_read,
            "file_write": self.file_write, "file_delete": self.file_delete, "file_read": self.file_read,
            "process_exec": self.process_exec, "messaging": self.messaging, "state_write": self.state_write,
            "control_flow": sorted(self.control_flow), "unresolved_calls": sorted(self.unresolved_calls)[:50],
            "side_effect": self.side_effect, "destructive": self.destructive, "reads": self.reads,
            "evidence_depth": self.depth, "indirect": self.indirect, "notes": self.notes,
        }


def _library_roots() -> tuple[str, ...]:
    roots = set()
    for key in ("stdlib", "platstdlib", "purelib", "platlib"):
        try:
            roots.add(str(Path(sysconfig.get_paths()[key]).resolve()).lower())
        except (KeyError, OSError):
            pass
    roots.add(str(Path(sys.base_prefix).resolve()).lower())
    for p in sys.path:
        if "site-packages" in p or "dist-packages" in p:
            roots.add(str(Path(p).resolve()).lower())
    return tuple(sorted(roots))


_LIB_ROOTS = _library_roots()


def is_application_code(obj: Any) -> bool:
    """True for functions / classes defined in the application (not stdlib, not installed libraries)."""
    try:
        path = inspect.getsourcefile(obj) or inspect.getfile(obj)
    except (TypeError, OSError):
        return False
    if not path:
        return False
    resolved = str(Path(path).resolve()).lower()
    return not any(resolved.startswith(root) for root in _LIB_ROOTS)


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func) + "()"
    if isinstance(node, ast.Subscript):
        return _dotted(node.value) + "[]"
    return ""


def _strings(node: ast.AST) -> list[str]:
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            out.append(n.value)
        elif isinstance(n, ast.JoinedStr):
            out.append("".join(v.value for v in n.values if isinstance(v, ast.Constant) and isinstance(v.value, str)))
    return out


def _unwrap(fn: Any) -> Any:
    seen = 0
    while hasattr(fn, "__wrapped__") and seen < 10:
        fn = fn.__wrapped__
        seen += 1
    if isinstance(fn, (staticmethod, classmethod)):
        fn = fn.__func__
    if isinstance(fn, types.MethodType):
        fn = fn.__func__
    return fn


class _Analyzer:
    """Collects evidence per call depth. The operation of a tool is what its shallowest
    level that touches anything does (a tool that runs its own SQL is classified by that
    SQL, not by the schema setup or seeding of the connection helper it calls); deeper
    evidence is kept as ``indirect``. A tool that only delegates (no operation of its own)
    is classified by the first level of its callees that has one."""

    def __init__(self) -> None:
        self.levels: dict[int, CodeEvidence] = {}
        self.meta = CodeEvidence()
        self._seen: set[Any] = set()

    @property
    def ev(self) -> CodeEvidence:                 # evidence object of the level being scanned
        return self.levels.setdefault(self._depth, CodeEvidence())

    _depth = 0

    def result(self) -> CodeEvidence:
        out = CodeEvidence(analyzed=self.meta.analyzed, functions=self.meta.functions, notes=self.meta.notes)
        unresolved: set[str] = set()
        for lvl in self.levels.values():
            unresolved |= lvl.unresolved_calls
        primary_depth = next((d for d in sorted(self.levels) if self.levels[d].has_operation()), None)
        if primary_depth is not None:
            p = self.levels[primary_depth]
            for name in ("http_methods", "sql", "db_write", "db_delete", "db_read", "file_write", "file_delete",
                         "file_read", "process_exec", "messaging", "state_write", "control_flow"):
                setattr(out, name, getattr(p, name))
            out.depth = primary_depth
            deeper = CodeEvidence()
            for d, lvl in self.levels.items():
                if d > primary_depth:
                    deeper.http_methods |= lvl.http_methods
                    deeper.sql |= lvl.sql
                    for name in ("db_write", "db_delete", "db_read", "file_write", "file_delete", "file_read",
                                 "process_exec", "messaging", "state_write"):
                        setattr(deeper, name, getattr(deeper, name) or getattr(lvl, name))
            if deeper.has_operation():
                out.indirect = {"http_methods": sorted(deeper.http_methods), "sql": sorted(deeper.sql),
                                "side_effect": deeper.side_effect, "destructive": deeper.destructive}
        out.unresolved_calls = unresolved
        return out

    def analyze(self, fn: Callable[..., Any], depth: int = 0) -> None:
        fn = _unwrap(fn)
        code = getattr(fn, "__code__", None)
        key = code or id(fn)
        if key in self._seen or depth > MAX_DEPTH:
            return
        self._seen.add(key)
        try:
            source = textwrap.dedent(inspect.getsource(fn))
            tree = ast.parse(source)
        except (OSError, TypeError, SyntaxError, IndentationError):
            if depth == 0:
                self.meta.notes.append("source not available")
            return
        if depth == 0:
            self.meta.analyzed = True
        self.meta.functions.append(f"{getattr(fn, '__module__', '?')}:{getattr(fn, '__qualname__', '?')}")
        glb = getattr(fn, "__globals__", {}) or {}
        saved = self._depth
        self._depth = depth
        try:
            self._scan(tree, glb, depth)
        finally:
            self._depth = saved

    # -- visiting ----------------------------------------------------------------------
    def _scan(self, tree: ast.AST, glb: dict[str, Any], depth: int) -> None:
        for text in _strings(tree):
            m = SQL_RE.match(text)
            if m and len(text) > 8:
                verb = m.group(1).upper()
                if verb == "WITH":
                    up = text.upper()
                    verb = next((v for v in ("INSERT", "UPDATE", "DELETE", "SELECT") if v in up), "SELECT")
                self.ev.sql.add(verb)
                if verb in SQL_WRITE:
                    self.ev.db_write = True
                elif verb in SQL_DELETE:
                    self.ev.db_delete = True
                else:
                    self.ev.db_read = True
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    self._assignment_target(t)
            elif isinstance(node, ast.Delete):
                for t in node.targets:
                    self._assignment_target(t)
            elif isinstance(node, ast.Call):
                self._call(node, glb, depth)

    def _assignment_target(self, t: ast.AST) -> None:
        name = _dotted(t)
        if isinstance(t, ast.Subscript) and name.endswith(".state[]"):
            self.ev.state_write = True
        elif name.endswith("actions.transfer_to_agent"):
            self.ev.control_flow.add("transfer_to_agent")
        elif name.endswith("actions.escalate"):
            self.ev.control_flow.add("escalate")
        elif name.endswith("actions.state_delta[]") or name.endswith("actions.state_delta"):
            self.ev.state_write = True

    def _call(self, node: ast.Call, glb: dict[str, Any], depth: int) -> None:
        func = node.func
        dotted = _dotted(func)
        last = dotted.rsplit(".", 1)[-1]
        receiver = dotted.rsplit(".", 1)[0].lower() if "." in dotted else ""
        low = dotted.lower()
        # process execution
        if dotted in EXEC_CALLS or (dotted in EXEC_BUILTINS and isinstance(func, ast.Name)):
            self.ev.process_exec = True
        # HTTP clients
        if isinstance(func, ast.Attribute) and last in HTTP_WRITE | HTTP_READ | {"request", "urlopen", "fetch"}:
            if last in HTTP_WRITE and not any(h in receiver for h in ("state", "dict", "list", "set")):
                if last == "delete" and any(h in receiver for h in ORM_RECEIVER_HINTS) \
                        and not any(h in receiver for h in ("requests", "httpx", "http")):
                    self.ev.db_delete = True
                else:
                    self.ev.http_methods.add(last)
            elif last in HTTP_READ and any(h in receiver for h in HTTP_RECEIVER_HINTS) \
                    and "state" not in receiver:
                self.ev.http_methods.add(last)
            elif last == "request" and node.args and isinstance(node.args[0], ast.Constant) \
                    and isinstance(node.args[0].value, str):
                self.ev.http_methods.add(node.args[0].value.lower())
            elif last == "urlopen":
                self.ev.http_methods.add(self._urlopen_method(node))
        # databases / key-value stores
        if isinstance(func, ast.Attribute):
            if last in {"execute", "executemany", "executescript"}:
                self.ev.db_read = self.ev.db_read or not (self.ev.db_write or self.ev.db_delete)
            if last in ORM_WRITE and any(h in receiver for h in ORM_RECEIVER_HINTS) and "state" not in receiver:
                self.ev.db_write = True
            if last in ORM_DELETE and any(h in receiver for h in ORM_RECEIVER_HINTS):
                self.ev.db_delete = True
            if last == "commit" and any(h in receiver for h in ORM_RECEIVER_HINTS):
                self.ev.db_write = True
            if last in {"query", "scalars", "scalar", "fetchone", "fetchall", "find", "find_one", "get_item", "hget"} \
                    and any(h in receiver for h in ORM_RECEIVER_HINTS):
                self.ev.db_read = True
        # session state
        if dotted.endswith(".state.update") or dotted.endswith(".state.setdefault") \
                or dotted.endswith(".state.pop") or dotted.endswith(".state.clear"):
            self.ev.state_write = True
        # files
        if isinstance(func, ast.Name) and func.id == "open":
            mode = ""
            if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                mode = str(node.args[1].value)
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = str(kw.value.value)
            if any(c in mode for c in "wax+"):
                self.ev.file_write = True
            else:
                self.ev.file_read = True
        elif isinstance(func, ast.Attribute):
            if last in FILE_DELETE_METHODS and (receiver.startswith(("os", "shutil")) or "path" in receiver
                                                or receiver.endswith(")") or receiver in {"p", "f", "file"}):
                self.ev.file_delete = True
            elif last in FILE_WRITE_METHODS and (receiver.startswith(("os", "shutil", "json", "yaml", "pickle"))
                                                 or "path" in receiver or receiver.endswith("()")):
                if last == "dump" and not receiver.startswith(("json", "yaml", "pickle")):
                    pass
                else:
                    self.ev.file_write = True
            elif last in FILE_READ_METHODS:
                self.ev.file_read = True
        # mail / messaging
        tokens = set(re.split(r"[._()\[\]]+", low)) - {""}
        if not low.startswith(("logging", "logger", "log.", "print")):
            if tokens & MAIL_TOKENS or last.lower() in MESSAGE_CALLS or (
                    last == "send" and set(re.split(r"[._()\[\]]+", receiver)) & SEND_RECEIVER_TOKENS):
                self.ev.messaging = True
        # follow application code
        target = self._resolve(func, glb)
        if target is not None:
            if is_application_code(target):
                if inspect.isclass(target):
                    init = getattr(target, "__init__", None)
                    if init is not None and is_application_code(init):
                        self.analyze(init, depth + 1)
                elif callable(target):
                    self.analyze(target, depth + 1)
                self._depth = depth
        elif isinstance(func, (ast.Name, ast.Attribute)) and dotted and dotted.split(".")[0] in glb:
            base = glb.get(dotted.split(".")[0])
            if not isinstance(base, types.ModuleType) or is_application_code(base):
                self.ev.unresolved_calls.add(dotted)

    @staticmethod
    def _urlopen_method(node: ast.Call) -> str:
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            if isinstance(arg, ast.Call) and _dotted(arg.func).endswith("Request"):
                for kw in arg.keywords:
                    if kw.arg == "method" and isinstance(kw.value, ast.Constant):
                        return str(kw.value.value).lower()
                if len(arg.args) > 1 or any(kw.arg == "data" for kw in arg.keywords):
                    return "post"
        return "get"

    @staticmethod
    def _resolve(func: ast.AST, glb: dict[str, Any]) -> Any:
        """Resolve a call target through the function's globals (live objects)."""
        parts = _dotted(func).split(".")
        if not parts or not parts[0] or "()" in parts[0] or "[]" in parts[0]:
            return None
        obj = glb.get(parts[0])
        if obj is None:
            return None
        for attr in parts[1:]:
            if "()" in attr or "[]" in attr:
                return None
            nxt = getattr(obj, attr, None)
            if nxt is None:
                # method of an application object: look it up on its class
                nxt = getattr(type(obj), attr, None)
                if nxt is None:
                    return None
            obj = nxt
        return _unwrap(obj)


def analyze_callable(fn: Callable[..., Any]) -> CodeEvidence:
    a = _Analyzer()
    try:
        a.analyze(fn)
    except RecursionError:
        a.meta.notes.append("analysis depth exceeded")
    return a.result()


def analyze_tool_object(tool: Any) -> CodeEvidence:
    """Custom BaseTool subclasses: analyse their run_async implementation."""
    run = getattr(type(tool), "run_async", None)
    if run is None:
        return CodeEvidence(notes=["no run_async"])
    return analyze_callable(run)
