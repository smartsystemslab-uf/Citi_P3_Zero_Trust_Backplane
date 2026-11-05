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
# Library code the analysis does not enter but knows to be free of external effects. A call into
# any other library (an SDK client, a driver the patterns above do not recognise, ...) is opaque:
# the analysis cannot show that it has no side effect, so the tool is never called "pure".
PURE_MODULES = {"builtins", "math", "cmath", "decimal", "fractions", "statistics", "random", "re", "string",
                "textwrap", "json", "datetime", "time", "calendar", "zoneinfo", "uuid", "hashlib", "hmac", "base64",
                "binascii", "itertools", "functools", "operator", "collections", "typing", "typing_extensions",
                "dataclasses", "enum", "copy", "pprint", "difflib", "unicodedata", "html", "ipaddress", "numbers",
                "logging", "warnings", "inspect", "abc", "contextlib", "bisect", "heapq", "array", "struct", "locale",
                "pydantic", "pydantic_core", "dateutil"}
PURE_SUBMODULES = {"urllib.parse", "os.path", "posixpath", "ntpath", "email.utils", "xml.sax.saxutils"}
# Methods of values (str, numbers, containers, dates, pydantic models, ...) without external effects.
PURE_METHODS = {"get", "items", "keys", "values", "copy", "lower", "upper", "title", "capitalize", "casefold",
                "strip", "lstrip", "rstrip", "split", "rsplit", "splitlines", "join", "format", "format_map",
                "replace", "startswith", "endswith", "find", "rfind", "index", "rindex", "count", "encode", "decode",
                "isdigit", "isalpha", "isalnum", "isspace", "isnumeric", "isdecimal", "zfill", "ljust", "rjust",
                "center", "partition", "rpartition", "translate", "removeprefix", "removesuffix", "expandtabs",
                "isoformat", "strftime", "timestamp", "date", "time", "weekday", "isoweekday", "astimezone",
                "total_seconds", "quantize", "to_integral_value", "is_integer", "conjugate", "hex", "bit_length",
                "model_dump", "model_dump_json", "model_copy", "model_validate", "model_validate_json", "dict", "json",
                "to_dict", "as_dict", "group", "groups", "groupdict", "match", "search",
                "fullmatch", "findall", "finditer", "hexdigest", "digest", "most_common", "elements",
                "intersection", "union", "difference", "symmetric_difference", "issubset", "issuperset",
                "isdisjoint", "fromkeys", "debug", "info", "warning", "exception"}
# Names bound to values the function builds itself: every method of these is in-memory.
CONTAINER_BUILDERS = {"dict", "list", "set", "frozenset", "tuple", "str", "int", "float", "bool", "bytes",
                      "bytearray", "sorted", "reversed", "defaultdict", "OrderedDict", "Counter", "deque",
                      "namedtuple"}
# Methods that change the object they are called on: a side effect when that object outlives the
# call (a module-level object, or an attribute of the instance the tool is a method of).
MUTATING_METHODS = {"append", "extend", "insert", "pop", "remove", "clear", "update", "setdefault", "popitem",
                    "add", "discard", "sort", "reverse", "appendleft", "extendleft", "popleft", "rotate",
                    "__setitem__", "__delitem__"}
# Of these, the ones only Python sequences / mappings have: on any local value they stay in memory.
# The others (update, add, insert, pop, remove, clear, ...) are also the write methods of SDK and
# ORM objects (a Firestore document's update, a session's add), so on an object the function did
# not build itself they are opaque.
CONTAINER_ONLY_MUTATIONS = {"append", "extend", "sort", "reverse", "appendleft", "extendleft", "popleft", "rotate",
                            "setdefault", "popitem", "discard"}
PURE_METHODS |= {"exists", "is_file", "is_dir", "resolve", "absolute", "with_suffix", "with_name", "with_stem",
                 "relative_to", "joinpath", "as_posix", "as_uri", "is_absolute", "stat", "expanduser"}
# query building / result reading on database objects (SQLAlchemy, DB-API cursors, ...)
PURE_METHODS |= {"filter", "filter_by", "where", "order_by", "group_by", "having", "limit", "offset", "distinct",
                 "join", "outerjoin", "select_from", "options", "first", "one", "one_or_none", "all", "scalar_one",
                 "scalar_one_or_none", "fetchmany", "mappings", "unique", "keys", "columns", "label", "desc", "asc",
                 "in_", "like", "ilike", "is_", "isnot", "between", "count"}
# Individual library calls known to be free of external effects (their module is not).
PURE_CALLS = {"os.getenv", "os.environ.get", "os.getcwd", "os.cpu_count", "os.getpid", "os.fspath", "sys.getsizeof",
              "asyncio.sleep", "asyncio.gather", "asyncio.wait", "asyncio.wait_for", "asyncio.shield",
              "asyncio.timeout", "asyncio.get_running_loop", "asyncio.get_event_loop", "asyncio.current_task"}
ARTIFACT_WRITE = {"save_artifact"}
ARTIFACT_READ = {"load_artifact", "list_artifacts", "search_memory"}


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
    state_write: bool = False                   # tool_context.state / callback state / artifacts
    memory_write: bool = False                  # module-level or instance objects changed (outlive the call)
    control_flow: set[str] = field(default_factory=set)   # transfer_to_agent / escalate set by the tool
    unresolved_calls: set[str] = field(default_factory=set)
    opaque_calls: set[str] = field(default_factory=set)   # library / object calls the analysis cannot see into
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
            "memory_write": self.memory_write,
            "control_flow": sorted(self.control_flow), "unresolved_calls": sorted(self.unresolved_calls)[:50],
            "opaque_calls": sorted(self.opaque_calls)[:50],
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


def _local_imports(tree: ast.AST) -> dict[str, tuple[str, str | None, int]]:
    """Imports inside the analysed function: bound name -> (module, attribute, relative level)."""
    out: dict[str, tuple[str, str | None, int]] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for al in n.names:
                if al.asname:
                    out[al.asname] = (al.name, None, 0)
                else:
                    top = al.name.split(".")[0]
                    out[top] = (top, None, 0)
        elif isinstance(n, ast.ImportFrom):
            for al in n.names:
                if al.name != "*":
                    out[al.asname or al.name] = (n.module or "", al.name, n.level or 0)
    return out


def _resolve_import(module: str, attr: str | None, level: int, package: str | None) -> Any:
    """The object a function-local import binds. The module is imported as the tool itself
    would import it, so the result does not depend on what happened to be imported before
    (the analysis runs at build time and again when the protected application starts)."""
    import importlib
    import importlib.util

    try:
        name = importlib.util.resolve_name("." * level + module, package) if level else module
        mod = importlib.import_module(name)
    except Exception:                                   # unresolvable: the name stays opaque
        return None
    if attr is None:
        return mod
    obj = getattr(mod, attr, None)
    if obj is None:
        try:
            obj = importlib.import_module(f"{name}.{attr}")
        except Exception:
            return None
    return obj


def _local_names(tree: ast.AST) -> tuple[frozenset[str], str | None]:
    """Names local to the analysed function (parameters and names it binds, minus those it
    declares ``global`` / ``nonlocal``), and the name of its instance parameter (``self``/``cls``)."""
    fn = next((n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))), None)
    names: set[str] = set()
    declared_outer: set[str] = set()
    self_name: str | None = None
    if fn is not None:
        a = fn.args
        params = [*a.posonlyargs, *a.args, *a.kwonlyargs] + [x for x in (a.vararg, a.kwarg) if x is not None]
        names.update(p.arg for p in params)
        positional = [*a.posonlyargs, *a.args]
        if positional and positional[0].arg in ("self", "cls"):
            self_name = positional[0].arg
    for n in ast.walk(tree):
        if isinstance(n, (ast.Global, ast.Nonlocal)):
            declared_outer.update(n.names)
        elif isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            names.add(n.id)
        elif isinstance(n, ast.arg):
            names.add(n.arg)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n is not fn:
            names.add(n.name)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            names.add(n.name)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            names.update((al.asname or al.name).split(".")[0] for al in n.names)
    return frozenset(names - declared_outer), self_name


def _builds_value(node: ast.AST | None) -> bool:
    """A value the function builds itself (a literal, a comprehension, a builtin container)."""
    if isinstance(node, (ast.Dict, ast.List, ast.Set, ast.Tuple, ast.ListComp, ast.DictComp, ast.SetComp,
                         ast.GeneratorExp, ast.Constant, ast.JoinedStr)):
        return True
    if isinstance(node, ast.Call):
        name = node.func.id if isinstance(node.func, ast.Name) else (
            node.func.attr if isinstance(node.func, ast.Attribute) else "")
        return name in CONTAINER_BUILDERS
    if isinstance(node, ast.BinOp):
        return _builds_value(node.left) and _builds_value(node.right)
    return False


def _local_containers(tree: ast.AST, locals_: frozenset[str]) -> frozenset[str]:
    """Local names every assignment of which binds a value the function builds itself."""
    built: dict[str, bool] = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.Assign, ast.AnnAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            for t in targets:
                if isinstance(t, ast.Name) and t.id in locals_:
                    built[t.id] = built.get(t.id, True) and _builds_value(n.value)
        elif isinstance(n, (ast.For, ast.AsyncFor, ast.With, ast.AsyncWith, ast.NamedExpr)):
            for t in ast.walk(n.target if isinstance(n, (ast.For, ast.AsyncFor, ast.NamedExpr))
                              else ast.Tuple(elts=[i.optional_vars for i in n.items if i.optional_vars], ctx=ast.Load())):
                if isinstance(t, ast.Name):
                    built[t.id] = False
    return frozenset(k for k, v in built.items() if v)


def _root_name(node: ast.AST) -> str:
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else ""


def _module_is_pure(module: str) -> bool:
    if not module:
        return False
    if module in PURE_SUBMODULES or any(module.startswith(p + ".") for p in PURE_SUBMODULES):
        return True
    return module.split(".")[0] in PURE_MODULES


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
            out.opaque_calls |= lvl.opaque_calls          # any level: the tool may do what is not seen
            out.memory_write = out.memory_write or lvl.memory_write
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
        if key in self._seen:
            return
        label = f"{getattr(fn, '__module__', '?')}:{getattr(fn, '__qualname__', '?')}"
        if depth > MAX_DEPTH:
            self.ev.opaque_calls.add(f"{label} (beyond analysis depth {MAX_DEPTH})")
            return
        self._seen.add(key)
        try:
            source = textwrap.dedent(inspect.getsource(fn))
            tree = ast.parse(source)
        except (OSError, TypeError, SyntaxError, IndentationError):
            if depth == 0:
                self.meta.notes.append("source not available")
            else:
                self.ev.opaque_calls.add(f"{label} (source not available)")
            return
        if depth == 0:
            self.meta.analyzed = True
        self.meta.functions.append(f"{getattr(fn, '__module__', '?')}:{getattr(fn, '__qualname__', '?')}")
        glb = dict(getattr(fn, "__globals__", {}) or {})
        closure = getattr(fn, "__closure__", None) or ()
        for var, cell in zip(getattr(code, "co_freevars", ()) if code else (), closure):
            try:
                glb[var] = cell.cell_contents          # closure variables resolve like globals
            except ValueError:
                pass
        saved, saved_scope = self._depth, (self._locals, self._self, self._containers)
        self._depth = depth
        self._locals, self._self = _local_names(tree)
        self._containers = _local_containers(tree, self._locals)
        package = getattr(sys.modules.get(getattr(fn, "__module__", "") or ""), "__package__", None)
        for alias, (module, attr, level) in _local_imports(tree).items():
            obj = _resolve_import(module, attr, level, package)
            if obj is not None:                    # resolved like a module-level import
                glb[alias] = obj
                self._locals = self._locals - {alias}
        try:
            self._scan(tree, glb, depth)
        finally:
            self._depth = saved
            self._locals, self._self, self._containers = saved_scope

    _locals: frozenset[str] = frozenset()
    _self: str | None = None
    _containers: frozenset[str] = frozenset()

    def _root_kind(self, root: str, glb: dict[str, Any]) -> str:
        """'self' (the instance of the method), 'container' (a local value the function built
        itself), 'local' (any other local: a parameter, a call result), 'global' (module-level or
        closure object)."""
        if root and root == self._self:
            return "self"
        if root in self._containers:
            return "container"
        if root in self._locals:
            return "local"
        if root in glb:
            return "global"
        return "local" if root else "unknown"

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
                    for leaf in (t.elts if isinstance(t, (ast.Tuple, ast.List)) else [t]):
                        self._assignment_target(leaf, glb)
            elif isinstance(node, ast.Delete):
                for t in node.targets:
                    self._assignment_target(t, glb)
            elif isinstance(node, ast.Call):
                self._call(node, glb, depth)

    def _assignment_target(self, t: ast.AST, glb: dict[str, Any] | None = None) -> None:
        name = _dotted(t)
        if isinstance(t, ast.Subscript) and name.endswith(".state[]"):
            self.ev.state_write = True
        elif name.endswith("actions.transfer_to_agent"):
            self.ev.control_flow.add("transfer_to_agent")
        elif name.endswith("actions.escalate"):
            self.ev.control_flow.add("escalate")
        elif name.endswith("actions.state_delta[]") or name.endswith("actions.state_delta"):
            self.ev.state_write = True
        elif isinstance(t, (ast.Attribute, ast.Subscript)):
            # obj.attr = ... / obj[key] = ...: a side effect if obj outlives the call
            if self._root_kind(_root_name(t), glb or {}) in ("self", "global"):
                self.ev.memory_write = True
        elif isinstance(t, ast.Name) and t.id not in self._locals and glb is not None and t.id in glb:
            self.ev.memory_write = True             # rebinding a name declared global / nonlocal

    def _signature(self) -> tuple[Any, ...]:
        e = self.ev
        return (len(e.http_methods), len(e.sql), e.db_write, e.db_delete, e.db_read, e.file_write, e.file_delete,
                e.file_read, e.process_exec, e.messaging, e.state_write, len(e.control_flow))

    def _call(self, node: ast.Call, glb: dict[str, Any], depth: int) -> None:
        before = self._signature()
        func = node.func
        dotted = _dotted(func)
        last = dotted.rsplit(".", 1)[-1]
        receiver = dotted.rsplit(".", 1)[0].lower() if "." in dotted else ""
        low = dotted.lower()
        self._patterns(node, func, dotted, last, receiver, low)
        recognised = self._signature() != before
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
                return
        elif isinstance(func, (ast.Name, ast.Attribute)) and dotted and dotted.split(".")[0] in glb:
            base = glb.get(dotted.split(".")[0])
            if not isinstance(base, types.ModuleType) or is_application_code(base):
                self.ev.unresolved_calls.add(dotted)
        if not recognised:
            self._unrecognised_call(func, dotted, last, glb, target)

    def _unrecognised_call(self, func: ast.AST, dotted: str, last: str, glb: dict[str, Any], target: Any) -> None:
        """A call none of the patterns explains: free of external effects, a change of state that
        outlives the call (memory_write), or opaque (it may do anything the analysis cannot see)."""
        if last in ARTIFACT_WRITE:
            self.ev.state_write = True
            return
        if last in ARTIFACT_READ:
            self.ev.file_read = True
            return
        if dotted in PURE_CALLS:
            return
        root = _root_name(func)
        kind = self._root_kind(root, glb)
        if target is not None:
            if inspect.isclass(target):
                return                                      # constructing a value
            owner = getattr(target, "__self__", None)
            if owner is not None and not isinstance(owner, types.ModuleType):
                owner_type = owner if inspect.isclass(owner) else type(owner)   # class- or instance-bound
                owner_module = getattr(owner_type, "__module__", "") or ""
                if owner_module == "builtins" or _module_is_pure(owner_module):
                    if last in MUTATING_METHODS and kind in ("self", "global") and not inspect.isclass(owner):
                        self.ev.memory_write = True
                    return
                self.ev.opaque_calls.add(dotted)
                return
            module = getattr(target, "__module__", None) or (owner.__name__ if isinstance(owner, types.ModuleType)
                                                             else "")
            if _module_is_pure(module):
                return
            self.ev.opaque_calls.add(dotted or "<dynamic call>")
            return
        if isinstance(func, ast.Name):
            if func.id in self._locals:
                self.ev.opaque_calls.add(dotted)            # a callable passed in or built at run time
            return                                          # a builtin (open / exec are patterns above)
        if kind == "global":
            base = glb.get(root)
            if isinstance(base, types.ModuleType):
                if not _module_is_pure(base.__name__):
                    self.ev.opaque_calls.add(dotted)
                return
        if kind == "container":
            return                                          # a value the function built: in memory
        if last in MUTATING_METHODS:
            if kind in ("self", "global"):
                self.ev.memory_write = True
            elif last not in CONTAINER_ONLY_MUTATIONS:
                self.ev.opaque_calls.add(dotted)            # e.g. doc_ref.update(...) of an SDK object
            return
        if last in PURE_METHODS:
            return
        self.ev.opaque_calls.add(dotted or "<dynamic call>")

    def _patterns(self, node: ast.Call, func: ast.AST, dotted: str, last: str, receiver: str, low: str) -> None:
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


def dynamic_run_nodes(fn: Callable[..., Any]) -> tuple[list[Any], list[str]]:
    """Nodes a graph-workflow function node starts dynamically (``ctx.run_node(X, ...)``):
    (objects ``X`` resolves to through the function's globals and closure, expressions that do
    not resolve). Followed into the application's own helpers like the side-effect analysis."""
    found: list[Any] = []
    unresolved: list[str] = []
    for target, _rebind, expr in _run_node_targets(fn):
        if target is None:
            unresolved.append(expr)
        elif not any(target is x for x in found):
            found.append(target)
    return found, unresolved


def dynamic_run_node_bindings(fn: Callable[..., Any]) -> list[tuple[Any, Callable[[Any], None]]]:
    """(target, rebind) for every node a function node starts dynamically: ``rebind(obj)`` makes
    the code start ``obj`` instead (the name it is reached through -- module global, closure
    variable or attribute -- is bound to ``obj``). The distributed runtime binds remote proxies."""
    return [(t, r) for t, r, _e in _run_node_targets(fn) if t is not None and r is not None]


def _run_node_targets(fn: Callable[..., Any]) -> list[tuple[Any, Callable[[Any], None] | None, str]]:
    out: list[tuple[Any, Callable[[Any], None] | None, str]] = []
    seen: set[Any] = set()

    def binder(arg: ast.AST, glb: dict[str, Any], cells: dict[str, Any], f_globals: dict[str, Any]
               ) -> Callable[[Any], None] | None:
        if isinstance(arg, ast.Name):
            if arg.id in cells:
                cell = cells[arg.id]
                return lambda obj: setattr(cell, "cell_contents", obj)
            if arg.id in f_globals:
                return lambda obj: f_globals.__setitem__(arg.id, obj)
            return None
        if isinstance(arg, ast.Attribute):
            owner = _Analyzer._resolve(arg.value, glb) if isinstance(arg.value, (ast.Name, ast.Attribute)) else None
            if owner is not None:
                return lambda obj: setattr(owner, arg.attr, obj)
        return None

    def scan(f: Callable[..., Any], depth: int) -> None:
        f = _unwrap(f)
        code = getattr(f, "__code__", None)
        if code is None or code in seen or depth > MAX_DEPTH:
            return
        seen.add(code)
        try:
            tree = ast.parse(textwrap.dedent(inspect.getsource(f)))
        except (OSError, TypeError, SyntaxError, IndentationError):
            return
        f_globals = getattr(f, "__globals__", {}) or {}
        glb = dict(f_globals)
        cells: dict[str, Any] = {}
        for var, cell in zip(code.co_freevars, getattr(f, "__closure__", None) or ()):
            try:
                glb[var] = cell.cell_contents
                cells[var] = cell
            except ValueError:
                pass
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute) and node.func.attr == "run_node":
                arg = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg == "node"), None)
                target = _Analyzer._resolve(arg, glb) if isinstance(arg, (ast.Name, ast.Attribute)) else None
                expr = ast.unparse(arg) if arg is not None else "<missing>"
                out.append((target, binder(arg, glb, cells, f_globals) if target is not None else None, expr))
                continue
            callee = _Analyzer._resolve(node.func, glb)
            if callee is not None and callable(callee) and not inspect.isclass(callee) and is_application_code(callee):
                scan(callee, depth + 1)

    scan(fn, 0)
    return out


def analyze_tool_object(tool: Any) -> CodeEvidence:
    """Custom BaseTool subclasses: analyse their run_async implementation."""
    run = getattr(type(tool), "run_async", None)
    if run is None:
        return CodeEvidence(notes=["no run_async"])
    return analyze_callable(run)
