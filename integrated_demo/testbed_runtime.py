from __future__ import annotations

import asyncio
import importlib
import importlib.util
import inspect
import json
import sys
from pathlib import Path
from typing import Any

import yaml


class TestbedToolError(RuntimeError):
    pass


def _load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(value, dict):
        raise TestbedToolError(f"expected mapping in {path}")
    return value


def _source_path(reference: str) -> str:
    # Scanner references look like: citi_banking_adk/bank_adk/tools/x.py:14
    text = str(reference or "")
    if ":" in text:
        head, tail = text.rsplit(":", 1)
        if tail.isdigit():
            return head
    return text


def _normalize(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool, list, dict)):
        return value
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "json") and callable(value.json):
        try:
            return value.json()
        except Exception:
            pass
    if hasattr(value, "text"):
        return {"status_code": getattr(value, "status_code", None), "text": str(value.text)}
    try:
        json.dumps(value)
        return value
    except TypeError:
        return repr(value)


class TestbedToolRuntime:
    """Resolve real scanner-discovered Python tools without changing the testbed.

    The runtime uses Task 2's source references as the source of truth. It imports
    the original module and invokes the original function only after the PEP has
    authorized the operation.
    """

    def __init__(self, banking_repo: Path, scanner_output: Path) -> None:
        self.banking_repo = Path(banking_repo).resolve()
        self.scanner_output = Path(scanner_output).resolve()
        raw = _load_yaml(self.scanner_output / "tools_draft.yaml").get("tools", [])
        self.tools = {
            str(item.get("tool_id")): item
            for item in raw
            if item.get("tool_id") and not str(item.get("tool_id")).startswith("_")
        }
        self._prepare_import_paths()

    def _prepare_import_paths(self) -> None:
        candidates = [self.banking_repo]
        # Citi testbed commonly has citi_banking_adk/bank_adk/...
        candidates.extend(path for path in self.banking_repo.rglob("bank_adk") if path.is_dir())
        for bank_adk in list(candidates):
            if bank_adk.name == "bank_adk":
                candidates.append(bank_adk.parent)
        for path in candidates:
            text = str(path)
            if text not in sys.path:
                sys.path.insert(0, text)

    def available(self, tool_id: str) -> bool:
        return tool_id in self.tools

    def source_reference(self, tool_id: str) -> str:
        item = self.tools.get(tool_id)
        if not item:
            raise TestbedToolError(f"Task 2 did not discover tool {tool_id!r}")
        return str(item.get("source", {}).get("reference") or "")

    def _resolve_file(self, tool_id: str) -> Path:
        reference = self.source_reference(tool_id)
        rel = Path(_source_path(reference))
        direct = self.banking_repo / rel
        if direct.exists():
            return direct.resolve()

        # If --banking-repo points one directory above the actual testbed, match
        # the scanner reference suffix rather than assuming a fixed checkout name.
        rel_parts = rel.parts
        matches: list[Path] = []
        for candidate in self.banking_repo.rglob(rel.name):
            if not candidate.is_file():
                continue
            parts = candidate.relative_to(self.banking_repo).parts
            suffix_len = min(len(parts), len(rel_parts))
            if tuple(parts[-suffix_len:]) == tuple(rel_parts[-suffix_len:]):
                matches.append(candidate)
        if len(matches) == 1:
            return matches[0].resolve()
        if matches:
            # Prefer the longest suffix match.
            return max(matches, key=lambda p: len(p.parts)).resolve()
        raise TestbedToolError(
            f"cannot resolve source file for {tool_id!r}: scanner reference={reference!r}, "
            f"banking_repo={self.banking_repo}"
        )

    def _load_module(self, file_path: Path):
        parts = file_path.parts
        if "bank_adk" in parts:
            idx = parts.index("bank_adk")
            module_parts = list(parts[idx:])
            module_parts[-1] = Path(module_parts[-1]).stem
            module_name = ".".join(module_parts)
            try:
                return importlib.import_module(module_name)
            except Exception as exc:
                package_exc = exc
            else:  # pragma: no cover
                package_exc = None
        else:
            package_exc = None

        module_name = f"zt_testbed_dynamic_{file_path.stem}_{abs(hash(str(file_path)))}"
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            raise TestbedToolError(f"cannot create import spec for {file_path}")
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:
            if package_exc is not None:
                raise TestbedToolError(
                    f"failed importing {file_path}; package import error={package_exc!r}; "
                    f"file import error={exc!r}"
                ) from exc
            raise TestbedToolError(f"failed importing {file_path}: {exc!r}") from exc
        return module

    @staticmethod
    def _unwrap_callable(obj: Any) -> Any:
        if callable(obj):
            return obj
        for attr in ("func", "function", "_func", "fn"):
            candidate = getattr(obj, attr, None)
            if callable(candidate):
                return candidate
        raise TestbedToolError(f"resolved object is not callable: {obj!r}")

    @staticmethod
    def _prepare_kwargs(func: Any, parameters: dict[str, Any]) -> dict[str, Any]:
        try:
            signature = inspect.signature(func)
        except (TypeError, ValueError):
            return dict(parameters)
        has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in signature.parameters.values())
        if has_var_kw:
            return dict(parameters)
        kwargs = {
            name: parameters[name]
            for name, param in signature.parameters.items()
            if name in parameters and param.kind in {inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY}
        }
        missing = [
            name
            for name, param in signature.parameters.items()
            if param.default is inspect.Parameter.empty
            and param.kind in {inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY}
            and name not in kwargs
        ]
        if missing:
            raise TestbedToolError(
                f"missing required parameters for {getattr(func, '__name__', func)!r}: {missing}; "
                f"provided={sorted(parameters)}"
            )
        return kwargs

    def resolve(self, tool_id: str) -> Any:
        file_path = self._resolve_file(tool_id)
        module = self._load_module(file_path)
        obj = getattr(module, tool_id, None)
        if obj is None:
            raise TestbedToolError(f"{tool_id!r} not found in imported module {file_path}")
        return self._unwrap_callable(obj)

    @staticmethod
    def _initialize_tool_runtime(func: Any) -> None:
        """Initialize the repository used by directly imported Citi ADK tools.

        Normal Citi testbed startup calls ``bootstrap_runtime()`` before agents run.
        Direct tool invocation bypasses that startup path, so SQLite may otherwise
        create an empty ``.runtime/banking.db`` with no tables.  The tool modules
        import their repository singleton as ``repo``; initializing that exact
        object keeps this adapter bound to the same runtime database as the tool.
        """
        repo = getattr(func, "__globals__", {}).get("repo")
        initialize = getattr(repo, "initialize", None)
        if callable(initialize):
            initialize()

    def invoke(self, tool_id: str, parameters: dict[str, Any]) -> Any:
        func = self.resolve(tool_id)
        self._initialize_tool_runtime(func)
        kwargs = self._prepare_kwargs(func, parameters)
        try:
            result = func(**kwargs)
            if inspect.isawaitable(result):
                try:
                    asyncio.get_running_loop()
                except RuntimeError:
                    result = asyncio.run(result)
                else:
                    # run_demo is synchronous, so a running loop would be unusual.
                    raise TestbedToolError("cannot synchronously await testbed tool inside an active event loop")
            return _normalize(result)
        except TestbedToolError:
            raise
        except Exception as exc:
            raise TestbedToolError(
                f"real testbed tool {tool_id!r} raised {type(exc).__name__}: {exc}"
            ) from exc
