"""Console configuration: where the protected application's profile, bundle and state live."""
from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", ".zt", "__pycache__", ".zt-console", "site-packages"}


class ProfileError(ValueError):
    """The profile file cannot be used (missing, not YAML, or not a mapping)."""


def _default_zt_adk() -> list[str]:
    """The zt-adk command installed next to this Python (also ``zt-adk.exe`` in a Windows ``Scripts`` folder)."""
    here = Path(sys.executable).parent
    for name in ("zt-adk", "zt-adk.exe"):
        if (here / name).exists():
            return [str(here / name)]
    found = shutil.which("zt-adk")
    return [found] if found else []


def _expand(value: str) -> str:
    return os.path.expandvars(value) if "$" in value else value


def discover_profiles(root: Path, depth: int = 3) -> list[Path]:
    """zt_adk*.yaml files below ``root`` (a few levels deep, skipping environments and build output)."""
    found: list[Path] = []

    def walk(d: Path, level: int) -> None:
        try:
            entries = sorted(d.iterdir())
        except OSError:
            return
        for e in entries:
            if e.is_file() and e.name.startswith("zt_adk") and e.suffix in (".yaml", ".yml"):
                found.append(e.resolve())
            elif e.is_dir() and level < depth and e.name not in SKIP_DIRS and not e.name.startswith("."):
                walk(e, level + 1)

    walk(Path(root), 0)
    return found


@dataclass
class Config:
    profile: Path | None = None
    bundle_dir: Path | None = None
    state_dir: Path | None = None
    keys_dir: Path | None = None
    approver_dir: Path | None = None
    app: str = ""
    data_dir: Path = field(default_factory=lambda: Path(".zt-console"))
    dev_approve: bool = False                      # developer mode: approve from the console with a local key
    zt_adk: list[str] = field(default_factory=_default_zt_adk)
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "[::1]")
    run_timeout_s: int = 150
    max_message_chars: int = 4000

    @property
    def configured(self) -> bool:
        return self.profile is not None and self.bundle_dir is not None and (self.bundle_dir / "bundle.json").is_file()

    @property
    def approvals_dir(self) -> Path | None:
        return self.state_dir / "approvals" if self.state_dir else None

    @classmethod
    def from_profile(cls, profile: str | Path, **overrides: Any) -> "Config":
        path = Path(profile).resolve()
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except OSError as exc:
            raise ProfileError(f"cannot read profile {path}: {exc.strerror or exc}") from exc
        except yaml.YAMLError as exc:
            raise ProfileError(f"profile {path} is not valid YAML: {exc}") from exc
        if not isinstance(raw, dict):
            raise ProfileError(f"profile {path} must be a YAML mapping (key: value), found {type(raw).__name__}")
        base = path.parent

        def rel(key: str, default: str) -> Path:
            return (base / _expand(str(raw.get(key) or default))).resolve()

        cfg = cls(profile=path, bundle_dir=rel("bundle_dir", ".zt/bundle"), state_dir=rel("state_dir", ".zt/state"),
                  keys_dir=rel("keys_dir", ".zt/keys"), approver_dir=rel("approver_keys_dir", ".zt/approver-keys"),
                  app=str(raw.get("app") or ""))
        for k, v in overrides.items():
            if v is not None:
                setattr(cfg, k, v)
        return cfg
