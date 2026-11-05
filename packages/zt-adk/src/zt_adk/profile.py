"""Protection profile of one ADK application: ``zt_adk.yaml`` next to the application.

Everything has a safe default; the profile only states what the code cannot tell (which
operations are critical, who may call what, which content must never leave the system,
which policies the owner adds). ``zt-adk init`` writes a commented template.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

IDENT = re.compile(r"^[a-z][a-z0-9_]*$")
Action = Literal["read", "write", "create", "update", "delete", "send", "execute", "invoke", "use"]
Criticality = Literal["low", "medium", "high", "critical"]
Classification = Literal["public", "internal", "confidential", "restricted", "regulated"]
ContentAction = Literal["deny", "flag", "off"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ToolOverride(_Strict):
    action: Action | None = None
    side_effect: bool | None = None
    criticality: Criticality | None = None
    classification: Classification | None = None
    requires_approval: bool | None = None
    secondary_approval: bool | None = None
    allowed_roles: list[str] | None = None
    mask_fields: list[str] = Field(default_factory=list)
    idempotent: bool | None = None


class ToolsetOverride(_Strict):
    resolve: bool = True
    tools: list[str] = Field(default_factory=list)      # declared names when resolution is impossible


class Domains(_Strict):
    mode: Literal["subtree", "single", "explicit"] = "subtree"
    default: str = "core"
    agents: dict[str, str] = Field(default_factory=dict)

    @field_validator("default")
    @classmethod
    def _ident(cls, v: str) -> str:
        if not IDENT.match(v):
            raise ValueError(f"domain {v!r} must match {IDENT.pattern}")
        return v

    @field_validator("agents")
    @classmethod
    def _idents(cls, v: dict[str, str]) -> dict[str, str]:
        for agent, dom in v.items():
            if not IDENT.match(dom):
                raise ValueError(f"domain {dom!r} of agent {agent} must match {IDENT.pattern}")
        return v


class Approvals(_Strict):
    critical: Literal["single", "dual", "none"] = "single"
    wait_seconds: float = 120.0          # how long a call waits for an approver before it is held
    lifetime_seconds: int = 300          # validity of a signed approval (<= PDP max assertion lifetime)
    poll_seconds: float = 1.0

    @model_validator(mode="after")
    def _bounds(self) -> "Approvals":
        if not 1 <= self.lifetime_seconds <= 3600:
            raise ValueError("approvals.lifetime_seconds must be between 1 and 3600")
        if self.wait_seconds < 0:
            raise ValueError("approvals.wait_seconds must be >= 0")
        return self


class DetectorRule(_Strict):
    input: ContentAction = "off"
    output: ContentAction = "off"
    tool_result: ContentAction = "off"


class CustomDetector(DetectorRule):
    pattern: str
    ignore_case: bool = True

    @field_validator("pattern")
    @classmethod
    def _compiles(cls, v: str) -> str:
        re.compile(v)
        return v


def _default_detectors() -> dict[str, DetectorRule]:
    return {
        "private_key": DetectorRule(output="deny", tool_result="flag", input="flag"),
        "api_key": DetectorRule(output="deny", tool_result="flag", input="flag"),
        "credit_card": DetectorRule(output="deny", tool_result="off", input="off"),
        "ssn": DetectorRule(output="deny"),
        "iban": DetectorRule(output="flag"),
        "email": DetectorRule(output="flag"),
        "phone": DetectorRule(output="flag"),
    }


class PromptInjection(_Strict):
    input: ContentAction = "deny"
    tool_result: ContentAction = "flag"
    agent_message: ContentAction = "flag"   # messages between agents (AgentTool requests)
    extra_patterns: list[str] = Field(default_factory=list)


class Content(_Strict):
    prompt_injection: PromptInjection = Field(default_factory=PromptInjection)
    detectors: dict[str, DetectorRule] = Field(default_factory=_default_detectors)
    custom: dict[str, CustomDetector] = Field(default_factory=dict)
    max_input_chars: int = 100_000
    taint_on_flag: bool = True     # a flagged tool result raises the run's risk (side effects then need approval)

    @field_validator("custom")
    @classmethod
    def _names(cls, v: dict[str, CustomDetector]) -> dict[str, CustomDetector]:
        for name in v:
            if not IDENT.match(name):
                raise ValueError(f"custom detector name {name!r} must match {IDENT.pattern}")
        return v


class Session(_Strict):
    require_session: bool = False
    roles: list[str] = Field(default_factory=list)     # roles an ingress may assert; empty = role not checked


class Policies(_Strict):
    overlays: list[str] = Field(default_factory=list)  # glob patterns of PSL files, relative to the profile
    workflow_order: bool = True                        # sequential workflows: steps in declared order
    deny_cross_domain_routes: bool = False             # an agent hands work only to agents of its own domain
    cross_domain_callers: list[str] = Field(default_factory=list)  # agents exempt (besides the root and ingress)


class Identity(_Strict):
    trust_domain: str = "zt-adk.local"

    @field_validator("trust_domain")
    @classmethod
    def _td(cls, v: str) -> str:
        if not re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", v):
            raise ValueError("identity.trust_domain must be a lower-case DNS-like name")
        return v


class ModelOverride(_Strict):
    type: Literal["playback"]
    script: str


class Service(_Strict):
    name: str
    image: str | None = None
    build: str | None = None                 # path to a build context (relative to the profile)
    dockerfile: str | None = None
    port: int | None = None
    environment: dict[str, str] = Field(default_factory=dict)
    healthcheck: list[str] | None = None


class Distributed(_Strict):
    compose_project: str = "citi_p3_ztbp"
    container_prefix: str = "ztbp-"
    python_image: str = "python:3.11-slim"
    requirements: list[str] = Field(default_factory=list)     # requirement files of the application
    pip_packages: list[str] = Field(default_factory=list)
    # copied into the image; relative to the profile, or anywhere (absolute / ${VAR}): an entry outside the
    # profile's directory is staged under _ext/ and the profile's paths into it are rewritten
    app_paths: list[str] = Field(default_factory=lambda: ["."])
    exclude: list[str] = Field(default_factory=lambda: [".venv", ".git", ".zt", "__pycache__", "*.pyc", ".env"])
    environment: dict[str, str] = Field(default_factory=dict)  # non-secret settings for every agent workload
    secret_env_files: list[str] = Field(default_factory=list)  # e.g. a .env with the model API key (not baked)
    services: list[Service] = Field(default_factory=list)      # backends the tools call
    tool_host_environment: dict[str, str] = Field(default_factory=dict)       # settings of the tools (gateway)
    tool_host_secret_env_files: list[str] = Field(default_factory=list)       # secrets of the tools (not baked)
    data_volumes: dict[str, str] = Field(default_factory=dict)  # volume name -> mount path in the tool host
    setup_command: list[str] | None = None                     # run once in the tool host before start


class Profile(_Strict):
    version: Literal[1] = 1
    app: str
    app_name: str | None = None
    source_root: str = "."
    python_paths: list[str] = Field(default_factory=lambda: ["."])
    environment: str = "dev"
    mode: Literal["enforce", "shadow"] = "enforce"
    bundle_dir: str = ".zt/bundle"
    keys_dir: str = ".zt/keys"
    approver_keys_dir: str = ".zt/approver-keys"
    state_dir: str = ".zt/state"
    strict: bool = True              # unresolved toolsets without declared tools fail the build
    domains: Domains = Field(default_factory=Domains)
    tools: dict[str, ToolOverride] = Field(default_factory=dict)
    toolsets: dict[str, ToolsetOverride] = Field(default_factory=dict)
    approvals: Approvals = Field(default_factory=Approvals)
    content: Content = Field(default_factory=Content)
    session: Session = Field(default_factory=Session)
    policies: Policies = Field(default_factory=Policies)
    identity: Identity = Field(default_factory=Identity)
    distributed: Distributed = Field(default_factory=Distributed)
    model_override: ModelOverride | None = None

    # set by load(): directory of the profile file
    base_dir: Path = Field(default=Path("."), exclude=True)

    @field_validator("environment")
    @classmethod
    def _env(cls, v: str) -> str:
        allowed = {"example", "prototype", "dev", "test", "stage", "prod", "citi_dev", "citi_test",
                   "citi_stage", "citi_prod"}
        if v not in allowed:
            raise ValueError(f"environment must be one of {sorted(allowed)}")
        return v

    @field_validator("app")
    @classmethod
    def _app(cls, v: str) -> str:
        if ":" not in v:
            raise ValueError("app must be 'module:attribute' (an ADK App, an agent, or a factory 'module:fn()')")
        return v

    def path(self, value: str) -> Path:
        """A path of the profile: ``$VAR`` / ``${VAR}`` are expanded (an unset variable is an error),
        relative paths are relative to the profile's directory."""
        expanded = os.path.expandvars(str(value))
        if "$" in expanded:
            raise ValueError(f"unset environment variable in profile path {value!r}")
        p = Path(expanded)
        return p if p.is_absolute() else (self.base_dir / p).resolve()

    def tool_override(self, agent: str, tool: str) -> ToolOverride | None:
        return self.tools.get(f"{agent}/{tool}") or self.tools.get(tool)

    def detector_rules(self) -> dict[str, DetectorRule]:
        out: dict[str, DetectorRule] = dict(self.content.detectors)
        out.update(self.content.custom)
        return out


def load_profile(path: str | Path) -> Profile:
    p = Path(path).resolve()
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{p}: the profile must be a mapping")
    profile = Profile.model_validate(raw)
    profile.base_dir = p.parent
    return profile


def profile_from_dict(raw: dict[str, Any], base_dir: str | Path = ".") -> Profile:
    profile = Profile.model_validate(raw)
    profile.base_dir = Path(base_dir).resolve()
    return profile
