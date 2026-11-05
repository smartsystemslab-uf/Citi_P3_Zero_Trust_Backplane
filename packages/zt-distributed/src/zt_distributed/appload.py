"""Load the protected ADK application inside a runtime container.

The application and its ``zt_adk.yaml`` are copied into the image under ``/opt/app`` (path
in ``ZT_ADK_PROFILE``). Every workload builds the application's agent tree from the same
code; each one then hosts exactly one agent of it (``remote.host_agent``), the gateway
executes its tools.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from zt_adk.discovery import discover, load_object, resolve_app
from zt_adk.model import SystemModel
from zt_adk.profile import Profile, load_profile

PROFILE_PATH = Path(os.environ.get("ZT_ADK_PROFILE", "/opt/app/zt_adk.yaml"))


@dataclass
class LoadedApp:
    profile: Profile
    root: Any
    app_name: str
    model: SystemModel
    agents: dict[str, Any]
    tools: dict[str, Any]
    plugins: list[Any] = field(default_factory=list)      # the application's own plugins (App / Runner)


def load_app(profile_path: Path | None = None, *, resolve_toolsets: bool = False,
             apply_model_override: bool = True) -> LoadedApp:
    from zt_adk.plugin import own_plugins

    prof = load_profile(profile_path or PROFILE_PATH)
    obj = load_object(prof.app, [prof.path(p) for p in prof.python_paths])
    root, name, _plugins = resolve_app(obj)
    app_name = prof.app_name or name or root.name
    if apply_model_override and prof.model_override is not None:
        from zt_adk.testing.playback import install_playback

        install_playback(root, prof.path(prof.model_override.script))
    declared = {n: ov.tools for n, ov in prof.toolsets.items()}
    resolution = {n: ov.resolve for n, ov in prof.toolsets.items()}
    model, agents, tools = discover(root, app_name=app_name, resolve_toolsets=resolve_toolsets,
                                    declared_toolset_tools=declared, toolset_resolution=resolution)
    return LoadedApp(prof, root, app_name, model, agents, tools, own_plugins(obj))
