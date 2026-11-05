from __future__ import annotations

import asyncio
import importlib
import json
import os
import shutil
import sys
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

warnings.filterwarnings("ignore")
BACKPLANE = Path(__file__).resolve().parents[3]          # repository root
EXAMPLE = BACKPLANE / "examples" / "helpdesk_mas"
if str(EXAMPLE) not in sys.path:
    sys.path.insert(0, str(EXAMPLE))


def helpdesk_profile(tmp: Path, **overrides: Any):
    from zt_adk.profile import profile_from_dict

    raw: dict[str, Any] = {
        "app": "helpdesk.agent:app", "python_paths": ["."],
        "keys_dir": str(tmp / "keys"), "approver_keys_dir": str(tmp / "approver-keys"),
        "bundle_dir": str(tmp / "bundle"), "state_dir": str(tmp / "state"),
        "tools": {"run_diagnostic": {"criticality": "high"},
                  "reset_password": {"criticality": "critical", "requires_approval": True},
                  "lookup_user": {"mask_fields": ["email"]}},
        "approvals": {"critical": "single", "wait_seconds": 4, "poll_seconds": 0.1},
        "session": {"roles": ["employee", "service_desk_staff"]},
        "policies": {"overlays": [str(EXAMPLE / "policies" / "*.psl")]},
    }
    for k, v in overrides.items():
        if isinstance(v, dict) and isinstance(raw.get(k), dict):
            raw[k] = {**raw[k], **v}
        else:
            raw[k] = v
    return profile_from_dict(raw, base_dir=EXAMPLE)


@pytest.fixture(scope="session")
def built(tmp_path_factory):
    """Keys + bundle of the example service desk, built once."""
    from zt_adk.build import build
    from zt_adk.keys import init_keys

    tmp = tmp_path_factory.mktemp("helpdesk")
    init_keys(tmp / "keys", tmp / "approver-keys", approvers=["alice"], secondaries=["bob"])
    prof = helpdesk_profile(tmp)
    import helpdesk.agent as hd

    result = build(prof, root_agent=hd.build_root_agent(), app_name="helpdesk", skip_static=True)
    return tmp, prof, result


@dataclass
class Session:
    runner: Any
    sessions: Any
    plugin: Any
    session_id: str
    state_dir: Path
    events: list[Any] = field(default_factory=list)

    def say(self, text: str, *, run_config: Any = None, approve: dict | None = None) -> list[Any]:
        return asyncio.run(self._say(text, run_config, approve))

    async def _say(self, text: str, run_config: Any, approve: dict | None) -> list[Any]:
        from google.genai import types

        task = asyncio.create_task(_approver(self.state_dir, approve)) if approve else None
        out = []
        kwargs = {"run_config": run_config} if run_config is not None else {}
        async for ev in self.runner.run_async(user_id="u1", session_id=self.session_id,
                                              new_message=types.Content(role="user", parts=[types.Part(text=text)]),
                                              **kwargs):
            out.append(ev)
        if task is not None:
            await task
        self.events.extend(out)
        return out


async def _approver(state_dir: Path, spec: dict) -> None:
    from zt_adk.approvals import ApprovalStore
    from zt_adk.keys import approver_issuer, load_private
    from zt_pdp.evidence_issuer import IssuerKey

    store = ApprovalStore(state_dir / "approvals")
    keys = spec["keys_dir"]
    for _ in range(200):
        pending = store.list(status="pending")
        if pending:
            for purpose, (name, secondary) in spec["signers"].items():
                prefix = "secondary" if secondary else "approver"
                key = IssuerKey(approver_issuer(name, secondary), "key-1",
                                load_private(keys / f"{prefix}_{name}_private.pem"))
                store.decide(pending[0].approval_id, key=key, purpose=purpose, approve=spec.get("approve", True),
                             approver=name, lifetime_seconds=120)
            return
        await asyncio.sleep(0.05)


@pytest.fixture()
def desk(built, tmp_path, monkeypatch):
    """A protected service desk with a fresh database and state directory."""

    def make(*, role: str = "employee", root: Any = None, bundle: Path | None = None, mode: str | None = None,
             register: bool = True, chunk_size: int = 0) -> Session:
        from google.adk.runners import Runner
        from google.adk.sessions import InMemorySessionService

        from zt_adk.plugin import ZeroTrustPlugin
        from zt_adk.testing.playback import install_playback

        tmp, prof, _result = built
        monkeypatch.setenv("HELPDESK_DB", str(tmp_path / "helpdesk.db"))
        import helpdesk.agent as hd

        agent = root or hd.build_root_agent()
        install_playback(agent, EXAMPLE / "playback.yaml", chunk_size=chunk_size)
        state = tmp_path / "state"
        plugin = ZeroTrustPlugin(root_agent=agent, bundle_dir=bundle or (tmp / "bundle"), keys_dir=tmp / "keys",
                                 state_dir=state, mode=mode)
        sessions = InMemorySessionService()
        runner = Runner(app_name="helpdesk", agent=agent, session_service=sessions, plugins=[plugin])
        sess = asyncio.run(sessions.create_session(app_name="helpdesk", user_id="u1"))
        if register:
            plugin.register_session(sess.id, user_role=role)
        return Session(runner, sessions, plugin, sess.id, state)

    return make


def texts(events: list[Any]) -> list[str]:
    out = []
    for ev in events:
        for p in (ev.content.parts if ev.content else []) or []:
            if p.text:
                out.append(p.text)
    return out


def calls(events: list[Any]) -> list[str]:
    return [p.function_call.name for ev in events for p in ((ev.content.parts if ev.content else []) or [])
            if p.function_call]


def results(events: list[Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for ev in events:
        for p in (ev.content.parts if ev.content else []) or []:
            if p.function_response:
                out[p.function_response.name] = p.function_response.response
    return out


def audit(state_dir: Path) -> list[dict[str, Any]]:
    path = state_dir / "audit.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
