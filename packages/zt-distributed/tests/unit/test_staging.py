"""Staging of an application for its runtime image (zt_distributed.staging)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

EXAMPLE = Path(__file__).resolve().parents[4] / "examples" / "helpdesk_mas"


def _stage(profile_path: Path, dest: Path):
    from zt_adk.profile import load_profile
    from zt_distributed.staging import stage_application

    prof = load_profile(profile_path)
    return prof, stage_application(prof, profile_path, dest)


def test_profile_next_to_the_application(tmp_path):
    from zt_adk.profile import load_profile

    dest = tmp_path / "app"
    _prof, doc = _stage(EXAMPLE / "zt_adk.playback.yaml", dest)
    assert doc["python_paths"] == ["."] and doc["policies"]["overlays"] == ["policies/*.psl"]
    assert doc["model_override"]["script"] == "playback.yaml"
    assert doc["distributed"]["requirements"] == ["requirements.txt"]
    assert (dest / "helpdesk" / "agent.py").exists() and (dest / "policies" / "helpdesk.psl").exists()
    assert not list(dest.rglob("__pycache__")) and not (dest / ".zt").exists()
    staged = load_profile(dest / "zt_adk.playback.yaml")          # what the image loads
    assert staged.path(staged.model_override.script).is_file()


def test_profile_apart_from_the_application(tmp_path, monkeypatch):
    """A profile in its own directory; the application found through ${VAR} elsewhere."""
    from zt_adk.profile import load_profile

    app = tmp_path / "elsewhere" / "shop_app"
    (app / "shop").mkdir(parents=True)
    (app / "shop" / "__init__.py").write_text("", encoding="utf-8")
    (app / "shop" / "agent.py").write_text(
        "from google.adk.agents import LlmAgent\nroot_agent = LlmAgent(name='shop', model='gemini-2.5-flash')\n",
        encoding="utf-8")
    (app / "shop" / "__pycache__").mkdir()
    (app / "shop" / "__pycache__" / "agent.cpython-311.pyc").write_bytes(b"x")
    (app / "requirements.txt").write_text("google-adk\n", encoding="utf-8")
    cfg = tmp_path / "config"
    (cfg / "policies").mkdir(parents=True)
    (cfg / "policies" / "shop.psl").write_text("// overlay\n", encoding="utf-8")
    (cfg / "zt_adk.yaml").write_text(
        'app: "shop.agent:root_agent"\npython_paths: ["${SHOP_APP}"]\nsource_root: "${SHOP_APP}"\n'
        'policies: {overlays: ["policies/*.psl"]}\n'
        'distributed:\n  app_paths: ["${SHOP_APP}/shop", "policies"]\n'
        '  requirements: ["${SHOP_APP}/requirements.txt"]\n  secret_env_files: [".env"]\n', encoding="utf-8")
    monkeypatch.setenv("SHOP_APP", str(app))
    with pytest.raises(Exception, match="requirements.txt.*not part of the staged application"):
        _stage(cfg / "zt_adk.yaml", tmp_path / "x")
    text = (cfg / "zt_adk.yaml").read_text(encoding="utf-8")
    (cfg / "zt_adk.yaml").write_text(text.replace('["${SHOP_APP}/shop", "policies"]',
                                                  '["${SHOP_APP}/shop", "${SHOP_APP}/requirements.txt", "policies"]'),
                                     encoding="utf-8")
    dest = tmp_path / "app_staged"
    _prof, doc = _stage(cfg / "zt_adk.yaml", dest)
    assert doc["distributed"]["app_paths"] == ["_ext/0/shop", "_ext/0/requirements.txt", "policies"]
    assert doc["distributed"]["requirements"] == ["_ext/0/requirements.txt"]
    assert doc["python_paths"] == ["_ext/0"] and doc["source_root"] == "_ext/0"
    assert doc["policies"]["overlays"] == ["policies/*.psl"]
    assert doc["distributed"]["secret_env_files"] == []                  # host only
    assert (dest / "_ext" / "0" / "shop" / "agent.py").exists()
    assert not (dest / "_ext" / "0" / "shop" / "__pycache__").exists()
    monkeypatch.delenv("SHOP_APP")
    staged = load_profile(dest / "zt_adk.yaml")                          # no ${VAR} left
    code = ("import sys; from zt_adk.discovery import load_object; from zt_adk.profile import load_profile; "
            f"p = load_profile(r'{dest / 'zt_adk.yaml'}'); "
            "a = load_object(p.app, [p.path(x) for x in p.python_paths]); print(a.name)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert out.stdout.strip().splitlines()[-1] == "shop", out.stderr[-2000:]
    assert staged.path(staged.python_paths[0]) == (dest / "_ext" / "0").resolve()


def test_unstaged_reference_is_refused(tmp_path, monkeypatch):
    from zt_distributed.staging import StagingError

    app = tmp_path / "app"
    (app / "pkg").mkdir(parents=True)
    (app / "lib").mkdir()                                    # on the python path, but never staged
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "zt_adk.yaml").write_text('app: "pkg.m:x"\npython_paths: ["' + (app / "lib").as_posix() + '"]\n'
                                     'distributed: {app_paths: ["' + (app / "pkg").as_posix() + '"]}\n',
                                     encoding="utf-8")
    with pytest.raises(StagingError, match="python_paths entry"):
        _stage(cfg / "zt_adk.yaml", tmp_path / "out")
