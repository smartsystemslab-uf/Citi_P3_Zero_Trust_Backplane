"""Direct CLI failure injection alongside real subprocess integration tests."""

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

CLI = Path(__file__).resolve().parents[1] / "bootstrap_agent_keys.py"
spec = importlib.util.spec_from_file_location("bootstrap_agent_keys", CLI)
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


def args(env, identity="new"):
    manifest = env.dir / "agents.yaml"
    manifest.write_text(yaml.safe_dump({"agents": [{"agent_id": identity}]}))
    return ["--manifest", str(manifest), "--keys-dir", str(env.dir / "keys"),
            "--public-keys", str(env.dir / "public.yaml"), "--registry", str(env.path),
            "--registry-root-private-key", str(env.private), "--registry-root-key-id", "root-v1"]


def test_default_manifest_candidates(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "REPO_ROOT", tmp_path)
    first = tmp_path / "zero_trust_task2/draft_manifests/agents_draft.yaml"
    second = tmp_path / "zero_trust_task2/output/draft_manifests/agents_draft.yaml"
    assert cli.get_default_manifest_path() == first
    second.parent.mkdir(parents=True)
    second.write_text("agents: []")
    assert cli.get_default_manifest_path() == second
    first.parent.mkdir(parents=True)
    first.write_text("agents: []")
    assert cli.get_default_manifest_path() == first


def test_publication_failure_does_not_claim_success(env, monkeypatch, capsys):
    values = args(env)
    def fail(*args, **kwargs):
        raise OSError("simulated failure")
    monkeypatch.setattr(cli, "write_signed_registry", fail)
    with pytest.raises(SystemExit) as exc:
        cli.main(values)
    assert exc.value.code == 1
    output = capsys.readouterr()
    assert "publication failed" in output.err
    assert "Generated keys" not in output.out
    assert (env.dir / "keys/new.key").exists()
    assert not env.path.exists()


@pytest.mark.parametrize("identity", ["../escape", ".", "..", "a/b", "a\\b", "a:b"])
def test_unsafe_signed_bootstrap_identity(env, identity):
    with pytest.raises(SystemExit):
        cli.main(args(env, identity))
    assert not (env.dir / "keys").exists()


def test_duplicates_and_output_collision_fail_before_keygen(env):
    values = args(env)
    manifest = env.dir / "agents.yaml"
    manifest.write_text("agents: [{agent_id: new}, {agent_id: new}]")
    with pytest.raises(SystemExit):
        cli.main(values)
    values = args(env)
    values[values.index("--public-keys") + 1] = str(env.path)
    with pytest.raises(SystemExit):
        cli.main(values)
    assert not (env.dir / "keys").exists()


def test_resolved_key_path_escape(env, monkeypatch):
    values = args(env)
    original = Path.resolve
    def resolve(path, *args, **kwargs):
        if path.name == "new.key":
            return env.dir / "escaped.key"
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "resolve", resolve)
    with pytest.raises(SystemExit):
        cli.main(values)
    assert not (env.dir / "keys").exists()


def test_signed_and_unsigned_main(env, capsys, monkeypatch):
    values = args(env)
    monkeypatch.setattr(sys, "argv", [str(CLI), *values])
    cli.main()
    assert "Signed registry:" in capsys.readouterr().out
    values = args(env, "other")[:6]
    cli.main(values)
    assert "Generated keys for 1 agents" in capsys.readouterr().out
