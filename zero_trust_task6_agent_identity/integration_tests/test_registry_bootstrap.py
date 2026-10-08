import base64
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zt_task6.keygen import bootstrap_agent_keys
from zt_task6.registry import RegistryError, write_signed_registry
from conftest import NOW, load


MODULE = Path(__file__).resolve().parents[1]


def manifest(env, names):
    path = env.dir / "agents.yaml"
    path.write_text(yaml.safe_dump({"agents": [{"agent_id": name} for name in names]}))
    return path


def run_cli(env, names=("agent",), extras=(), signed=True):
    command = [sys.executable]
    if os.getenv("AUTHN2_COVERAGE"):
        command += ["-m", "coverage", "run", "--parallel-mode",
                    "--source=zt_task6,bootstrap_agent_keys"]
    command += [str(MODULE / "bootstrap_agent_keys.py"),
                "--manifest", str(manifest(env, names)),
                "--keys-dir", str(env.dir / "keys"),
                "--public-keys", str(env.dir / "public.yaml")]
    if signed:
        command += ["--registry", str(env.path), "--registry-root-private-key", str(env.private),
                    "--registry-root-key-id", "root-v1"]
    return subprocess.run([*command, *extras], capture_output=True, text=True, cwd=MODULE)


def test_real_function_chain_and_reload(env):
    keys = bootstrap_agent_keys(manifest(env, ["agent"]), env.dir / "keys", env.dir / "public.yaml")
    write_signed_registry(keys, env.path, root_private_key_path=env.private,
                          root_key_id="root-v1", valid_from=NOW)
    store = load(env)
    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(
        (env.dir / "keys/agent.key").read_text()))
    store.lookup("agent", at=NOW)[0].as_public_key().verify(private.sign(b"request"), b"request")
    keys = bootstrap_agent_keys(manifest(env, ["new"]), env.dir / "keys", env.dir / "public.yaml")
    write_signed_registry(keys, env.path, root_private_key_path=env.private,
                          root_key_id="root-v1", valid_from=NOW)
    assert store.lookup("new", at=NOW) == ()
    store.reload()
    assert store.lookup("new", at=NOW) and store.lookup("agent", at=NOW)


def test_real_signed_cli_and_incremental_bootstrap(env):
    result = run_cli(env)
    assert result.returncode == 0, result.stderr
    assert "Signed registry:" in result.stdout
    store = load(env)
    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(
        (env.dir / "keys/agent.key").read_text()))
    store.lookup("agent")[0].as_public_key().verify(private.sign(b"tool"), b"tool")
    before = (env.dir / "keys/agent.key").read_bytes()
    second = run_cli(env, names=("new",))
    assert second.returncode == 0, second.stderr
    store.reload()
    assert store.lookup("new") and store.lookup("agent")
    assert (env.dir / "keys/agent.key").read_bytes() == before


@pytest.mark.parametrize("extras", [
    ("--registry", "unused.yaml"), ("--registry-root-private-key", "missing.pem"),
    ("--registry-root-key-id", "root-v1"),
    ("--registry", "unused.yaml", "--registry-root-key-id", "root-v1"),
])
def test_cli_partial_options_fail_without_writes(env, extras):
    result = run_cli(env, signed=False, extras=extras)
    assert result.returncode == 2
    assert "required together" in result.stderr
    assert not (env.dir / "keys").exists()


def test_cli_signing_failure_and_tampered_registry_preflight(env):
    env.private.write_text("invalid root")
    result = run_cli(env)
    assert result.returncode != 0 and "preflight failed" in result.stderr
    assert not (env.dir / "keys").exists()


def test_cli_tampered_registry_blocks_keygen(env):
    env.path.write_text("public_keys: {}")
    result = run_cli(env)
    assert result.returncode != 0
    assert not (env.dir / "keys").exists()
    assert env.path.read_text() == "public_keys: {}"


def test_force_cannot_replace_registered_agent(env):
    assert run_cli(env).returncode == 0
    before = (env.dir / "keys/agent.key").read_bytes()
    signed_before = env.path.read_bytes()
    result = run_cli(env, extras=("--force",))
    assert result.returncode != 0 and "rotation" in result.stderr
    assert (env.dir / "keys/agent.key").read_bytes() == before
    assert env.path.read_bytes() == signed_before


def test_unsigned_authn1_cli_remains_compatible(env):
    result = run_cli(env, signed=False)
    assert result.returncode == 0, result.stderr
    assert "Signed registry:" not in result.stdout
    assert yaml.safe_load((env.dir / "public.yaml").read_text())["public_keys"]["agent"]
    assert not env.path.exists()
    env.path.write_bytes((env.dir / "public.yaml").read_bytes())
    with pytest.raises(RegistryError):
        load(env)


def test_keygen_failure_never_publishes_registry(env):
    assert run_cli(env, signed=False).returncode == 0
    result = run_cli(env)
    assert result.returncode != 0
    assert not env.path.exists()
