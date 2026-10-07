import os
import stat
import base64
import sys
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from zt_task6.keygen import (
    bootstrap_agent_keys,
    generate_keypair,
    load_agent_identities,
)


def create_test_manifest(path: Path) -> None:
    data = {
        "agents": [
            {"agent_id": "aml_investigator"},
            {"agent_id": "sar_drafting_agent"},
            {"agent_id": "front_office_router"},
        ]
    }

    path.write_text(
        yaml.safe_dump(data),
        encoding="utf-8",
    )


def test_load_agent_identities(tmp_path):
    manifest = tmp_path / "agents_draft.yaml"
    create_test_manifest(manifest)

    agents = load_agent_identities(manifest)

    assert agents
    assert "aml_investigator" in agents
    assert "sar_drafting_agent" in agents
    assert "front_office_router" in agents


def test_empty_agent_list_fails(tmp_path):
    manifest = tmp_path / "agents_draft.yaml"

    manifest.write_text(
        yaml.safe_dump({"agents": []}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_agent_identities(manifest)


def test_ed25519_sign_verify_round_trip():
    private_b64, public_b64 = generate_keypair()

    private_key = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(private_b64)
    )

    public_key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(public_b64)
    )

    message = b"authentication test"
    signature = private_key.sign(message)

    public_key.verify(signature, message)


def test_bootstrap_creates_keys(tmp_path):
    manifest = tmp_path / "agents_draft.yaml"
    keys_dir = tmp_path / "keys"
    public_keys_file = tmp_path / "public_keys.yaml"

    create_test_manifest(manifest)

    public_keys = bootstrap_agent_keys(
        manifest,
        keys_dir,
        public_keys_file,
    )

    assert len(public_keys) == 3

    assert (keys_dir / "aml_investigator.key").exists()
    assert (keys_dir / "sar_drafting_agent.key").exists()
    assert (keys_dir / "front_office_router.key").exists()

    assert public_keys_file.exists()


def test_bootstrap_does_not_overwrite_without_force(tmp_path):
    manifest = tmp_path / "agents_draft.yaml"
    keys_dir = tmp_path / "keys"
    public_keys_file = tmp_path / "public_keys.yaml"

    create_test_manifest(manifest)

    bootstrap_agent_keys(
        manifest,
        keys_dir,
        public_keys_file,
    )

    with pytest.raises(FileExistsError):
        bootstrap_agent_keys(
            manifest,
            keys_dir,
            public_keys_file,
        )


def test_bootstrap_allows_force(tmp_path):
    manifest = tmp_path / "agents_draft.yaml"
    keys_dir = tmp_path / "keys"
    public_keys_file = tmp_path / "public_keys.yaml"

    create_test_manifest(manifest)

    bootstrap_agent_keys(
        manifest,
        keys_dir,
        public_keys_file,
    )

    bootstrap_agent_keys(
        manifest,
        keys_dir,
        public_keys_file,
        force=True,
    )

def test_private_key_permissions_are_0600(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX file permissions are not enforced on Windows")

    manifest = tmp_path / "agents_draft.yaml"
    keys_dir = tmp_path / "keys"
    public_keys_file = tmp_path / "public_keys.yaml"

    create_test_manifest(manifest)

    bootstrap_agent_keys(
        manifest,
        keys_dir,
        public_keys_file,
    )

    key_path = keys_dir / "aml_investigator.key"

    permissions = stat.S_IMODE(key_path.stat().st_mode)

    assert permissions == 0o600