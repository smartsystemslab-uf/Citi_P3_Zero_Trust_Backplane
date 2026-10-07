import base64
from pathlib import Path

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def load_agent_identities(manifest_path: Path) -> list[str]:
    with manifest_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if not isinstance(data, dict):
        raise ValueError("Agent manifest must contain a YAML mapping")

    agents = data.get("agents")

    if not isinstance(agents, list) or not agents:
        raise ValueError("Agent manifest contains no agents")

    agent_ids = []

    for agent in agents:
        if not isinstance(agent, dict):
            raise ValueError("Invalid agent entry in manifest")

        agent_id = agent.get("agent_id")

        if not isinstance(agent_id, str) or not agent_id.strip():
            raise ValueError("Agent entry is missing a valid agent_id")

        agent_ids.append(agent_id.strip())

    return agent_ids

def generate_keypair() -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    private_b64 = base64.b64encode(private_bytes).decode("ascii")
    public_b64 = base64.b64encode(public_bytes).decode("ascii")

    return private_b64, public_b64

def write_private_key(
    agent_id: str,
    private_key_b64: str,
    keys_dir: Path,
    force: bool = False,
) -> Path:
    keys_dir.mkdir(parents=True, exist_ok=True)

    key_path = keys_dir / f"{agent_id}.key"

    if key_path.exists() and not force:
        raise FileExistsError(
            f"Private key already exists for {agent_id}: {key_path}"
        )

    key_path.write_text(private_key_b64, encoding="utf-8")

    key_path.chmod(0o600)

    return key_path

def bootstrap_agent_keys(
    manifest_path: Path,
    keys_dir: Path,
    public_keys_path: Path,
    force: bool = False,
) -> dict[str, str]:
    agent_ids = load_agent_identities(manifest_path)

    if not agent_ids:
        raise ValueError("No agent identities found")

    existing_keys = [
        keys_dir / f"{agent_id}.key"
        for agent_id in agent_ids
        if (keys_dir / f"{agent_id}.key").exists()
    ]

    if existing_keys and not force:
        raise FileExistsError(
            "Private keys already exist. Use --force to overwrite them."
        )

    public_keys = {}

    for agent_id in agent_ids:
        private_key_b64, public_key_b64 = generate_keypair()

        write_private_key(
            agent_id,
            private_key_b64,
            keys_dir,
            force=force,
        )

        public_keys[agent_id] = public_key_b64

    public_keys_path.parent.mkdir(parents=True, exist_ok=True)

    with public_keys_path.open("w", encoding="utf-8") as file:
        yaml.safe_dump(
            {"public_keys": public_keys},
            file,
            sort_keys=True,
        )

    return public_keys