import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path


MODULE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = MODULE_ROOT.parent
SRC_DIR = MODULE_ROOT / "src"

def get_default_manifest_path() -> Path:
    candidates = [
        REPO_ROOT
        / "zero_trust_task2"
        / "draft_manifests"
        / "agents_draft.yaml",

        REPO_ROOT
        / "zero_trust_task2"
        / "output"
        / "draft_manifests"
        / "agents_draft.yaml",
    ]

    for path in candidates:
        if path.exists():
            return path

    return candidates[0]


sys.path.insert(0, str(SRC_DIR))

from zt_task6.keygen import bootstrap_agent_keys, load_agent_identities
from zt_task6.registry import RegistryError, validate_bootstrap_registry, write_signed_registry


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate Ed25519 keypairs for discovered agents."
    )

    parser.add_argument(
        "--manifest",
        type=Path,
        default=get_default_manifest_path(),
    )

    parser.add_argument(
        "--keys-dir",
        type=Path,
        default=MODULE_ROOT / "keys",
    )

    parser.add_argument(
        "--public-keys",
        type=Path,
        default=MODULE_ROOT / "public_keys.yaml",
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing private keys.",
    )

    parser.add_argument("--registry", type=Path, help="Publish a root-signed authentication registry.")
    parser.add_argument("--registry-root-private-key", type=Path, help="Externally provisioned PEM Ed25519 root.")
    parser.add_argument("--registry-root-key-id", help="Pinned registry root identifier.")
    args = parser.parse_args(argv)
    signing_options = (args.registry, args.registry_root_private_key, args.registry_root_key_id)
    if any(value is not None for value in signing_options) and not all(
        value is not None for value in signing_options
    ):
        parser.error("--registry, --registry-root-private-key and --registry-root-key-id are required together")

    if args.registry is not None:
        try:
            identities = load_agent_identities(args.manifest)
            if len(set(identities)) != len(identities):
                raise RegistryError("Duplicate bootstrap identities")
            # Signed mode must not allow an identity to escape the private-key directory.
            key_paths = []
            for identity in identities:
                if identity in (".", "..") or any(char in identity for char in '/\\:'):
                    raise RegistryError("Unsafe bootstrap identity")
                key_path = (args.keys_dir / f"{identity}.key").resolve()
                if key_path.parent != args.keys_dir.resolve():
                    raise RegistryError("Unsafe bootstrap key path")
                key_paths.append(key_path)
            outputs = [args.registry.resolve(), args.public_keys.resolve(), *key_paths]
            protected = {args.manifest.resolve(), args.registry_root_private_key.resolve()}
            if len(set(outputs)) != len(outputs) or any(path in protected for path in outputs):
                raise RegistryError("Bootstrap output paths overlap protected inputs or each other")
            validate_bootstrap_registry(
                args.registry, root_private_key_path=args.registry_root_private_key,
                root_key_id=args.registry_root_key_id, agent_identities=identities,
            )
        except (RegistryError, OSError, ValueError) as exc:
            parser.exit(1, f"Signed registry preflight failed: {exc}\n")

    public_keys = bootstrap_agent_keys(
        manifest_path=args.manifest,
        keys_dir=args.keys_dir,
        public_keys_path=args.public_keys,
        force=args.force,
    )

    if args.registry is not None:
        try:
            write_signed_registry(
                public_keys, args.registry,
                root_private_key_path=args.registry_root_private_key,
                root_key_id=args.registry_root_key_id, valid_from=datetime.now(timezone.utc),
            )
        except (RegistryError, OSError) as exc:
            parser.exit(1, f"Signed registry publication failed; generated keys are not registered: {exc}\n")
        print(f"Signed registry: {args.registry}")

    print(f"Generated keys for {len(public_keys)} agents.")
    print(f"Private keys: {args.keys_dir}")
    print(f"Public keys: {args.public_keys}")


if __name__ == "__main__":
    main()
