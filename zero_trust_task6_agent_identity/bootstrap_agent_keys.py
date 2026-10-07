import argparse
import sys
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

from zt_task6.keygen import bootstrap_agent_keys


def main():
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

    args = parser.parse_args()

    public_keys = bootstrap_agent_keys(
        manifest_path=args.manifest,
        keys_dir=args.keys_dir,
        public_keys_path=args.public_keys,
        force=args.force,
    )

    print(f"Generated keys for {len(public_keys)} agents.")
    print(f"Private keys: {args.keys_dir}")
    print(f"Public keys: {args.public_keys}")


if __name__ == "__main__":
    main()