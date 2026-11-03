"""Stage a read-only build input copy of the MAS repository (D:\\Lab\\Citi_P3).

The repository tracks a .env and a .venv, so it is not used as a Docker build context
directly. This walks it read-only and byte-copies the source tree into
runtime/build/Citi_P3 (git-ignored), skipping secrets, virtual environments, caches,
databases and run outputs -- the same rules as the MCP/PSL experiments' snapshots. The
source repository is never modified. A provenance file records the git HEAD, whether the
working tree was dirty, and the SHA-256 of every staged file.

    python scripts/stage_mas.py [--src D:\\Lab\\Citi_P3]
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "runtime" / "build" / "Citi_P3"
EXCLUDED_DIRS = {".git", ".ipynb_checkpoints", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".venv",
                 "__pycache__", "mlruns", "node_modules", "venv"}
EXCLUDE = ["*.DS_Store", "*.coverage", "*/.coverage", "*.env", ".env", "*/.env", "*.db", "*.sqlite", "*.pyc",
           "*.egg-info/*", "citi_banking_adk/observability_runs/*", "native_zero_trust_e2e_report.json",
           "native_zero_trust_latency_report.json", "*/.runtime/*", "*/data/citi_banking.db"]


def _git(src: Path, *args: str) -> str:
    try:
        return subprocess.run(["git", "--no-optional-locks", "-C", str(src), *args], capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def stage(src: Path, dest: Path = DEST) -> dict:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    files = []
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS and not d.endswith(".egg-info"))
        for name in sorted(filenames):
            p = Path(dirpath) / name
            rel = p.relative_to(src).as_posix()
            if any(fnmatch.fnmatch(rel, pat) for pat in EXCLUDE) or p.is_symlink():
                continue
            out = dest / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, out)
            files.append({"path": rel, "sha256": hashlib.sha256(out.read_bytes()).hexdigest()})
    status = _git(src, "status", "--porcelain")
    prov = {"staged_at": datetime.now(timezone.utc).isoformat(), "source": str(src),
            "method": "read-only walk + byte copy; source never modified",
            "git_head": _git(src, "rev-parse", "HEAD") or None,
            "git_dirty_paths": status.splitlines() if status else [],
            "excluded_dirs": sorted(EXCLUDED_DIRS), "exclude_patterns": EXCLUDE,
            "files": len(files),
            "tree_sha256": hashlib.sha256("\n".join(f"{f['path']} {f['sha256']}" for f in files).encode()).hexdigest()}
    (dest.parent / "Citi_P3.provenance.json").write_text(json.dumps({**prov, "file_hashes": files}, indent=1),
                                                         encoding="utf-8")
    return prov


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=os.environ.get("CITI_MAS_SRC", r"D:\Lab\Citi_P3"))
    ns = ap.parse_args()
    prov = stage(Path(ns.src))
    print(json.dumps({k: v for k, v in prov.items() if k != "git_dirty_paths"} |
                     {"git_dirty": len(prov["git_dirty_paths"])}, indent=1))


if __name__ == "__main__":
    main()
