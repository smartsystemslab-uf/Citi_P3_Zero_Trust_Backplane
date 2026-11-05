"""Stage a protected ADK application for its runtime image (host side, ``zt-distributed build``).

The image receives the application's files (``distributed.app_paths``, minus ``distributed.exclude``)
and a staged copy of ``zt_adk.yaml`` under ``/opt/app``. The profile may live apart from the
application (a separate configuration repository, paths given as ``${VAR}`` or absolute): an
``app_paths`` entry inside the profile's directory keeps its relative location, an entry outside it
keeps its name under ``_ext/<k>/``, one ``_ext/<k>`` per directory that contains such entries (so a
python path naming that directory still finds the packages). Every path of the staged profile that the image uses
(python_paths, policy overlays, the model override script, requirement files) is rewritten to its
staged location; a path that points to something not staged is an error, so the image never starts
with a profile that refers to files it does not contain.
"""
from __future__ import annotations

import fnmatch
import shutil
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

EXT_DIR = "_ext"
HOST_ONLY = ("secret_env_files", "tool_host_secret_env_files")   # read by compose on the host, never staged


class StagingError(ValueError):
    pass


def _skip(rel: str, excludes: list[str]) -> bool:
    parts = rel.split("/")
    return any(fnmatch.fnmatch(rel, pat) or any(fnmatch.fnmatch(p, pat) for p in parts) for pat in excludes)


def stage_application(prof: Any, profile_path: Path, dest: Path) -> dict[str, Any]:
    """Copy the application into ``dest`` and write the staged profile ``dest/<profile file name>``.
    Returns the staged profile (as written)."""
    profile_path = Path(profile_path).resolve()
    base = Path(prof.base_dir).resolve()
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    excludes = list(prof.distributed.exclude)
    roots: list[tuple[Path, PurePosixPath]] = []
    ext_parents: dict[Path, PurePosixPath] = {}     # outside directory -> _ext/<k> (entries keep their names)
    for item in prof.distributed.app_paths:
        src = prof.path(item)
        if not src.exists():
            raise FileNotFoundError(f"distributed.app_paths entry not found: {item!r} ({src})")
        if src == base or base in src.parents:
            staged, anchor = PurePosixPath(src.relative_to(base).as_posix()), base
        else:
            parent = ext_parents.setdefault(src.parent, PurePosixPath(EXT_DIR, str(len(ext_parents))))
            staged, anchor = parent / src.name, src.parent
        roots.append((src, staged))
        if src.is_file():
            files = [(src, dest / staged)]
        else:
            files = [(p, dest / staged / p.relative_to(src)) for p in sorted(src.rglob("*")) if p.is_file()]
        for path, target in files:
            if _skip(path.relative_to(anchor).as_posix(), excludes):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
    by_depth = sorted(roots, key=lambda r: len(r[0].parts), reverse=True)

    def staged_path(value: str, what: str) -> str:
        p = prof.path(value)
        for src, staged in by_depth:
            if p == src or src in p.parents:
                return (staged / p.relative_to(src).as_posix()).as_posix()
        if p in ext_parents:                 # e.g. python_paths: the directory that contains staged packages
            return ext_parents[p].as_posix()
        if p == base:
            return "."
        raise StagingError(f"{what} {value!r} ({p}) is not part of the staged application: "
                           "add it (or a directory containing it) to distributed.app_paths")

    doc = prof.model_dump(mode="json")
    doc["python_paths"] = [staged_path(v, "python_paths entry") for v in prof.python_paths]
    try:
        doc["source_root"] = staged_path(prof.source_root, "source_root")
    except StagingError:
        doc["source_root"] = "."          # only the host build runs the static cross-check
    doc["policies"]["overlays"] = [staged_path(v, "policies.overlays pattern") for v in prof.policies.overlays]
    if prof.model_override is not None:
        doc["model_override"]["script"] = staged_path(prof.model_override.script, "model_override.script")
    dist = doc["distributed"]
    dist["requirements"] = [staged_path(v, "distributed.requirements entry") for v in prof.distributed.requirements]
    dist["app_paths"] = [staged.as_posix() for _src, staged in roots]
    for key in HOST_ONLY:
        dist[key] = []
    target = dest / profile_path.name
    target.write_text("# Staged by zt_distributed.staging from " + profile_path.name + " (paths rewritten to the "
                      "image's /opt/app). Do not edit.\n" + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True),
                      encoding="utf-8")
    return doc
