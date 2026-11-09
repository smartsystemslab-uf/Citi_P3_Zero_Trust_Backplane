"""zt-console: a browser UI for running and testing the Zero Trust Backplane.

    zt-console --profile examples/helpdesk_mas/zt_adk.playback.yaml
    zt-console --profiles-dir examples          # pick the application in the browser
    zt-console                                  # looks for zt_adk*.yaml below the current directory

It is a thin surface over the real command line (zt-adk) and binds to 127.0.0.1 only.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import Config, ProfileError, discover_profiles


def main() -> int:
    ap = argparse.ArgumentParser(prog="zt-console", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", action="append", default=[], help="zt_adk.yaml of an application (repeatable)")
    ap.add_argument("--profiles-dir", action="append", default=[], help="folder searched for zt_adk*.yaml")
    ap.add_argument("--host", default="127.0.0.1", help="interface to listen on (default: loopback only)")
    ap.add_argument("--port", type=int, default=8766)
    ap.add_argument("--data-dir", default=".zt-console", help="where saved tests and run history are kept")
    ap.add_argument("--zt-adk", help="path of the zt-adk command used to run messages")
    ap.add_argument("--dev-approve", action="store_true",
                    help="DEVELOPMENT ONLY: allow approving from the console with local approver keys")
    ns = ap.parse_args()

    import uvicorn

    from .app import create_app

    paths = [Path(p).resolve() for p in ns.profile]
    for d in ns.profiles_dir:
        paths += discover_profiles(Path(d))
    if not paths:
        paths = discover_profiles(Path.cwd())
    seen: set[Path] = set()
    paths = [p for p in paths if not (p in seen or seen.add(p))]
    overrides = {"data_dir": Path(ns.data_dir), "dev_approve": ns.dev_approve,
                 "zt_adk": [ns.zt_adk] if ns.zt_adk else None}
    try:
        cfgs = [Config.from_profile(p, **overrides) for p in paths] or [
            Config(**{k: v for k, v in overrides.items() if v is not None})]
    except ProfileError as exc:
        print(f"zt-console: {exc}", file=sys.stderr)
        return 2
    if ns.host not in ("127.0.0.1", "localhost", "::1"):
        print("warning: the console has no user authentication; listening on", ns.host, "exposes it to that network")
        for c in cfgs:
            c.allowed_hosts = tuple(c.allowed_hosts) + (ns.host,)
    if ns.dev_approve:
        print("warning: --dev-approve lets anyone who can reach this console approve operations with local keys")
    if not paths:
        print("note: no zt_adk*.yaml profile found; start with --profile PATH or --profiles-dir DIR")
    print(f"zt-console on http://{ns.host}:{ns.port}  ({len(paths)} profile(s) found)")
    uvicorn.run(create_app(cfgs[0], cfgs), host=ns.host, port=ns.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
