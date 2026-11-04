"""Control CLI of the distributed runtime (run with the Backplane venv's Python).

  build                 stage the MAS build input, build the spire / backend / runtime images
  prepare               generate compose, fresh deployment keys, re-signed PSL store, SPIRE entries,
                        agent registry, service map, golden data
  start                 SPIRE, agent-credential issuer, bank backend, gateway, 13 agent workloads,
                        ingress client  [--svid-ttl S] [--agent-cert-ttl S] [--conn-mode reuse|new|new-resume]
  status                running containers + health of gateway and agents
  run SCENARIO [...]    one ingress request burst (read, write, write_direct, workflow, workflow_mismatch,
                        workflow_not_ready, ledger_direct, knowledge, custom); extra args go to the
                        ingress client (--count N, --no-approvals, --user-role R, --entry A --message M, ...)
  verify                business side effects + audit trails (hash chain, PSL audit correlation)
  unit-test             zero_trust_identity unit tests inside the runtime image
  functional-test       end-to-end tests (pytest distributed_runtime/tests/functional)
  admin disable|enable AGENT   agent registry administration (issuer admin socket)
  stop [--purge]        stop the project's containers (purge also removes its volumes)
Only the compose project `citi_p3_ztbp` is ever touched.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")

from scripts import stack  # noqa: E402


def status() -> None:
    names = stack.running_containers()
    print(json.dumps({"running": names}, indent=1))
    for n in names:
        short = n.removeprefix(stack.P)
        if short == "zt-gateway" or short.startswith("wl-"):
            try:
                h = stack.http_local(short, "/health")
                keep = {k: h.get(k) for k in ("status", "agent_id", "spiffe_id", "policy_version", "gateway_rules")}
                if h.get("svid"):
                    keep["svid"] = h["svid"]["spiffe_id"]
                if h.get("agent_credential"):
                    keep["agent_cert_serial"] = h["agent_credential"]["serial"]
                print(short, json.dumps(keep))
            except Exception as exc:
                print(short, "health error:", str(exc)[-200:])


def unit_test() -> int:
    code = stack.run(["docker", "run", "--rm", "--network", "none", "-u", "65534:65534", "-e", "HOME=/tmp",
                      "-w", "/opt/citi/Citi_P3_Zero_Trust_Backplane/zero_trust_identity", stack.IMAGES["runtime"],
                      "python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"], check=False, capture=False)
    return code.returncode


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--no-stage", action="store_true")
    sub.add_parser("prepare")
    s = sub.add_parser("start")
    s.add_argument("--svid-ttl", type=int, default=0)
    s.add_argument("--agent-cert-ttl", type=int, default=86400)
    s.add_argument("--conn-mode", default="reuse", choices=["reuse", "new", "new-resume"])
    sub.add_parser("status")
    r = sub.add_parser("run")
    r.add_argument("scenario")
    r.add_argument("rest", nargs=argparse.REMAINDER)
    sub.add_parser("verify")
    sub.add_parser("unit-test")
    f = sub.add_parser("functional-test")
    f.add_argument("pytest_args", nargs=argparse.REMAINDER)
    a = sub.add_parser("admin")
    a.add_argument("action", choices=["disable", "enable"])
    a.add_argument("agent_id")
    st = sub.add_parser("stop")
    st.add_argument("--purge", action="store_true")
    ns, extra = ap.parse_known_args()
    if extra and ns.cmd not in ("run", "functional-test"):
        ap.error(f"unrecognized arguments: {' '.join(extra)}")
    if ns.cmd == "build":
        print(json.dumps(stack.build(stage=not ns.no_stage), indent=1))
    elif ns.cmd == "prepare":
        print(json.dumps(stack.prepare(), indent=1))
    elif ns.cmd == "start":
        info = stack.start(svid_ttl=ns.svid_ttl, agent_cert_ttl=ns.agent_cert_ttl, conn_mode=ns.conn_mode)
        print(json.dumps({k: v for k, v in info.items() if k not in ("agent_health",)}, indent=1, default=str))
    elif ns.cmd == "status":
        status()
    elif ns.cmd == "run":
        print(json.dumps(stack.ingress("--scenario", ns.scenario, *ns.rest, *extra), indent=1))
    elif ns.cmd == "verify":
        print(json.dumps(stack.verify_state(), indent=1))
    elif ns.cmd == "unit-test":
        return unit_test()
    elif ns.cmd == "functional-test":
        return subprocess.call([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q",
                                str(ROOT / "tests" / "functional"), *ns.pytest_args, *extra], cwd=ROOT)
    elif ns.cmd == "admin":
        print(json.dumps(stack.issuer_admin(ns.action, ns.agent_id), indent=1))
    elif ns.cmd == "stop":
        stack.stop_all(purge=ns.purge)
    return 0


if __name__ == "__main__":
    sys.exit(main())
