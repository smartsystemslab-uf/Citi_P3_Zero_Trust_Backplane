"""Control CLI of the distributed runtime for any ADK application (run with the Backplane venv's Python).

  build --project DIR     stage the application (DIR/zt_adk.yaml), build the SPIRE and runtime images,
                          describe the agent tree inside the image (runtime/deployment.json), compose file
  prepare                 fresh deployment keys + approver keys, the signed protection bundle built inside
                          the image, SPIRE entries, agent CA + registry, service map; distributed.setup_command
  start                   SPIRE, agent-credential issuer, the application's services, gateway, one workload
                          per agent, ingress client  [--svid-ttl S] [--agent-cert-ttl S] [--conn-mode M]
  status                  running containers + health of gateway and agent workloads
  run -m MSG [-m MSG ...] one conversation through the ingress [--role R] [--session-id S] [--repeat N]
  approvals list|show ID|approve ID|deny ID --approver NAME [--secondary]
  admin disable|enable AGENT   agent registry administration (issuer admin socket)
  verify                  audit hash chains, PDP decision log, PSL audit correlation
  stats                   gateway counters (identities, revocations, PSL monitors)
  logs CONTAINER          last log lines of a container (e.g. zt-gateway, wl-account-agent)
  stop [--purge]          stop the project's containers (purge also removes its volumes)
Only the compose project named in the application's profile is ever touched.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")

from scripts import stack  # noqa: E402


def _print(obj: object) -> None:
    print(json.dumps(obj, indent=1, default=str))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--project", type=Path, help="directory of the application's zt_adk.yaml (remembered)")
    sub.add_parser("prepare")
    s = sub.add_parser("start")
    s.add_argument("--svid-ttl", type=int, default=0)
    s.add_argument("--agent-cert-ttl", type=int, default=86400)
    s.add_argument("--conn-mode", default="reuse", choices=["reuse", "new", "new-resume"])
    sub.add_parser("status")
    r = sub.add_parser("run")
    r.add_argument("-m", "--message", action="append", required=True)
    r.add_argument("--role", default="")
    r.add_argument("--session-id")
    r.add_argument("--repeat", type=int, default=1)
    a = sub.add_parser("approvals")
    a.add_argument("action", choices=["list", "show", "approve", "deny", "wait"])
    a.add_argument("id", nargs="?")
    a.add_argument("--approver")
    a.add_argument("--secondary", action="store_true")
    a.add_argument("--comment", default="")
    ad = sub.add_parser("admin")
    ad.add_argument("action", choices=["disable", "enable"])
    ad.add_argument("agent_id")
    sub.add_parser("verify")
    sub.add_parser("stats")
    lg = sub.add_parser("logs")
    lg.add_argument("container")
    lg.add_argument("--tail", type=int, default=80)
    st = sub.add_parser("stop")
    st.add_argument("--purge", action="store_true")
    ns = ap.parse_args()

    if ns.cmd == "build":
        _print(stack.build(ns.project))
    elif ns.cmd == "prepare":
        _print(stack.prepare())
    elif ns.cmd == "start":
        stack.reset_state()
        _print(stack.start(svid_ttl=ns.svid_ttl, agent_cert_ttl=ns.agent_cert_ttl, conn_mode=ns.conn_mode))
    elif ns.cmd == "status":
        _print(stack.status())
    elif ns.cmd == "run":
        args: list[str] = []
        for m in ns.message:
            args += ["--message", m]
        if ns.role:
            args += ["--role", ns.role]
        if ns.session_id:
            args += ["--session-id", ns.session_id]
        args += ["--repeat", str(ns.repeat)]
        _print(stack.ingress(*args))
    elif ns.cmd == "approvals":
        store = stack.approvals_store()
        if ns.action == "list":
            _print([{"approval_id": r.approval_id, "status": r.status, "agent": r.record["agent"],
                     "tool": r.record["tool"], "purposes": r.record["purposes"]} for r in store.list()])
        elif ns.action == "wait":
            req = stack.wait_for_approval()
            _print(req.record if req else {"status": "no pending approval"})
        elif ns.action == "show":
            _print(store.get(ns.id).record | {"decisions": store.decisions_for(ns.id)})
        else:
            if not ns.id or not ns.approver:
                ap.error("approve/deny need ID and --approver")
            from zt_adk.approvals import ApprovalError  # noqa: F401
            prof = stack.profile()
            key = stack.approver_key(ns.approver, ns.secondary)
            signed = store.decide(ns.id, key=key, purpose="secondary_authorization" if ns.secondary else "human_approval",
                                  approve=ns.action == "approve", approver=ns.approver,
                                  lifetime_seconds=prof.approvals.lifetime_seconds, comment=ns.comment)
            _print({"decision": signed["decision"], "issuer": signed["issuer"], "expires_at": signed["expires_at"]})
    elif ns.cmd == "admin":
        _print(stack.issuer_admin(ns.action, ns.agent_id))
    elif ns.cmd == "verify":
        result = stack.verify()
        _print(result)
        return 0 if result.get("ok") else 1
    elif ns.cmd == "stats":
        _print(stack.gateway_stats())
    elif ns.cmd == "logs":
        print(stack.logs(ns.container, ns.tail))
    elif ns.cmd == "stop":
        stack.stop_all(purge=ns.purge)
    return 0


if __name__ == "__main__":
    sys.exit(main())
