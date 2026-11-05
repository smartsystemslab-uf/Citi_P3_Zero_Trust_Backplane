"""zt-adk: protect a Google ADK multi-agent system with the Zero Trust Backplane.

    zt-adk init --app my_pkg.agent:root_agent      write zt_adk.yaml
    zt-adk keys init [--approver NAME] [--secondary NAME]
    zt-adk build                                   discover, generate and sign the protection bundle
    zt-adk check                                   verify the bundle against the running code
    zt-adk inspect [--json]                        agents, operations, routes, policy rules
    zt-adk run "message" [...]                     run messages through the protected application
    zt-adk approvals list|show|approve|deny        human approval of held critical operations
    zt-adk audit verify                            verify the hash chain of the audit log
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from importlib import resources
from pathlib import Path
from typing import Any

from .profile import Profile, load_profile


def _profile(ns: argparse.Namespace) -> Profile:
    path = Path(ns.profile)
    if not path.exists():
        raise SystemExit(f"profile not found: {path} (run 'zt-adk init' first)")
    return load_profile(path)


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True, default=str))


# ---------------------------------------------------------------------------- init / keys
def cmd_init(ns: argparse.Namespace) -> int:
    target = Path(ns.dir) / "zt_adk.yaml"
    if target.exists() and not ns.force:
        raise SystemExit(f"{target} exists (use --force to overwrite)")
    text = resources.files("zt_adk").joinpath("resources/zt_adk.template.yaml").read_text("utf-8")
    target.write_text(text.format(app=ns.app), encoding="utf-8")
    gi = Path(ns.dir) / ".gitignore"
    lines = gi.read_text(encoding="utf-8").splitlines() if gi.exists() else []
    if ".zt/" not in lines:
        gi.write_text("\n".join(lines + [".zt/"]) + "\n", encoding="utf-8")
    print(f"wrote {target}; .zt/ added to {gi}")
    return 0


def cmd_keys(ns: argparse.Namespace) -> int:
    from .keys import add_approver, describe, init_keys

    prof = _profile(ns)
    keys_dir, appr_dir = prof.path(prof.keys_dir), prof.path(prof.approver_keys_dir)
    if ns.keys_cmd == "init":
        approvers = ns.approver or ["approver"]
        secondaries = ns.secondary or (["secondary"] if prof.approvals.critical == "dual" else [])
        _print(init_keys(keys_dir, appr_dir, approvers=approvers, secondaries=secondaries,
                         max_assertion_lifetime=prof.approvals.lifetime_seconds, overwrite=ns.force))
    elif ns.keys_cmd == "add-approver":
        a = add_approver(keys_dir, appr_dir, ns.name, secondary=ns.secondary,
                         max_assertion_lifetime=prof.approvals.lifetime_seconds)
        print(f"added {a.issuer} ({a.purpose}); private key: {a.private_key_file}")
        print("rebuild the bundle (zt-adk build) so the separation-of-duty rules include the new approver")
    else:
        _print(describe(keys_dir, appr_dir))
    return 0


# ---------------------------------------------------------------------------- build / check / inspect
def cmd_build(ns: argparse.Namespace) -> int:
    from .build import build

    prof = _profile(ns)
    r = build(prof, skip_static=ns.no_static)
    print(f"bundle: {r.bundle_dir}")
    print(f"app {r.model.app_name}: {len(r.model.agents)} agents, {len(r.model.tools)} tools, "
          f"{len(r.model.edges)} edges")
    print(f"PEP placements: {r.logical_peps} logical / {r.physical_peps} physical; PSL rules: {r.rules}; "
          f"policy version {r.policy_version}")
    for w in r.warnings:
        print(f"warning: {w}")
    print(f"report: {r.bundle_dir / 'REPORT.md'}")
    return 0


def cmd_check(ns: argparse.Namespace) -> int:
    from .bundle import verify_bundle
    from .discovery import discover, load_object, resolve_app
    from .keys import POLICY_ISSUER

    prof = _profile(ns)
    keys_dir = prof.path(prof.keys_dir)
    index = verify_bundle(prof.path(prof.bundle_dir), keys_dir / "signing" / "policy_public.pem",
                          expected_issuer=POLICY_ISSUER[0])
    root, _name, _plugins = resolve_app(load_object(prof.app, [prof.path(p) for p in prof.python_paths]))
    live, _a, _t = discover(root, resolve_toolsets=False)
    ok = live.fingerprint() == index["fingerprint"]
    from zt_backplane.crypto import TrustedKeyStore
    from zt_backplane.psl_policy import PslPolicyStore

    store = PslPolicyStore.load(prof.path(prof.bundle_dir) / "policy_store",
                                keys=TrustedKeyStore(keys_dir / "trusted_issuers.yaml"))
    _print({"bundle_signature": "valid", "files": len(index["files"]), "policy_version": store.version,
            "fingerprint_matches_running_code": ok, "bundle_fingerprint": index["fingerprint"],
            "live_fingerprint": live.fingerprint()})
    if not ok:
        print("the application changed since the bundle was built: run 'zt-adk build'", file=sys.stderr)
        return 1
    return 0


def cmd_inspect(ns: argparse.Namespace) -> int:
    prof = _profile(ns)
    b = prof.path(prof.bundle_dir)
    model = json.loads((b / "system_model.json").read_text("utf-8"))
    ids = json.loads((b / "bindings.json").read_text("utf-8"))
    index = json.loads((b / "bundle.json").read_text("utf-8"))
    if ns.json:
        _print({"index": {k: v for k, v in index.items() if k != "files"}, "operations": ids["operations"],
                "domains": ids["domains"], "edges": model["edges"]})
        return 0
    print((b / "REPORT.md").read_text("utf-8"))
    return 0


# ---------------------------------------------------------------------------- run
def cmd_run(ns: argparse.Namespace) -> int:
    from google.adk.sessions import InMemorySessionService
    from google.genai import types

    from .discovery import load_object, resolve_app
    from .plugin import ZeroTrustPlugin, protected_runner

    prof = _profile(ns)
    app_obj = load_object(prof.app, [prof.path(p) for p in prof.python_paths])
    root, name, _plugins = resolve_app(app_obj)
    script = ns.playback or (prof.model_override.script if prof.model_override else None)
    if script:
        from .testing.playback import install_playback

        install_playback(root, prof.path(script))
        print(f"[zt-adk] model replaced by the playback script {script} (test/demo mode)")
    plugin = ZeroTrustPlugin.from_profile(prof, root_agent=root)
    app_name = prof.app_name or name or root.name
    sessions = InMemorySessionService()
    # the application's own plugins and App configuration stay; the PEP runs first
    runner = protected_runner(app_obj, plugin, root_agent=root, app_name=app_name, session_service=sessions)

    async def go() -> None:
        session = await sessions.create_session(app_name=app_name, user_id=ns.user)
        plugin.register_session(session.id, user_role=ns.role)
        for message in ns.message:
            print(f"\n>>> {message}")
            async for ev in runner.run_async(user_id=ns.user, session_id=session.id,
                                             new_message=types.Content(role="user", parts=[types.Part(text=message)])):
                for p in (ev.content.parts if ev.content else []):
                    if p.text:
                        print(f"[{ev.author}] {p.text}")
                    if p.function_call:
                        print(f"[{ev.author}] call {p.function_call.name} {json.dumps(p.function_call.args, default=str)}")
                    if p.function_response and ns.verbose:
                        print(f"[{ev.author}] result {p.function_response.name} "
                              f"{json.dumps(p.function_response.response, default=str)[:400]}")
        await plugin.close()

    asyncio.run(go())
    print(f"\n[zt-adk] audit log: {prof.path(prof.state_dir) / 'audit.jsonl'}")
    return 0


# ---------------------------------------------------------------------------- approvals / audit
def cmd_approvals(ns: argparse.Namespace) -> int:
    from zt_backplane.evidence_issuer import IssuerKey

    from .approvals import ApprovalStore, operation_hash
    from .keys import approver_issuer, load_private

    prof = _profile(ns)
    store = ApprovalStore(prof.path(prof.state_dir) / "approvals")
    if ns.ap_cmd == "list":
        rows = store.list(None if ns.all else "pending")
        for r in rows:
            rec = r.record
            print(f"{r.approval_id}  {rec['status']:<9} {rec['created_at']}  {rec['agent']}/{rec['tool']}  "
                  f"needs {','.join(rec['purposes'])}")
        if not rows:
            print("no approval requests" + ("" if ns.all else " pending"))
        return 0
    req = store.get(ns.id)
    if ns.ap_cmd == "show":
        rec = dict(req.record)
        rec["hash_check"] = "ok" if operation_hash(rec["operation"]) == rec["request_hash"] else "MISMATCH"
        rec["decisions"] = store.decisions_for(ns.id)
        _print(rec)
        return 0
    approve = ns.ap_cmd == "approve"
    secondary = bool(ns.secondary)
    purpose = "secondary_authorization" if secondary else "human_approval"
    key_file = Path(ns.key) if ns.key else prof.path(prof.approver_keys_dir) / \
        f"{'secondary' if secondary else 'approver'}_{ns.approver}_private.pem"
    if not key_file.exists():
        raise SystemExit(f"approver key not found: {key_file}")
    key = IssuerKey(approver_issuer(ns.approver, secondary), "key-1", load_private(key_file))
    signed = store.decide(ns.id, key=key, purpose=purpose, approve=approve, approver=ns.approver,
                          lifetime_seconds=prof.approvals.lifetime_seconds, comment=ns.comment or "")
    print(f"{'approved' if approve else 'denied'} {ns.id} as {key.issuer} ({purpose}); "
          f"valid until {signed['expires_at']}")
    return 0


def cmd_audit(ns: argparse.Namespace) -> int:
    from .audit import verify_chain

    prof = _profile(ns)
    result = verify_chain(prof.path(prof.state_dir) / "audit.jsonl")
    _print(result)
    return 0 if result["ok"] else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="zt-adk", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", default=os.environ.get("ZT_ADK_PROFILE", "zt_adk.yaml"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init")
    p.add_argument("--app", required=True, help="module:attribute of the ADK App / root agent")
    p.add_argument("--dir", default=".")
    p.add_argument("--force", action="store_true")
    k = sub.add_parser("keys")
    ks = k.add_subparsers(dest="keys_cmd", required=True)
    ki = ks.add_parser("init")
    ki.add_argument("--approver", action="append")
    ki.add_argument("--secondary", action="append")
    ki.add_argument("--force", action="store_true")
    ka = ks.add_parser("add-approver")
    ka.add_argument("name")
    ka.add_argument("--secondary", action="store_true")
    ks.add_parser("show")
    b = sub.add_parser("build")
    b.add_argument("--no-static", action="store_true", help="skip the static cross-check scan")
    sub.add_parser("check")
    i = sub.add_parser("inspect")
    i.add_argument("--json", action="store_true")
    r = sub.add_parser("run")
    r.add_argument("message", nargs="+")
    r.add_argument("--role", default="", help="end-user role the front end asserts")
    r.add_argument("--user", default="cli-user")
    r.add_argument("--playback", help="replace the model by a playback script (tests/demos)")
    r.add_argument("--verbose", action="store_true")
    a = sub.add_parser("approvals")
    asub = a.add_subparsers(dest="ap_cmd", required=True)
    al = asub.add_parser("list")
    al.add_argument("--all", action="store_true")
    for name in ("show", "approve", "deny"):
        x = asub.add_parser(name)
        x.add_argument("id")
        if name != "show":
            x.add_argument("--approver", required=True)
            x.add_argument("--secondary", action="store_true", help="sign as the secondary authorizer")
            x.add_argument("--key", help="approver private key file (default: approver_keys_dir)")
            x.add_argument("--comment")
    au = sub.add_parser("audit")
    au.add_argument("action", choices=["verify"])
    ns = ap.parse_args(argv)
    handler = {"init": cmd_init, "keys": cmd_keys, "build": cmd_build, "check": cmd_check, "inspect": cmd_inspect,
               "run": cmd_run, "approvals": cmd_approvals, "audit": cmd_audit}[ns.cmd]
    try:
        return handler(ns)
    except _expected_errors() as exc:
        if os.environ.get("ZT_ADK_DEBUG"):
            raise
        print(f"zt-adk {ns.cmd}: error: {exc}\n(set ZT_ADK_DEBUG=1 for the traceback)", file=sys.stderr)
        return 2


def _expected_errors() -> tuple[type[BaseException], ...]:
    """What a user's input can cause (profile, application, keys, bundle, approvals): reported as
    one message, not a traceback."""
    import yaml

    from .approvals import ApprovalError
    from .build import BuildError
    from .bundle import BundleError
    from .discovery import DiscoveryError
    from .engine import EngineError
    from .keys import KeyError_
    from .plugin import StaleBundleError

    return (ApprovalError, BuildError, BundleError, DiscoveryError, EngineError, KeyError_, StaleBundleError,
            ValueError, yaml.YAMLError, FileNotFoundError, ImportError)


if __name__ == "__main__":
    sys.exit(main())
