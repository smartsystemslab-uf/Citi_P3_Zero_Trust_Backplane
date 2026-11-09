"""Fixtures: a small synthetic bundle and state directory, and a stand-in for the zt-adk command."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from zt_console.app import create_app
from zt_console.config import Config

GENESIS = "0" * 64


def write_chain(path: Path, records: list[dict]) -> None:
    prev, lines = GENESIS, []
    for i, rec in enumerate(records, 1):
        r = {"seq": i, "ts": f"2026-11-09T10:00:{i:02d}+00:00", **rec, "prev": prev}
        canon = json.dumps(r, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False).encode()
        r["hash"] = hashlib.sha256(prev.encode() + canon).hexdigest()
        prev = r["hash"]
        lines.append(json.dumps(r, sort_keys=True, ensure_ascii=False))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


PSL = """// @policy_set demo.access
// @version 1.0.0
vunit access (pdp_request) {
  // @rule access.tool.lookup
  // @nl alice_agent may read the user directory.
  // @permit
  property permit_0 = subject.id == "x";
}
// @policy_set demo.content
// @version 1.0.0
vunit content_input (input_message) {
  // @rule content.input.prompt-injection
  // @nl A user message with prompt-injection patterns is refused before any agent sees it.
  // @on_violation DENY
  input_injection: assert never (input_received && input.prompt_injection_detected);
}
"""

FAKE_ZT_ADK = '''
import json, sys, hashlib, pathlib
args = sys.argv[1:]
if "run" not in args:
    print("fake zt-adk:", " ".join(a for a in args if not a.startswith("/")))
    sys.exit(0)
state = pathlib.Path(__file__).parent / "state"
msg = " ".join(args[args.index("--") + 1:])
if msg.startswith("slow"):                      # a long-running command that has started a child process of its own
    import subprocess, time
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    (state / "child.pid").write_text(str(child.pid))
    time.sleep(60)
lines = [json.loads(l) for l in (state / "audit.jsonl").read_text().splitlines() if l.strip()]
prev, seq = lines[-1]["hash"], lines[-1]["seq"]
def add(rec):
    global prev, seq
    seq += 1
    r = {"seq": seq, "ts": "2026-11-09T11:00:00+00:00", **rec, "prev": prev}
    canon = json.dumps(r, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False).encode()
    r["hash"] = hashlib.sha256(prev.encode() + canon).hexdigest(); prev = r["hash"]
    with (state / "audit.jsonl").open("a") as fh: fh.write(json.dumps(r, sort_keys=True) + "\\n")
role = next((a for a in args if a.startswith("--role")), "")
if msg.startswith("whoami"):
    add({"event": "INPUT_AUTHORIZATION", "allowed": True, "decision": "ALLOW", "caller": "ingress", "target": "service_desk"})
    print("[service_desk] argv:" + repr([a for a in args[:args.index("--")] if a.startswith("--role") or a.startswith("-x")]))
elif "ignore" in msg.lower():
    add({"event": "CONTENT_INPUT", "allowed": False, "decision": "DENY", "reason": "psl_violation:content.input.prompt-injection", "rules": ["content.input.prompt-injection"], "caller": "ingress", "target": "service_desk"})
    print('[model] {"status": "zero_trust_denied", "boundary": "input"}')
else:
    add({"event": "INPUT_AUTHORIZATION", "allowed": True, "decision": "ALLOW", "caller": "ingress", "target": "service_desk", "reason": "VALID_PERMIT_LEASE"})
    print("[service_desk] call transfer_to_agent {}")
    print("[service_desk] Hello from the fake app.")
'''


@pytest.fixture()
def env(tmp_path: Path):
    bundle, state = tmp_path / "bundle", tmp_path / "state"
    (bundle / "policy_store").mkdir(parents=True)
    (state / "approvals" / "requests").mkdir(parents=True)
    (state / "approvals" / "decisions").mkdir(parents=True)
    (bundle / "bundle.json").write_text(json.dumps({
        "app_name": "demo", "fingerprint": "f" * 64, "policy_version": "pv1", "created_at": "2026-11-09T09:00:00+00:00",
        "mode": "enforce", "environment": "test", "logical_peps": 3, "policy_sets": {"a": "1", "b": "1"},
        "adk_version": "2.14.0", "files": {}}))
    (bundle / "runtime_profile.json").write_text(json.dumps({"mode": "enforce", "session": {"roles": ["employee"]},
                                                              "approvals": {"wait_seconds": 5, "lifetime_seconds": 300}}))
    (bundle / "system_model.json").write_text(json.dumps({
        "app_name": "demo", "root_agent": "service_desk", "adk_version": "2.14.0", "warnings": [], "workflows": {},
        "agents": {"service_desk": {"kind": "llm", "description": "root", "parent": None, "sub_agents": ["account_agent"]},
                   "account_agent": {"kind": "llm", "description": "accounts", "parent": "service_desk", "sub_agents": []}},
        "tools": {"account_agent/lookup_user": {"agent": "account_agent", "name": "lookup_user", "kind": "function",
                                                "description": "look up"}},
        "edges": [{"kind": "entry", "caller": "ingress", "target": "service_desk", "workflow": None},
                  {"kind": "transfer", "caller": "service_desk", "target": "account_agent", "workflow": None}]}))
    (bundle / "bindings.json").write_text(json.dumps({
        "domains": {"service_desk": "core", "account_agent": "account"},
        "operations": {"account_agent/lookup_user": {"action": "read", "side_effect": False, "criticality": "low",
                                                      "classification": "confidential", "requires_approval": False,
                                                      "secondary_approval": False, "allowed_roles": None,
                                                      "mask_fields": ["email"], "declared": True, "evidence": ["name verb"]}}}))
    (bundle / "policy_store" / "10_access.psl").write_text(PSL)
    write_chain(state / "audit.jsonl", [
        {"event": "ENGINE_START", "mode": "enforce", "policy_version": "pv1"},
        {"event": "INPUT_AUTHORIZATION", "allowed": True, "decision": "ALLOW", "caller": "ingress", "target": "service_desk"},
        {"event": "CONTENT_INPUT", "allowed": False, "decision": "DENY", "reason": "psl_violation:content.input.prompt-injection",
         "rules": ["content.input.prompt-injection"], "caller": "ingress", "target": "service_desk"}])
    (state / "approvals" / "requests" / "apr-aaaaaaaaaaaa.json").write_text(json.dumps({
        "approval_id": "apr-aaaaaaaaaaaa", "status": "pending", "agent": "account_agent", "tool": "reset_password",
        "reason": "needs human_approval", "purposes": ["human_approval"], "created_at": "2026-11-09T10:00:00Z",
        "expires_at": "2026-11-09T11:00:00Z", "request_hash": "ab" * 32, "trace_id": "t1",
        "operation": {"parameters": {"username": "<b>alice</b>"}, "environment": "test"}}))
    profile = tmp_path / "zt_adk.yaml"
    profile.write_text("version: 1\napp: demo.agent:app\nbundle_dir: bundle\nstate_dir: state\n")
    fake = tmp_path / "fake_zt_adk.py"
    fake.write_text(FAKE_ZT_ADK)
    cfg = Config.from_profile(profile, data_dir=tmp_path / "data", zt_adk=[sys.executable, str(fake)],
                              allowed_hosts=("testserver",))
    client = TestClient(create_app(cfg), headers={"X-ZT-Console": "1"})
    return {"client": client, "cfg": cfg, "state": state, "bundle": bundle, "tmp": tmp_path}


@pytest.fixture()
def bare(tmp_path: Path):
    """Console with no protected application loaded."""
    cfg = Config(data_dir=tmp_path / "data", allowed_hosts=("testserver",))
    client = TestClient(create_app(cfg), headers={"X-ZT-Console": "1"})
    client.cfg = cfg
    return client
