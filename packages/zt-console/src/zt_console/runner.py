"""Run messages through the protected application, check expectations, and prepare the application.

The console never imports the application. It starts the ``zt-adk`` command for the profile it was configured with
(one operation at a time, argument list without a shell, fixed time limit) and reads the audit records that run
appended.
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import threading
from pathlib import Path
from typing import Any

from .backplane import SAFE_ID, Backplane, BackplaneUnavailable
from .casestore import CaseError, clean_expect, clean_messages
from .config import Config

ROLE_RE = re.compile(r"^[A-Za-z0-9_.-]{0,40}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$")      # an approver name: becomes part of a key file name
_RUN_LOCK = threading.Lock()
_PROC_LOCK = threading.Lock()
_PROC: subprocess.Popen[str] | None = None            # the zt-adk command running now, if any
_CANCEL = threading.Event()                           # set when the user stopped that command
_AGENT_LINE = re.compile(r"^\[(?P<agent>[\w.-]+)\] (?P<text>.*)$")
SETUP_ACTIONS = {"keys": 120, "build": 900, "check": 180}


class RunRejected(ValueError):
    pass


def load_scenarios(seed_dir: Path, app: str | tuple[str, ...]) -> list[dict[str, Any]]:
    """Presets written for this application (``app`` is one name or every name it is known by)."""
    p = seed_dir / "scenarios.json"
    if not p.exists():
        return []
    names = (app,) if isinstance(app, str) else tuple(app)
    items = json.loads(p.read_text(encoding="utf-8")).get("scenarios", [])
    return [{**s, "preset": True} for s in items if s.get("app") in ("*", *names)]


def parse_answer(output: str) -> tuple[str, str]:
    """The last agent answer printed by ``zt-adk run``: ``(agent, text)``, or ``("", "")``.

    ``zt-adk run`` prints ``[agent] text`` with the text unmodified, so a multi-line answer continues on lines that
    carry no prefix. Tool-call lines, the engine's own ``[zt-adk]`` lines, the echoed ``>>> message`` and refusal
    notices (a JSON object) are not answers."""
    answers: list[tuple[str, list[str]]] = []
    current: tuple[str, list[str]] | None = None
    for line in output.splitlines():
        m = _AGENT_LINE.match(line)
        if m:
            agent, text = m.group("agent"), m.group("text")
            current = None
            if agent != "zt-adk" and text.strip() and not text.startswith("call ") and not text.lstrip().startswith("{"):
                current = (agent, [text])
                answers.append(current)
        elif line.startswith(">>> "):
            current = None
        elif current is not None:
            current[1].append(line)
    if not answers:
        return "", ""
    agent, lines = answers[-1]
    return agent, "\n".join(lines).strip()


def _verdict(events: list[dict[str, Any]]) -> dict[str, str]:
    held = [e for e in events if e["outcome"] == "held"]
    applied = [e for e in events if e["event"] == "APPROVAL_APPLIED" and e["raw"].get("allowed")]
    denied = [e for e in events if e["outcome"] == "denied"]
    if held and not applied:
        return {"state": "held", "title": "Held for approval",
                "text": "A critical operation is waiting for a human approval. Approve or deny it, then run again "
                        "if the run timed out."}
    if denied:
        first = denied[0]
        return {"state": "blocked", "title": f"Blocked at the {first['boundary'].lower()} boundary", "text": first["text"]}
    flagged = [e for e in events if e["outcome"] == "flagged"]
    if flagged:
        return {"state": "flagged", "title": "Completed, with content flagged", "text": flagged[0]["text"]}
    return {"state": "allowed", "title": "Completed", "text": "Every boundary allowed the request."}


def evaluate(expect: dict[str, str], result: dict[str, Any]) -> list[dict[str, Any]]:
    """Compare a run with the expectations of a test case. Returns one check per expectation."""
    checks: list[dict[str, Any]] = []
    state, events = result["verdict"]["state"], result["events"]
    answer = (result.get("answer") or "").lower()
    if "state" in expect:
        want = expect["state"]
        ok = state in ("allowed", "flagged") if want == "completed" else state == want
        checks.append({"name": f"outcome is {want}", "ok": ok, "detail": f"actual: {state}"})
    if "boundary" in expect:
        b = expect["boundary"]
        stop = expect.get("state") in ("blocked", "held")
        hit = [e for e in events if e["boundary"] == b and (e["outcome"] in ("denied", "held") if stop else True)]
        checks.append({"name": f"{b} boundary {'stopped it' if stop else 'was involved'}", "ok": bool(hit),
                       "detail": "boundaries seen: " + ", ".join(sorted({e['boundary'] for e in events}))})
    if "rule" in expect:
        rules = {r["id"] for e in events for r in e["rules"]}
        checks.append({"name": f"rule {expect['rule']} fired", "ok": expect["rule"] in rules,
                       "detail": "rules seen: " + (", ".join(sorted(rules)) or "none")})
    if "answer_contains" in expect:
        checks.append({"name": f"answer contains '{expect['answer_contains']}'",
                       "ok": expect["answer_contains"].lower() in answer, "detail": f"answer: {result.get('answer') or ''}"[:200]})
    if "answer_not_contains" in expect:
        checks.append({"name": f"answer does not contain '{expect['answer_not_contains']}'",
                       "ok": expect["answer_not_contains"].lower() not in answer, "detail": f"answer: {result.get('answer') or ''}"[:200]})
    return checks


def _terminate(proc: subprocess.Popen[str]) -> None:
    """Stop the command and anything it started (the command gets its own process group), politely first."""
    if proc.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGTERM)
        else:
            proc.terminate()
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError):
        pass


def cancel_current() -> bool:
    """Stop the zt-adk command that is running now. Returns False when nothing is running."""
    with _PROC_LOCK:
        proc = _PROC
        if proc is None or proc.poll() is not None:
            return False
        _CANCEL.set()
    _terminate(proc)
    return True


def _exec(cfg: Config, argv: list[str], timeout: int) -> tuple[str, int, bool, bool]:
    """Run one command. Returns ``(output, exit code, timed out, cancelled by the user)``."""
    global _PROC
    kwargs: dict[str, Any] = {"cwd": str(cfg.profile.parent), "stdout": subprocess.PIPE, "stderr": subprocess.PIPE,  # type: ignore[union-attr]
                              "text": True, "shell": False}
    if os.name == "posix":
        kwargs["start_new_session"] = True            # own process group: a stop or a timeout also ends its children
    else:
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    with _PROC_LOCK:
        _CANCEL.clear()
        proc = subprocess.Popen(argv, **kwargs)
        _PROC = proc
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate(proc)
        out, err = proc.communicate()
    finally:
        with _PROC_LOCK:
            _PROC = None
    cancelled = _CANCEL.is_set()
    return (out or "") + (err or ""), (-1 if timed_out or cancelled else proc.returncode), timed_out, cancelled


def _need_command(cfg: Config) -> None:
    if not cfg.zt_adk:
        raise RunRejected("the zt-adk command was not found next to this Python; install zt-adk in the same "
                          "environment or start the console with --zt-adk PATH")


def run_messages(cfg: Config, bp: Backplane, messages: list[str], role: str,
                 expect: dict[str, str] | None = None) -> dict[str, Any]:
    if not cfg.configured:
        raise BackplaneUnavailable("no protected application is loaded or its bundle is not built yet")
    _need_command(cfg)
    try:
        messages = clean_messages(messages, cfg.max_message_chars)
        expect = clean_expect(expect)
    except CaseError as exc:
        raise RunRejected(str(exc)) from exc
    role = (role or "").strip()
    if not ROLE_RE.match(role):
        raise RunRejected("role may contain letters, digits, '.', '_' and '-' only")
    if not _RUN_LOCK.acquire(blocking=False):
        raise RunRejected("another operation is in progress; wait for it to finish")
    try:
        before = bp.last_seq()
        argv = [*cfg.zt_adk, "--profile", str(cfg.profile), "run"]
        if role:
            argv += [f"--role={role}"]                      # one token, so a role that starts with '-' stays a value
        argv += ["--user", "console-user", "--", *messages]
        output, code, timed_out, cancelled = _exec(cfg, argv, cfg.run_timeout_s)
    finally:
        _RUN_LOCK.release()
    events = list(reversed(bp.events(after_seq=before, limit=500)["items"]))
    agent, answer = parse_answer(output)
    verdict = _verdict(events)
    if cancelled:
        verdict = {"state": "cancelled", "title": "Run stopped",
                   "text": "The run was stopped from the console. The decisions recorded before it stopped are shown."}
    elif timed_out:
        verdict = {"state": "timeout", "title": "Run timed out", "text": f"No result within {cfg.run_timeout_s} s."}
    elif code != 0 and not events:
        verdict = {"state": "error", "title": "The run failed", "text": "zt-adk exited with an error; see the raw output."}
    result = {"ok": code == 0, "exit_code": code, "timed_out": timed_out, "cancelled": cancelled, "verdict": verdict, "answer": answer,
              "answer_agent": agent, "events": events, "output": output[-20000:], "role": role, "messages": messages}
    if expect:
        result["checks"] = evaluate(expect, result)
        result["passed"] = all(c["ok"] for c in result["checks"])
    return result


def run_setup(cfg: Config, action: str, approver: str = "alice", secondary: str = "bob") -> dict[str, Any]:
    """keys / build / check for the loaded profile (the same commands you would type)."""
    if cfg.profile is None:
        raise BackplaneUnavailable("no profile selected")
    if action not in SETUP_ACTIONS:
        raise RunRejected(f"unknown setup action {action!r}")
    if action == "keys" and not (NAME_RE.match(approver) and NAME_RE.match(secondary)):
        raise RunRejected("approver names start with a letter or digit and may contain letters, digits, '.', '_' "
                          "and '-' (at most 40 characters)")
    _need_command(cfg)
    argv = [*cfg.zt_adk, "--profile", str(cfg.profile)]
    argv += {"keys": ["keys", "init", f"--approver={approver}", f"--secondary={secondary}"], "build": ["build"],
             "check": ["check"]}[action]
    if not _RUN_LOCK.acquire(blocking=False):
        raise RunRejected("another operation is in progress; wait for it to finish")
    try:
        output, code, timed_out, cancelled = _exec(cfg, argv, SETUP_ACTIONS[action])
    finally:
        _RUN_LOCK.release()
    return {"action": action, "ok": code == 0, "exit_code": code, "timed_out": timed_out, "cancelled": cancelled,
            "output": output[-20000:]}


def _key_names(directory: Path | None, prefix: str) -> list[str]:
    """Names of the approvers whose private key is on this machine (``<prefix>_<name>_private.pem``)."""
    if directory is None or not directory.is_dir():
        return []
    suffix = "_private.pem"
    names = (p.name[len(prefix) + 1:-len(suffix)] for p in sorted(directory.glob(f"{prefix}_*{suffix}")))
    return [n for n in names if NAME_RE.match(n)]


def setup_status(cfg: Config) -> dict[str, Any]:
    keys = bool(cfg.keys_dir and (cfg.keys_dir / "pep_private.pem").exists())
    return {"profile": str(cfg.profile) if cfg.profile else None, "keys": keys, "bundle": cfg.configured,
            "command": bool(cfg.zt_adk), "approvers": _key_names(cfg.approver_dir, "approver"),
            "secondaries": _key_names(cfg.approver_dir, "secondary")}


# ---------------------------------------------------------------------- developer-only approvals
def decide_approval(cfg: Config, bp: Backplane, approval_id: str, approve: bool, approver: str,
                    secondary: bool, comment: str) -> dict[str, Any]:
    """Sign an approval with a LOCAL approver key. Disabled unless the console runs with --dev-approve.

    This is a developer convenience. In a real deployment approver keys must stay on approver devices;
    the console should then only display requests."""
    if not cfg.dev_approve:
        raise RunRejected("approving from the console is disabled; use: zt-adk approvals approve <id> --approver NAME "
                          "(or start the console with --dev-approve on a development machine)")
    if not SAFE_ID.match(approval_id) or not SAFE_ID.match(approver):
        raise RunRejected("invalid approval id or approver name")
    try:
        from zt_adk.approvals import ApprovalError, ApprovalStore
        from zt_adk.keys import approver_issuer, load_private
        from zt_pdp.evidence_issuer import IssuerKey
    except ImportError as exc:                                  # the console itself does not need zt-adk
        raise RunRejected(f"zt-adk is not importable in this environment: {exc}") from exc
    assert cfg.approver_dir and cfg.approvals_dir and cfg.bundle_dir
    prefix = "secondary" if secondary else "approver"
    key_file = cfg.approver_dir / f"{prefix}_{approver}_private.pem"
    if not key_file.is_file():
        raise RunRejected(f"no local key for approver {approver!r}")
    profile = json.loads((cfg.bundle_dir / "runtime_profile.json").read_text("utf-8"))
    lifetime = int((profile.get("approvals") or {}).get("lifetime_seconds", 300))
    store = ApprovalStore(cfg.approvals_dir)
    try:
        signed = store.decide(approval_id, key=IssuerKey(approver_issuer(approver, secondary), "key-1",
                                                         load_private(key_file)),
                              purpose="secondary_authorization" if secondary else "human_approval", approve=approve,
                              approver=approver, lifetime_seconds=lifetime, comment=comment[:500])
    except ApprovalError as exc:
        raise RunRejected(str(exc)) from exc
    return {"decision": signed.get("decision"), "issuer": signed.get("issuer"), "expires_at": signed.get("expires_at")}
