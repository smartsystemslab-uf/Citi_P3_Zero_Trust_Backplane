"""Regression: the Citi P3 banking MAS protected through the generic zt-adk path.

The application is not part of this repository and is never modified. The test runs only when
CITI_MAS_COPY points at a COPY of D:\\Lab\\Citi_P3\\citi_banking_adk (the directory that contains the
bank_adk package); the bank's own state goes to a temporary directory. Its model is replaced by
profiles/citi_p3/playback.yaml; agents, tools, workflows and its custom orchestration agents run
unchanged under ZeroTrustPlugin with the bundle built from profiles/citi_p3/zt_adk.yaml.
"""
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path

import pytest

from conftest import BACKPLANE, _approver, audit, calls, results, texts

PROFILE = BACKPLANE / "profiles" / "citi_p3" / "zt_adk.yaml"
pytestmark = pytest.mark.skipif(not os.environ.get("CITI_MAS_COPY"),
                                reason="CITI_MAS_COPY (a copy of the Citi banking ADK app) is not set")


@pytest.fixture(scope="module")
def citi(tmp_path_factory):
    from zt_adk.build import build
    from zt_adk.keys import init_keys
    from zt_adk.profile import load_profile

    tmp = tmp_path_factory.mktemp("citi")
    sys.dont_write_bytecode = True        # importing the app leaves no files in its tree
    os.environ["BANKING_ADK_RUNTIME_DIR"] = str(tmp / "bank_state")    # read when bank_adk is imported
    os.environ["BANKING_USE_EXTERNAL_API"] = "false"
    init_keys(tmp / "keys", tmp / "approver-keys", approvers=["ops_lead"], secondaries=["risk_officer"])
    prof = load_profile(PROFILE)
    prof.keys_dir, prof.approver_keys_dir = str(tmp / "keys"), str(tmp / "approver-keys")
    prof.bundle_dir, prof.state_dir = str(tmp / "bundle"), str(tmp / "state")
    prof.approvals.wait_seconds, prof.approvals.poll_seconds = 6, 0.1     # tests: an unanswered call is held soon
    result = build(prof, skip_static=True)
    return tmp, prof, result


class Bank:
    def __init__(self, citi, tmp_path: Path, role: str) -> None:
        from google.adk.runners import Runner
        from google.adk.sessions import InMemorySessionService

        from zt_adk.discovery import load_object, resolve_app
        from zt_adk.plugin import ZeroTrustPlugin
        from zt_adk.testing.playback import install_playback

        tmp, prof, _ = citi
        root, _name, _plugins = resolve_app(load_object(prof.app, [prof.path(p) for p in prof.python_paths]))
        install_playback(root, PROFILE.parent / "playback.yaml")
        self.state_dir = tmp_path / "state"
        self.keys = tmp / "approver-keys"
        self.plugin = ZeroTrustPlugin(root_agent=root, bundle_dir=tmp / "bundle", keys_dir=tmp / "keys",
                                      state_dir=self.state_dir)
        self.sessions = InMemorySessionService()
        self.runner = Runner(app_name="citi_banking_adk", agent=root, session_service=self.sessions,
                             plugins=[self.plugin])
        self.session = asyncio.run(self.sessions.create_session(app_name="citi_banking_adk", user_id="u1"))
        self.plugin.register_session(self.session.id, user_role=role)

    def say(self, text: str, approve: dict | None = None) -> list:
        return asyncio.run(self._say(text, approve))

    async def _say(self, text: str, approve: dict | None) -> list:
        from google.genai import types

        task = asyncio.create_task(_approver(self.state_dir, approve)) if approve else None
        out = [ev async for ev in self.runner.run_async(
            user_id="u1", session_id=self.session.id,
            new_message=types.Content(role="user", parts=[types.Part(text=text)]))]
        if task is not None:
            await task
        return out


def test_bundle_from_generic_path(citi):
    _tmp, _prof, res = citi
    m = res.model
    assert len(m.agents) == 36 and m.root_agent == "user_proxy_agent"
    assert m.agents["customer_service_chatbot_workflow"].kind == "custom"
    store = res.bundle_dir / "policy_store"
    assert (store / "90_overlay_citi_intent.psl").exists() and (store / "15_domains.psl").exists()
    ops = res.ids.operations
    for key in ("transaction_processing_agent/execute_transfer", "ledger_update_agent/apply_ledger_updates"):
        assert ops[key]["criticality"] == "critical" and ops[key]["secondary_approval"]
    assert ops["transaction_processing_agent/execute_transfer"]["allowed_roles"] == ["customer", "internal_rep"]
    assert any("front_office_router (front_office) -> back_office_router (back_office)" in w for w in res.warnings)


def test_transfer_runs_after_dual_approval(citi, tmp_path):
    tmp, _, _ = citi
    bank = Bank(citi, tmp_path, "customer")
    ev = bank.say("Transfer 250 from CHK-001 to CHK-002",
                  approve={"keys_dir": tmp / "approver-keys",
                           "signers": {"human_approval": ("ops_lead", False),
                                       "secondary_authorization": ("risk_officer", True)}})
    assert "execute_transfer" in calls(ev)
    raw = results(ev)["execute_transfer"]
    assert '"status": "posted"' in str(raw), raw
    events = [r["event"] for r in audit(bank.state_dir)]
    assert "APPROVAL_REQUESTED" in events and "APPROVAL_APPLIED" in events


def test_transfer_without_secondary_authorization_is_held(citi, tmp_path):
    tmp, _, _ = citi
    bank = Bank(citi, tmp_path, "customer")
    ev = bank.say("Transfer 250 from CHK-001 to CHK-002",
                  approve={"keys_dir": tmp / "approver-keys", "signers": {"human_approval": ("ops_lead", False)}})
    r = results(ev)["execute_transfer"]
    assert r["status"] in ("pending_approval", "zero_trust_denied"), r


def test_transfer_by_wrong_role_is_denied(citi, tmp_path):
    tmp, _, _ = citi
    bank = Bank(citi, tmp_path, "ops_scheduler")                  # not a transfer role
    ev = bank.say("Transfer 250 from CHK-001 to CHK-002",
                  approve={"keys_dir": tmp / "approver-keys",
                           "signers": {"human_approval": ("ops_lead", False),
                                       "secondary_authorization": ("risk_officer", True)}})
    assert results(ev)["execute_transfer"]["status"] == "zero_trust_denied"


def test_cross_domain_transfer_is_denied(citi, tmp_path):
    bank = Bank(citi, tmp_path, "customer")
    ev = bank.say("Please check the ledger batch status")
    r = results(ev)["transfer_to_agent"]
    assert r["status"] == "zero_trust_denied" and "domains.no-cross-domain-routes" in r["reason"], r
    assert not any(e.author == "back_office_router" for e in ev)


def test_account_ids_are_withheld(citi, tmp_path):
    bank = Bank(citi, tmp_path, "customer")
    ev = bank.say("What are my account numbers?")
    shown = " ".join(texts(ev))
    assert "CHK-001" not in shown and "SVG-001" not in shown


def test_unknown_role_is_refused(citi, tmp_path):
    bank = Bank(citi, tmp_path, f"visitor-{uuid.uuid4().hex[:4]}")
    ev = bank.say("What are my account numbers?")
    assert calls(ev) == [] and "content.input.known-role" in texts(ev)[0]
