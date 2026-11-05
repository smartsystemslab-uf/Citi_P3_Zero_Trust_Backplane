"""Component correctness of scheme B (agent certificate + RFC 9421)."""
from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest
from multidict import CIMultiDict
from cryptography.hazmat.primitives import serialization

from zt_identity.agent_identity import certs
from zt_identity.agent_identity.httpsig import (
    SignatureRejected, check_content_digest, content_digest, sign_request, verify_request_signature,
)
from zt_identity.agent_identity.verifier import AgentCredentialAuthenticator, RegistrySnapshotCache
from zt_identity.identity import AuthenticationError, VerifiedTransportIdentity

AUTH = "zt-gateway:8443"
URL = f"https://{AUTH}/v1/tools/get_eod_batch"
WL = "spiffe://citi-p3.test/ztbp/wl/eod_processing_agent"


@pytest.fixture(scope="module")
def ca():
    return certs.make_ca("unit agent CA", days=1)


def issue(ca, agent="eod_processing_agent", ttl=300):
    key = certs.new_key()
    cert = certs.issue_agent_cert(ca[0], ca[1], key.public_key(), agent, ttl)
    return key, cert.public_bytes(serialization.Encoding.DER)


def signed(key, der, body=b'{"request_id":"r1","workflow_run_id":"w1"}', agent="eod_processing_agent", workload=WL):
    headers = sign_request(method="POST", url=URL, body=body, private_key=key, key_id=certs.fingerprint(der),
                           agent_id=agent, workload_id=workload, request_id="r1", workflow_run_id="w1",
                           cert_header=base64.b64encode(der).decode())
    headers["Host"] = AUTH
    return headers, body


def test_signature_roundtrip(ca):
    key, der = issue(ca)
    headers, body = signed(key, der)
    check_content_digest(headers["Content-Digest"], body)
    vc = certs.verify_agent_cert(der, ca[1])
    res = verify_request_signature(method="POST", url=URL, headers=headers, public_key=vc.public_key,
                                   key_id=certs.fingerprint(der))
    assert "x-zt-workload-id" in res.covered and res.expires - res.created <= 60


def test_body_change_breaks_digest(ca):
    key, der = issue(ca)
    headers, _ = signed(key, der)
    with pytest.raises(SignatureRejected) as e:
        check_content_digest(headers["Content-Digest"], b'{"request_id":"r1","workflow_run_id":"w2"}')
    assert e.value.code == "content_digest_mismatch"


def test_signature_by_other_key_rejected(ca):
    key, der = issue(ca)
    other, _ = issue(ca)
    headers, _ = signed(other, der)        # keyid claims `der`, signed by a different key
    with pytest.raises(SignatureRejected) as e:
        verify_request_signature(method="POST", url=URL, headers=headers,
                                 public_key=certs.verify_agent_cert(der, ca[1]).public_key,
                                 key_id=certs.fingerprint(der))
    assert e.value.code == "invalid_signature"


def test_cert_from_other_ca_rejected(ca):
    other_ca = certs.make_ca("other", days=1)
    _, der = issue(other_ca)
    with pytest.raises(certs.AgentCertError) as e:
        certs.verify_agent_cert(der, ca[1])
    assert e.value.code in {"agent_cert_untrusted_issuer", "agent_cert_bad_signature"}


def test_expired_cert_rejected(ca):
    _, der = issue(ca, ttl=1)
    with pytest.raises(certs.AgentCertError) as e:
        certs.verify_agent_cert(der, ca[1], now=datetime.now(timezone.utc) + timedelta(seconds=30))
    assert e.value.code == "agent_cert_outside_validity"


def test_renew_proof_requires_current_key(ca):
    key, der = issue(ca)
    from cryptography import x509
    cert = x509.load_der_x509_certificate(der)
    csr = certs.build_csr(certs.new_key(), "eod_processing_agent", "nonce-1")
    certs.verify_renew_proof(cert, csr, "nonce-1", certs.sign_renew_proof(key, csr, "nonce-1"))
    with pytest.raises(certs.AgentCertError):
        certs.verify_renew_proof(cert, csr, "nonce-1", certs.sign_renew_proof(certs.new_key(), csr, "nonce-1"))


# ---------------------------------------------------------------------------
@dataclass
class Req:
    method: str
    path_qs: str
    headers: dict
    body: bytes


class _Map:
    def lookup(self, spiffe_id):
        return None


def authenticator(ca, *, enabled=True, revoked=(), workloads=(WL,)):
    async def fetch():
        return {}
    reg = RegistrySnapshotCache(fetch)
    reg.snapshot = {"registry_version": 7, "agents": {"eod_processing_agent": {
        "enabled": enabled, "identity_version": "agent-idv-3", "allowed_workloads": list(workloads),
        "revoked_serials": list(revoked)}}}
    reg.fetched_at = time.monotonic()
    return AgentCredentialAuthenticator(ca_cert=ca[1], registry=reg, service_map=_Map(), authority=AUTH), reg


def transport(spiffe=WL):
    return VerifiedTransportIdentity(spiffe_id=spiffe, cert_serial="abc", connection_id=1,
                                     not_after=datetime.now(timezone.utc) + timedelta(hours=1))


def do(auth, headers, body, t=None):
    # aiohttp request headers are case-insensitive (CIMultiDict), as in the gateway
    return auth.authenticate(Req("POST", "/v1/tools/get_eod_batch", CIMultiDict(headers), body), t or transport(),
                             body_json={"request_id": "r1", "workflow_run_id": "w1"})


def test_b_authenticates_both_layers(ca):
    key, der = issue(ca)
    auth, _ = authenticator(ca)
    ident = do(auth, *signed(key, der))
    assert (ident.auth_mode, ident.agent_id, ident.workload_spiffe_id) == ("B", "eod_processing_agent", WL)
    assert ident.identity_version == "agent-idv-3" and ident.agent_credential_id


@pytest.mark.parametrize("case,code", [
    ("no_cert", "missing_agent_credential"),
    ("disabled", "agent_disabled"),
    ("revoked", "agent_cert_revoked"),
    ("unbound_workload", "workload_not_bound_to_agent"),
    ("claimed_other_agent", "claimed_agent_mismatch"),
    ("stale_registry", "agent_registry_stale"),
])
def test_b_rejections(ca, case, code):
    key, der = issue(ca)
    serial = format(__import__("cryptography").x509.load_der_x509_certificate(der).serial_number, "x")
    auth, reg = authenticator(ca, enabled=case != "disabled", revoked=[serial] if case == "revoked" else [])
    headers, body = signed(key, der)
    t = None
    if case == "no_cert":
        headers.pop("X-ZT-Agent-Cert")
    if case == "unbound_workload":
        t = transport("spiffe://citi-p3.test/ztbp/wl/ledger_update_agent")
    if case == "claimed_other_agent":
        headers["X-ZT-Agent-Id"] = "ledger_update_agent"
    if case == "stale_registry":
        reg.fetched_at -= 60
    with pytest.raises(AuthenticationError) as e:
        do(auth, headers, body, t)
    assert e.value.code == code


def test_b_signed_workload_must_match_tls_peer(ca):
    key, der = issue(ca)
    auth, reg = authenticator(ca, workloads=(WL, "spiffe://citi-p3.test/ztbp/wl/other"))
    headers, body = signed(key, der, workload="spiffe://citi-p3.test/ztbp/wl/other")
    with pytest.raises(AuthenticationError) as e:
        do(auth, headers, body)
    assert e.value.code == "signed_workload_binding_mismatch"


def test_b_same_signature_accepted_once(ca):
    key, der = issue(ca)
    auth, _ = authenticator(ca)
    headers, body = signed(key, der)
    do(auth, dict(headers), body)
    with pytest.raises(AuthenticationError) as e:
        do(auth, dict(headers), body)
    assert e.value.code == "signature_replayed"
