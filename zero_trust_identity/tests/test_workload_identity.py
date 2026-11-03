"""Workload layer of SPIFFE scheme B: X.509-SVID leaf validation, mTLS server-identity check, service map."""
from __future__ import annotations

import asyncio
import json
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

import aiohttp
import pytest
from aiohttp import web

from zt_identity.identity import AuthenticationError, VerifiedTransportIdentity
from zt_identity.workload_identity.service_map import IdentityMap
from zt_identity.workload_identity.connector import PeerIdentityRejected, SpiffeConnector
from zt_identity.workload_identity.svid import validate_svid_leaf
from tests.helpers import make_ca, make_svid, pem_cert, pem_key

TD = "citi-p3.test"
GW = f"spiffe://{TD}/ztbp/svc/zt-gateway"
LEDGER = f"spiffe://{TD}/ztbp/wl/ledger_update_agent"


def test_svid_leaf_ok():
    k, c = make_ca()
    _, leaf = make_svid(k, c, LEDGER)
    assert validate_svid_leaf(leaf, TD) == LEDGER


@pytest.mark.parametrize("uri,kw,code", [
    ("spiffe://other.test/ztbp/wl/x", {}, "svid_wrong_trust_domain"),
    (None, {}, "svid_missing_san"),
    ("https://not-spiffe/x", {}, "svid_uri_not_spiffe"),
    (LEDGER, {"ca": True}, "svid_leaf_is_ca"),
    (LEDGER, {"digital_signature": False}, "svid_bad_key_usage"),
    (LEDGER, {"valid_for": timedelta(seconds=1), "start_offset": timedelta(minutes=-5)}, "svid_outside_validity"),
])
def test_svid_leaf_rejections(uri, kw, code):
    k, c = make_ca()
    _, leaf = make_svid(k, c, uri, **kw)
    with pytest.raises(AuthenticationError) as e:
        validate_svid_leaf(leaf, TD)
    assert e.value.code == code


def _map(tmp_path: Path, enabled=True) -> IdentityMap:
    p = tmp_path / "map.json"
    p.write_text(json.dumps({"version": 1, "entries": {LEDGER: {
        "kind": "agent", "agent_id": "ledger_update_agent", "identity_version": 4, "enabled": enabled}}}))
    return IdentityMap(p)


def _t(spiffe=LEDGER):
    return VerifiedTransportIdentity(spiffe_id=spiffe, cert_serial="1", connection_id=1,
                                     not_after=datetime.now(timezone.utc) + timedelta(hours=1))


def test_service_map_reloads_controlled_file(tmp_path):
    m = _map(tmp_path)
    e = m.lookup(LEDGER)
    assert e is not None and e.agent_id == "ledger_update_agent" and e.enabled
    assert m.lookup(GW) is None                       # unmapped SPIFFE ID: no subject


def _tls_material(tmp_path: Path, server_uri: str):
    ck, cc = make_ca()
    sk, sc = make_svid(ck, cc, server_uri)
    lk, lc = make_svid(ck, cc, LEDGER)
    files = {}
    for name, data in {"ca.pem": pem_cert(cc), "srv.pem": pem_cert(sc), "srv.key": pem_key(sk),
                       "cli.pem": pem_cert(lc), "cli.key": pem_key(lk)}.items():
        (tmp_path / name).write_bytes(data)
        files[name] = str(tmp_path / name)
    return files


async def _roundtrip(files, expected: str):
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.verify_mode = ssl.CERT_REQUIRED
    sctx.load_cert_chain(files["srv.pem"], files["srv.key"])
    sctx.load_verify_locations(files["ca.pem"])
    app = web.Application()
    app.router.add_get("/", lambda r: web.json_response({"ok": True}))
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=sctx)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.check_hostname = False
    cctx.verify_mode = ssl.CERT_REQUIRED
    cctx.load_cert_chain(files["cli.pem"], files["cli.key"])
    cctx.load_verify_locations(files["ca.pem"])
    conn = SpiffeConnector(ssl=cctx, trust_domain=TD, authorize_server=lambda h, sid: sid == expected)
    try:
        async with aiohttp.ClientSession(connector=conn) as s:
            async with s.get(f"https://127.0.0.1:{port}/") as r:
                return await r.json()
    finally:
        await runner.cleanup()


def test_client_accepts_expected_server_id(tmp_path):
    files = _tls_material(tmp_path, GW)
    assert asyncio.run(_roundtrip(files, GW)) == {"ok": True}


def test_client_rejects_unexpected_server_id(tmp_path):
    files = _tls_material(tmp_path, f"spiffe://{TD}/ztbp/svc/something-else")
    with pytest.raises(PeerIdentityRejected):
        asyncio.run(_roundtrip(files, GW))
