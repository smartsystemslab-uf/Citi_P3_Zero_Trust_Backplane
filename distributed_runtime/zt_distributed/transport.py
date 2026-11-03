"""HTTPS transport shared by every workload: SPIFFE mTLS (X.509-SVID from the SPIRE agent).

Connection policy is explicit:
  reuse       keep-alive connection pool (default)
  new         a new TCP+TLS connection per request, full handshake
              (servers are started with TLS 1.3 session tickets disabled)
  new-resume  a new connection per request, resuming the previous TLS session
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Callable
from urllib.parse import urlsplit

import aiohttp

from zt_identity.agent_identity.client import AgentCredentialManager
from zt_identity.workload_identity.connector import ConnectionStats, SpiffeConnector
from zt_identity.workload_identity.spiffe_tls import WorkloadIdentity

CONN_MODES = ("reuse", "new", "new-resume")


def dumps(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), default=str).encode("utf-8")


class ServiceClient:
    def __init__(
        self,
        *,
        identity: WorkloadIdentity,
        trust_domain: str,
        expected_servers: dict[str, str],
        conn_mode: str = "reuse",
        limit: int = 1024,
        timeout_s: float = 60.0,
        agent_creds: AgentCredentialManager | None = None,
    ) -> None:
        if conn_mode not in CONN_MODES:
            raise ValueError(conn_mode)
        self.identity = identity
        self.trust_domain = trust_domain
        self.expected = dict(expected_servers)
        self.conn_mode = conn_mode
        self.limit = limit
        self.timeout = aiohttp.ClientTimeout(total=timeout_s)
        self.agent_creds = agent_creds
        self.stats = ConnectionStats()
        self.sessions_replaced = 0
        self._ctx = None
        self._session = self._new_session()
        identity.add_listener(self._on_svid_rotation)

    def _authorize_server(self, host: str, spiffe_id: str) -> bool:
        return self.expected.get(host) == spiffe_id

    def _new_session(self) -> aiohttp.ClientSession:
        force_close = self.conn_mode != "reuse"
        self._ctx = self.identity.client_context(resume_sessions=self.conn_mode == "new-resume")
        pool_kw: dict[str, Any] = {"force_close": True} if force_close else {"keepalive_timeout": 60}
        connector = SpiffeConnector(
            ssl=self._ctx,
            trust_domain=self.trust_domain, authorize_server=self._authorize_server,
            stats=self.stats, limit=self.limit, limit_per_host=self.limit, **pool_kw,
        )
        return aiohttp.ClientSession(connector=connector, timeout=self.timeout,
                                     cookie_jar=aiohttp.DummyCookieJar(), raise_for_status=False)

    def _on_svid_rotation(self) -> None:
        # New handshakes must present the new SVID: start a fresh pool and let
        # in-flight requests on the old pool finish before closing it.
        old = self._session
        self._session = self._new_session()
        self.sessions_replaced += 1

        async def _close_later() -> None:
            await asyncio.sleep(30)
            await old.close()

        try:
            asyncio.get_running_loop().create_task(_close_later())
        except RuntimeError:
            pass

    async def post(
        self,
        url: str,
        payload: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
        sign_for: tuple[str, str] | None = None,
    ) -> tuple[int, dict[str, Any], dict[str, float]]:
        body = dumps(payload)
        hdrs = {"Content-Type": "application/json"}
        if headers:
            hdrs.update(headers)
        info: dict[str, float] = {"sign_ms": 0.0}
        if self.agent_creds is not None and sign_for is not None:
            signed, info["sign_ms"] = self.agent_creds.sign(
                method="POST", url=url, body=body, request_id=sign_for[0], workflow_run_id=sign_for[1])
            hdrs.update(signed)
        t0 = time.perf_counter()
        async with self._session.post(url, data=body, headers=hdrs) as resp:
            raw = await resp.read()
            status = resp.status
        if self.conn_mode == "new-resume" and self._ctx is not None:
            # TLS 1.3 tickets arrive after the handshake; once the response has been
            # read they are processed, so the newest connection's session is resumable.
            host = urlsplit(url).hostname or ""
            ssl_obj = self._session.connector.last_ssl_object.get(host)
            if ssl_obj is not None and ssl_obj.session is not None and ssl_obj.session.has_ticket:
                self._ctx.remember_session(host, ssl_obj.session)
        info["rtt_ms"] = (time.perf_counter() - t0) * 1000
        try:
            data = json.loads(raw) if raw else {}
        except ValueError:
            data = {"raw": raw[:200].decode("utf-8", "replace")}
        return status, data, info

    async def get_json(self, url: str) -> tuple[int, dict[str, Any]]:
        async with self._session.get(url) as resp:
            raw = await resp.read()
            return resp.status, (json.loads(raw) if raw else {})

    async def close(self) -> None:
        await self._session.close()


class SpanWriter:
    """Buffered JSONL writer (flushed off the request path once per second)."""

    def __init__(self, path: str | None) -> None:
        self.path = path
        self._buf: list[dict[str, Any]] = []
        self._task: asyncio.Task | None = None

    def add(self, rec: dict[str, Any]) -> None:
        if self.path:
            self._buf.append(rec)

    def start(self) -> None:
        if self.path and self._task is None:
            self._task = asyncio.get_running_loop().create_task(self._run())

    def flush(self) -> None:
        if not self.path or not self._buf:
            return
        buf, self._buf = self._buf, []
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write("".join(json.dumps(r, separators=(",", ":"), default=str) + "\n" for r in buf))

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            try:
                self.flush()
            except OSError:
                pass


def now_ms() -> float:
    return time.time() * 1000.0


PeerCheck = Callable[[Any], Any]
