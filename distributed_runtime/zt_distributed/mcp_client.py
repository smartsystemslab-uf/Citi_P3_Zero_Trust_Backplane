"""Agent-side MCP client: official SDK ClientSession over Streamable HTTP(S).

Layers (bottom-up):
  SpiffeHTTPTransport  httpx transport on an httpcore pool whose network backend
                       authorizes the server's SPIFFE ID right after the TLS
                       handshake (before any request bytes), records full vs
                       resumed handshakes, applies the connection policy
                       (reuse / new / new-resume) and recycles the pool when the
                       workload's SVID rotates.
  AgentSigningAuth     httpx.Auth used by the SDK's own httpx client: adds the
                       correlation headers and signs the FINAL serialized request
                       (RFC 9421 + RFC 9530) with the current agent key -- a fresh
                       signature/nonce for every HTTP request the SDK sends.
  McpToolSession       one MCP session per agent workload (never shared between
                       agents): initialize -> notifications/initialized ->
                       tools/list, then tools/call with correlation in `_meta`.
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from datetime import timedelta
from typing import Any, Callable

import httpcore
import httpx
from mcp.shared.exceptions import McpError
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client

from zt_identity.agent_identity.client import AgentCredentialManager
from zt_identity.agent_identity.httpsig import (
    H_MCP_PROTOCOL, H_MCP_SESSION, content_digest, mcp_required_components, sign_components,
)
from zt_identity.events import EventLog
from zt_identity.identity import AuthenticationError
from zt_identity.workload_identity.connector import ConnectionStats, PeerIdentityRejected
from zt_identity.workload_identity.spiffe_tls import WorkloadIdentity
from zt_identity.workload_identity.svid import PeerIdentityCache

from .mcp_server import K_ATTEMPT, K_CALL_ID, K_IDEMPOTENCY, K_REQUEST_ID, K_TRACE_ID, K_WORKFLOW_RUN_ID

try:  # httpcore >= 1.0
    from httpcore import AnyIOBackend
except ImportError:  # pragma: no cover
    from httpcore._backends.anyio import AnyIOBackend


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------
class _VerifiedStream(httpcore.AsyncNetworkStream):
    def __init__(self, inner: httpcore.AsyncNetworkStream, owner: "SpiffeHTTPTransport", host: str, t0: float) -> None:
        self._s, self._owner, self._host, self._t0 = inner, owner, host, t0

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self._s.read(max_bytes, timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self._s.write(buffer, timeout)

    async def aclose(self) -> None:
        await self._s.aclose()

    def get_extra_info(self, info: str) -> Any:
        return self._s.get_extra_info(info)

    async def start_tls(self, ssl_context, server_hostname: str | None = None, timeout: float | None = None):
        new = await self._s.start_tls(ssl_context, server_hostname, timeout)
        ssl_obj = new.get_extra_info("ssl_object")
        try:
            ident = self._owner.peer_cache.identity_for(ssl_obj)
        except AuthenticationError as exc:
            await new.aclose()
            raise PeerIdentityRejected(f"server SVID invalid: {exc}") from exc
        if self._owner.expected.get(self._host) != ident.spiffe_id:
            await new.aclose()
            raise PeerIdentityRejected(f"unexpected server SPIFFE ID {ident.spiffe_id} for {self._host}")
        ms = (time.perf_counter() - self._t0) * 1000
        st = self._owner.stats
        st.created += 1
        st.create_ms.append(ms)
        if ssl_obj.session_reused:
            st.resumed += 1
            st.create_ms_resumed.append(ms)
        else:
            st.full_handshakes += 1
            st.create_ms_full.append(ms)
        self._owner.last_ssl_object[self._host] = ssl_obj
        return _VerifiedStream(new, self._owner, self._host, self._t0)


class _VerifyingBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, owner: "SpiffeHTTPTransport") -> None:
        self._inner = AnyIOBackend()
        self._owner = owner

    async def connect_tcp(self, host: str, port: int, timeout: float | None = None, local_address: str | None = None,
                          socket_options: Any = None) -> httpcore.AsyncNetworkStream:
        t0 = time.perf_counter()
        s = await self._inner.connect_tcp(host, port, timeout=timeout, local_address=local_address,
                                          socket_options=socket_options)
        return _VerifiedStream(s, self._owner, host, t0)

    async def connect_unix_socket(self, path: str, timeout: float | None = None, socket_options: Any = None):
        return await self._inner.connect_unix_socket(path, timeout=timeout, socket_options=socket_options)

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class SpiffeHTTPTransport(httpx.AsyncHTTPTransport):
    """httpx transport with SPIFFE server authorization and an explicit connection policy."""

    def __init__(self, *, identity: WorkloadIdentity, trust_domain: str, expected_servers: dict[str, str],
                 conn_mode: str = "reuse", limit: int = 1024) -> None:
        super().__init__(http1=True, http2=False, retries=0)
        self.identity = identity
        self.conn_mode = conn_mode
        self.limit = limit
        self.expected = dict(expected_servers)
        self.peer_cache = PeerIdentityCache(trust_domain)
        self.stats = ConnectionStats()
        self.last_ssl_object: dict[str, Any] = {}
        self.pools_replaced = 0
        self.ctx = identity.client_context(resume_sessions=conn_mode == "new-resume")
        self._pool = self._make_pool()
        identity.add_listener(self._on_svid_rotation)

    def _make_pool(self) -> httpcore.AsyncConnectionPool:
        keep = self.conn_mode == "reuse"
        return httpcore.AsyncConnectionPool(
            ssl_context=self.ctx, max_connections=self.limit,
            max_keepalive_connections=self.limit if keep else 0, keepalive_expiry=60.0 if keep else 0.0,
            http1=True, http2=False, retries=0, network_backend=_VerifyingBackend(self))

    def _on_svid_rotation(self) -> None:
        # New handshakes must present the new SVID: fresh pool; in-flight
        # requests finish on the old pool, which is closed afterwards.
        old = self._pool
        self._pool = self._make_pool()
        self.pools_replaced += 1
        if self.ctx is not None:
            self.ctx.forget_sessions()

        async def _close_later() -> None:
            await asyncio.sleep(30)
            await old.aclose()

        try:
            asyncio.get_running_loop().create_task(_close_later())
        except RuntimeError:
            pass

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self.conn_mode == "new-resume" and self.ctx is not None:
            so = self.last_ssl_object.get(request.url.host)
            if so is not None and so.session is not None and so.session.has_ticket:
                self.ctx.remember_session(request.url.host, so.session)
        return await super().handle_async_request(request)


# ---------------------------------------------------------------------------
# per-request authentication material (inside the SDK's httpx request flow)
# ---------------------------------------------------------------------------
def _rpc_info(request: httpx.Request) -> tuple[str | None, dict[str, Any]]:
    if not request.content:
        return None, {}
    try:
        msg = json.loads(request.content)
    except ValueError:
        return None, {}
    if not isinstance(msg, dict):
        return None, {}
    method = msg.get("method")
    meta = ((msg.get("params") or {}).get("_meta") or {}) if method == "tools/call" else {}
    return method, meta


class AgentAuth(httpx.Auth):
    """Correlation headers (base of AgentSigningAuth; the agent name header is informational
    only -- the identity is the verified agent certificate bound to the workload SVID)."""

    requires_request_body = True

    def __init__(self, agent_id: str, stats: dict[str, Any]) -> None:
        self.agent_id = agent_id
        self.stats = stats

    def _prepare(self, request: httpx.Request) -> tuple[str | None, str]:
        method, meta = _rpc_info(request)
        rid = str(meta.get(K_REQUEST_ID) or uuid.uuid4())
        request.headers["X-ZT-Agent-Id"] = self.agent_id
        request.headers["X-ZT-Request-Id"] = rid
        if method == "tools/call" and meta.get(K_WORKFLOW_RUN_ID):
            request.headers["X-ZT-Workflow-Run-Id"] = str(meta[K_WORKFLOW_RUN_ID])
        key = method or request.method
        self.stats[key] = self.stats.get(key, 0) + 1
        return method, rid

    def auth_flow(self, request: httpx.Request):
        self._prepare(request)
        yield request

    last_reject: dict[str, Any] | None = None

    async def async_auth_flow(self, request: httpx.Request):
        # Same as httpx.Auth.async_auth_flow, plus: when the PEP rejects a message
        # (401/403) remember its reason code. The SDK raises on such responses and
        # does not expose the body, but the agent needs the reason to apply the
        # same re-enrollment rule as the HTTP path (agent_cert_revoked only).
        if self.requires_request_body:
            await request.aread()
        flow = self.auth_flow(request)
        response = yield next(flow)
        if response.status_code in (401, 403):
            await response.aread()
            try:
                reason = str(json.loads(response.content).get("reason", ""))
            except (ValueError, AttributeError):
                reason = ""
            self.last_reject = {"status": response.status_code, "reason": reason, "t": time.monotonic()}


class AgentSigningAuth(AgentAuth):
    """RFC 9421 signature over the exact bytes/headers the SDK sends."""

    def __init__(self, agent_id: str, stats: dict[str, Any], creds: AgentCredentialManager,
                 workload_id: Callable[[], str], sign_times: dict[str, float]) -> None:
        super().__init__(agent_id, stats)
        self.creds = creds
        self.workload_id = workload_id
        self.sign_times = sign_times

    def auth_flow(self, request: httpx.Request):
        t0 = time.perf_counter_ns()
        method, rid = self._prepare(request)
        cred = self.creds.cred
        if cred is None:
            raise RuntimeError("agent credential not ready")
        request.headers["X-ZT-Workload-Id"] = self.workload_id()
        request.headers["X-ZT-Agent-Cert"] = cred.cert_header
        if request.content:
            request.headers["Content-Digest"] = content_digest(request.content)
        names = {k.lower() for k in request.headers.keys()}
        covered = mcp_required_components(has_body=bool(request.content), is_tools_call=method == "tools/call",
                                          header_names=names)
        hdrs = {k: v for k, v in request.headers.items()}
        request.headers.update(sign_components(method=request.method, url=str(request.url), headers=hdrs,
                                               covered=covered, private_key=cred.key, key_id=cred.key_id))
        self.sign_times[rid] = (time.perf_counter_ns() - t0) / 1e6
        yield request


# ---------------------------------------------------------------------------
# session
# ---------------------------------------------------------------------------
class McpToolSession:
    def __init__(self, *, url: str, agent_id: str, transport: SpiffeHTTPTransport, auth: httpx.Auth,
                 events: EventLog, protocol_stats: dict[str, Any], read_timeout_s: float = 60.0) -> None:
        self.url = url
        self.agent_id = agent_id
        self.transport = transport
        self.auth = auth
        self.events = events
        self.protocol_stats = protocol_stats
        self.read_timeout = timedelta(seconds=read_timeout_s)
        self.session: ClientSession | None = None
        self.server_info: dict[str, Any] = {}
        self.tools: list[str] = []
        self.connects = 0
        self.reconnect_reasons: dict[str, int] = {}
        self.last_connect: dict[str, Any] = {}
        self._stop: asyncio.Event | None = None
        self._task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        # one httpx client per agent workload (carries this agent's credentials only)
        self.http = httpx.AsyncClient(transport=transport, auth=auth, timeout=httpx.Timeout(read_timeout_s),
                                      follow_redirects=False, trust_env=False)

    async def _runner(self, ready: asyncio.Future) -> None:
        t0 = time.perf_counter()
        try:
            async with streamable_http_client(self.url, http_client=self.http, terminate_on_close=True) as (r, w, sid):
                async with ClientSession(r, w, client_info=types.Implementation(
                        name=f"citi-p3-agent:{self.agent_id}", version="1.0.0"),
                        read_timeout_seconds=self.read_timeout) as session:
                    t1 = time.perf_counter()
                    init = await session.initialize()
                    t2 = time.perf_counter()
                    listed = await session.list_tools()
                    t3 = time.perf_counter()
                    self.session = session
                    self.server_info = {"protocolVersion": init.protocolVersion,
                                        "serverInfo": init.serverInfo.model_dump(), "session_id_prefix": (sid() or "")[:8]}
                    self.session_id_full = sid()       # kept in memory only (never logged)
                    self.tools = [t.name for t in listed.tools]
                    self.last_connect = {"transport_open_ms": round((t1 - t0) * 1000, 3),
                                         "initialize_ms": round((t2 - t1) * 1000, 3),
                                         "tools_list_ms": round((t3 - t2) * 1000, 3),
                                         "tools": len(self.tools), **self.server_info}
                    ready.set_result(True)
                    assert self._stop is not None
                    await self._stop.wait()
        except BaseException as exc:  # noqa: BLE001 - surface any transport failure to the waiter
            if not ready.done():
                ready.set_exception(exc if isinstance(exc, Exception) else RuntimeError(repr(exc)))
            else:
                self.events.emit("mcp_session_ended", error=f"{type(exc).__name__}: {exc}"[:300])
        finally:
            self.session = None

    async def connect(self, reason: str) -> dict[str, Any]:
        async with self._lock:
            return await self._connect_locked(reason)

    async def _connect_locked(self, reason: str) -> dict[str, Any]:
        await self._close_locked()
        self._stop = asyncio.Event()
        ready: asyncio.Future = asyncio.get_running_loop().create_future()
        t0 = time.perf_counter()
        self._task = asyncio.create_task(self._runner(ready))
        await ready
        self.connects += 1
        self.reconnect_reasons[reason] = self.reconnect_reasons.get(reason, 0) + 1
        info = {**self.last_connect, "connect_total_ms": round((time.perf_counter() - t0) * 1000, 3),
                "reason": reason, "connects": self.connects}
        self.events.emit("mcp_session_ready", **info)
        return info

    async def _close_locked(self) -> None:
        if self._task is not None:
            assert self._stop is not None
            self._stop.set()
            try:
                await asyncio.wait_for(self._task, timeout=15)
            except Exception:
                self._task.cancel()
            self._task = None

    async def call(self, name: str, arguments: dict[str, Any], meta: dict[str, Any]) -> types.CallToolResult:
        session = self.session
        if session is None:
            async with self._lock:              # concurrent callers share one re-initialization
                if self.session is None:
                    await self._connect_locked("lazy_reconnect")
                session = self.session
            assert session is not None
        try:
            return await session.call_tool(name, arguments, read_timeout_seconds=self.read_timeout, meta=meta)
        except McpError as exc:
            # HTTP 404 on a session request = the server no longer knows the session
            # (spec: the client MUST start a new session). This call stays failed (no
            # retry); the next call re-initializes.
            if "Session terminated" in str(exc.error.message) and self.session is session:
                self.session = None
                self.events.emit("mcp_session_terminated_by_server")
            raise

    def status(self) -> dict[str, Any]:
        return {"connected": self.session is not None, "connects": self.connects,
                "reconnect_reasons": self.reconnect_reasons, "last_connect": self.last_connect,
                "tools_discovered": self.tools, "protocol_messages_sent": dict(self.protocol_stats),
                "connections": {k: v for k, v in self.transport.stats.snapshot().items() if not isinstance(v, list)},
                "pools_replaced": self.transport.pools_replaced}


def call_meta(*, request_id: str, workflow_run_id: str, trace_id: str, idempotency_key: str, call_id: str,
              attempt: int = 1) -> dict[str, Any]:
    return {K_REQUEST_ID: request_id, K_WORKFLOW_RUN_ID: workflow_run_id, K_TRACE_ID: trace_id,
            K_IDEMPOTENCY: idempotency_key, K_CALL_ID: call_id, K_ATTEMPT: attempt}
