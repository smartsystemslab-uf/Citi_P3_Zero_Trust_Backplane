"""aiohttp connector that authorizes the server's SPIFFE ID after the TLS
handshake and before any request bytes are written, plus connection
instrumentation (new/reused connection, handshake time, session resumption).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

import aiohttp

from ..identity import AuthenticationError
from .svid import PeerIdentityCache


class PeerIdentityRejected(aiohttp.ClientConnectionError):
    pass


@dataclass
class ConnectionStats:
    created: int = 0
    reused: int = 0
    resumed: int = 0
    full_handshakes: int = 0
    create_ms: list[float] = field(default_factory=list)       # TCP connect + TLS handshake
    create_ms_resumed: list[float] = field(default_factory=list)
    create_ms_full: list[float] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        return {
            "created": self.created, "reused": self.reused,
            "resumed": self.resumed, "full_handshakes": self.full_handshakes,
            "create_ms": list(self.create_ms), "create_ms_resumed": list(self.create_ms_resumed),
            "create_ms_full": list(self.create_ms_full),
        }


class SpiffeConnector(aiohttp.TCPConnector):
    def __init__(
        self,
        *args: Any,
        trust_domain: str,
        authorize_server: Callable[[str, str], bool],
        stats: ConnectionStats | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._peer_cache = PeerIdentityCache(trust_domain)
        self._authorize_server = authorize_server
        self.stats = stats or ConnectionStats()
        self.last_ssl_object: dict[str, Any] = {}     # host -> SSLObject of the newest connection

    async def _wrap_create_connection(self, *args: Any, **kwargs: Any):
        started = time.perf_counter()
        transport, proto = await super()._wrap_create_connection(*args, **kwargs)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        ssl_obj = transport.get_extra_info("ssl_object")
        if kwargs.get("ssl") and ssl_obj is not None:
            host = str(kwargs.get("server_hostname") or getattr(kwargs.get("req"), "host", "") or "")
            try:
                ident = self._peer_cache.identity_for(ssl_obj)
            except AuthenticationError as exc:
                transport.close()
                raise PeerIdentityRejected(f"server SVID invalid: {exc}") from exc
            if not self._authorize_server(host, ident.spiffe_id):
                transport.close()
                raise PeerIdentityRejected(f"unexpected server SPIFFE ID {ident.spiffe_id} for {host}")
            self.last_ssl_object[host] = ssl_obj
            self.stats.created += 1
            self.stats.create_ms.append(elapsed_ms)
            if ssl_obj.session_reused:
                self.stats.resumed += 1
                self.stats.create_ms_resumed.append(elapsed_ms)
            else:
                self.stats.full_handshakes += 1
                self.stats.create_ms_full.append(elapsed_ms)
        else:
            self.stats.created += 1
            self.stats.create_ms.append(elapsed_ms)
        return transport, proto
