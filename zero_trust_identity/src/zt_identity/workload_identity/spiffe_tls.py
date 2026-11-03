"""SPIFFE Workload API client + mTLS contexts with in-process SVID rotation.

The workload obtains its X.509-SVID, private key and trust bundle from the
local SPIRE Agent through the Workload API (py-spiffe X509Source, a streaming
gRPC watch). On every update pushed by the Workload API the new SVID is loaded
into the *same* ssl.SSLContext objects used by the running servers/clients, so
new handshakes present the new certificate. Python's ssl module can only load
a certificate/key from a file, so the material is written to a per-process
tmpfs directory (/dev/shm, mode 0700/0600) inside the workload's own container;
it is never written to a persistent volume.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import ssl
import threading
import time
import weakref
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives import serialization
from spiffe import TrustDomain, X509Source

from ..events import EventLog

TLS_MIN = ssl.TLSVersion.TLSv1_3


class ResumingClientContext(ssl.SSLContext):
    """Client context that offers a cached TLS session when resumption is on.

    asyncio (and therefore aiohttp) never passes `session=` to wrap_bio, so
    client-side session resumption is implemented by overriding wrap_bio.
    """

    resume_sessions: bool = False

    def __init__(self, *args, **kwargs) -> None:  # noqa: D401 - ssl.SSLContext uses __new__
        super().__init__()
        self._sessions: dict[str, ssl.SSLSession] = {}
        self._lock = threading.Lock()

    def wrap_bio(self, incoming, outgoing, server_side=False, server_hostname=None, session=None):
        if self.resume_sessions and not server_side and session is None and server_hostname:
            with self._lock:
                session = self._sessions.get(server_hostname)
        return super().wrap_bio(incoming, outgoing, server_side=server_side,
                                server_hostname=server_hostname, session=session)

    def remember_session(self, server_hostname: str, session: ssl.SSLSession | None) -> None:
        if self.resume_sessions and session is not None and server_hostname:
            with self._lock:
                self._sessions[server_hostname] = session

    def forget_sessions(self) -> None:
        with self._lock:
            self._sessions.clear()


class WorkloadIdentity:
    def __init__(
        self,
        *,
        trust_domain: str,
        socket_path: str | None = None,
        events: EventLog | None = None,
        timeout_s: float = 120.0,
    ) -> None:
        self.trust_domain = trust_domain
        self.events = events or EventLog(None)
        self._contexts: "weakref.WeakSet[ssl.SSLContext]" = weakref.WeakSet()
        self._listeners: list[Callable[[], None]] = []
        self._lock = threading.RLock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self.generation = 0
        self._dir = Path("/dev/shm") / f"citi-svid-{os.getpid()}"
        self._dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self._dir, 0o700)
        t0 = time.monotonic()
        self.events.emit("svid_fetch_start")
        self.source = X509Source(
            socket_path=socket_path or os.environ.get("SPIFFE_ENDPOINT_SOCKET"),
            timeout_in_seconds=timeout_s,
        )
        self.time_to_first_svid_s = time.monotonic() - t0
        self._write_material()
        self.events.emit(
            "svid_ready",
            spiffe_id=self.spiffe_id,
            serial=self.cert_serial,
            not_after=self.not_after_iso,
            time_to_first_svid_s=round(self.time_to_first_svid_s, 4),
        )
        self.source.subscribe_for_updates(self._on_update_from_watcher)

    # ------------------------------------------------------------------
    @property
    def svid(self):
        return self.source.svid

    @property
    def spiffe_id(self) -> str:
        return str(self.svid.spiffe_id)

    @property
    def cert_serial(self) -> str:
        return format(self.svid.leaf.serial_number, "x")

    @property
    def not_after_iso(self) -> str:
        return self.svid.leaf.not_valid_after_utc.isoformat()

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def add_listener(self, callback: Callable[[], None]) -> None:
        self._listeners.append(callback)

    # ------------------------------------------------------------------
    def _write_material(self) -> None:
        with self._lock:
            svid = self.source.svid
            bundle = self.source.get_bundle_for_trust_domain(TrustDomain(self.trust_domain))
            if bundle is None:
                raise RuntimeError(f"no X.509 bundle for trust domain {self.trust_domain}")
            gen_dir = self._dir / f"g{self.generation + 1}"
            gen_dir.mkdir(mode=0o700, exist_ok=True)
            chain = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in svid.cert_chain)
            key = svid.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            roots = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in bundle.x509_authorities)
            for name, data in (("svid.pem", chain), ("svid.key", key), ("bundle.pem", roots)):
                fd = os.open(gen_dir / name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
            old = self._dir / f"g{self.generation}"
            self.generation += 1
            self.cert_path = str(gen_dir / "svid.pem")
            self.key_path = str(gen_dir / "svid.key")
            self.bundle_path = str(gen_dir / "bundle.pem")
            if old.exists():
                shutil.rmtree(old, ignore_errors=True)

    def _apply(self, ctx: ssl.SSLContext) -> None:
        ctx.load_cert_chain(self.cert_path, self.key_path)
        ctx.load_verify_locations(cafile=self.bundle_path)

    def _on_update_from_watcher(self) -> None:
        # Runs on py-spiffe's watcher thread; hand the reload to the event loop
        # so SSLContext objects are only mutated on the thread that uses them.
        if self._loop is not None and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._rotate)
        else:
            self._rotate()

    def _rotate(self) -> None:
        old_serial = getattr(self, "_last_serial", None)
        self._write_material()
        with self._lock:
            for ctx in list(self._contexts):
                self._apply(ctx)
        new_serial = self.cert_serial
        self._last_serial = new_serial
        self.events.emit(
            "svid_rotated",
            spiffe_id=self.spiffe_id,
            old_serial=old_serial,
            serial=new_serial,
            not_after=self.not_after_iso,
            generation=self.generation,
        )
        for cb in list(self._listeners):
            try:
                cb()
            except Exception as exc:  # pragma: no cover - listener bugs must not stop rotation
                self.events.emit("svid_listener_error", error=repr(exc))

    # ------------------------------------------------------------------
    def server_context(self, *, session_tickets: bool = True) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = TLS_MIN
        ctx.verify_mode = ssl.CERT_REQUIRED          # client certificate is mandatory
        if not session_tickets:
            ctx.num_tickets = 0                      # disables TLS 1.3 resumption
        self._apply(ctx)
        self._contexts.add(ctx)
        self._last_serial = self.cert_serial
        return ctx

    def client_context(self, *, resume_sessions: bool = False) -> ResumingClientContext:
        ctx = ResumingClientContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = TLS_MIN
        # SPIFFE IDs are URI SANs, not DNS names: hostname checking is replaced
        # by an explicit SPIFFE-ID authorization right after the handshake
        # (see connector.SpiffeConnector). Chain/validity checks stay on.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.resume_sessions = resume_sessions
        self._apply(ctx)
        self._contexts.add(ctx)
        self._last_serial = self.cert_serial
        return ctx

    def close(self) -> None:
        try:
            self.source.close()
        finally:
            shutil.rmtree(self._dir, ignore_errors=True)
