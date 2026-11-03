"""RFC 9421 HTTP Message Signatures + RFC 9530 Content-Digest for agent requests.

Signature base construction, the ecdsa-p256-sha256 algorithm (raw r||s) and
created/expires checks come from the `http-message-signatures` library;
Content-Digest serialization uses `http-sfv` (RFC 8941 structured fields).
This module adds the application profile the library deliberately leaves to
callers: the mandatory covered components, tag, algorithm, keyid, nonce and
maximum validity window.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

import http_sfv
from http_message_signatures import (
    HTTPMessageSigner,
    HTTPMessageVerifier,
    HTTPSignatureKeyResolver,
    algorithms,
)
from http_message_signatures.exceptions import HTTPMessageSignaturesException, InvalidSignature

SIG_LABEL = "zt-agent"
SIG_TAG = "citi-p3-agent/v1"
ALGORITHM = algorithms.ECDSA_P256_SHA256
MAX_WINDOW_S = 60
DEFAULT_WINDOW_S = 30

H_REQUEST_ID = "x-zt-request-id"
H_WORKFLOW_RUN_ID = "x-zt-workflow-run-id"
H_AGENT_ID = "x-zt-agent-id"
H_WORKLOAD_ID = "x-zt-workload-id"
H_AGENT_CERT = "x-zt-agent-cert"
H_CONTENT_DIGEST = "content-digest"

H_MCP_SESSION = "mcp-session-id"
H_MCP_PROTOCOL = "mcp-protocol-version"

# Previous-round HTTP profile (unchanged).
REQUIRED_COMPONENTS = (
    "@method", "@authority", "@target-uri", H_CONTENT_DIGEST,
    H_REQUEST_ID, H_WORKFLOW_RUN_ID, H_AGENT_ID, H_WORKLOAD_ID,
)


class SignatureRejected(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def content_digest(body: bytes) -> str:
    d = http_sfv.Dictionary()
    d["sha-256"] = hashlib.sha256(body).digest()
    return str(d)


def check_content_digest(header_value: str | None, body: bytes) -> None:
    if not header_value:
        raise SignatureRejected("missing_content_digest")
    try:
        d = http_sfv.Dictionary()
        d.parse(header_value.encode("ascii"))
        claimed = d["sha-256"].value
    except Exception as exc:
        raise SignatureRejected("malformed_content_digest") from exc
    if not isinstance(claimed, bytes) or not hmac.compare_digest(claimed, hashlib.sha256(body).digest()):
        raise SignatureRejected("content_digest_mismatch")


class _Msg:
    """Request view in the shape the library's component resolver expects."""

    def __init__(self, method: str, url: str, headers: Mapping[str, str]) -> None:
        self.method = method
        self.url = url
        self.headers = dict(headers)


class _StaticKey(HTTPSignatureKeyResolver):
    def __init__(self, key_id: str, *, private_key=None, public_key=None) -> None:
        self.key_id = key_id
        self._private = private_key
        self._public = public_key

    def resolve_private_key(self, key_id: str):
        if key_id != self.key_id:
            raise SignatureRejected("keyid_mismatch")
        return self._private

    def resolve_public_key(self, key_id: str):
        if key_id != self.key_id:
            raise SignatureRejected("keyid_mismatch")
        return self._public


def sign_components(
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    covered: Sequence[str],
    private_key,
    key_id: str,
    window_s: int = DEFAULT_WINDOW_S,
) -> dict[str, str]:
    """Sign an already-final request (headers + covered component list).

    Returns only the two signature headers; callers attach them to the very
    request object that is sent (e.g. inside an httpx.Auth flow), so the signed
    body/headers are exactly what goes on the wire.
    """
    msg = _Msg(method, url, headers)
    created = _dt.datetime.now()
    signer = HTTPMessageSigner(signature_algorithm=ALGORITHM, key_resolver=_StaticKey(key_id, private_key=private_key))
    signer.sign(
        msg,
        key_id=key_id,
        created=created,
        expires=created + _dt.timedelta(seconds=window_s),
        nonce=secrets.token_urlsafe(16),
        label=SIG_LABEL,
        tag=SIG_TAG,
        include_alg=True,
        covered_component_ids=tuple(covered),
    )
    return {"Signature-Input": msg.headers["Signature-Input"], "Signature": msg.headers["Signature"]}


def sign_request(
    *,
    method: str,
    url: str,
    body: bytes,
    private_key,
    key_id: str,
    agent_id: str,
    workload_id: str,
    request_id: str,
    workflow_run_id: str,
    cert_header: str,
    window_s: int = DEFAULT_WINDOW_S,
) -> dict[str, str]:
    """Previous-round HTTP profile (route calls and the HTTP tool control set)."""
    headers = {
        "Content-Type": "application/json",
        "Content-Digest": content_digest(body),
        "X-ZT-Request-Id": request_id,
        "X-ZT-Workflow-Run-Id": workflow_run_id,
        "X-ZT-Agent-Id": agent_id,
        "X-ZT-Workload-Id": workload_id,
        "X-ZT-Agent-Cert": cert_header,
    }
    headers.update(sign_components(method=method, url=url, headers=headers, covered=REQUIRED_COMPONENTS,
                                   private_key=private_key, key_id=key_id, window_s=window_s))
    return headers


@dataclass(frozen=True)
class SignatureResult:
    key_id: str
    nonce: str
    created: int
    expires: int
    covered: tuple[str, ...]


def verify_request_signature(
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    public_key,
    key_id: str,
    required: Sequence[str] = REQUIRED_COMPONENTS,
) -> SignatureResult:
    msg = _Msg(method, url, headers)
    verifier = HTTPMessageVerifier(signature_algorithm=ALGORITHM, key_resolver=_StaticKey(key_id, public_key=public_key))
    try:
        results = verifier.verify(msg, expect_tag=SIG_TAG, expect_label=SIG_LABEL,
                                  max_age=_dt.timedelta(seconds=MAX_WINDOW_S))
    except SignatureRejected:
        raise
    except (InvalidSignature, HTTPMessageSignaturesException) as exc:
        raise SignatureRejected("invalid_signature", str(exc)[:200]) from exc
    if len(results) != 1:
        raise SignatureRejected("signature_count")
    res = results[0]
    params: dict[str, Any] = dict(res.parameters)
    covered = tuple(k.strip('"') for k in res.covered_components.keys() if k != '"@signature-params"')
    missing = [c for c in required if c not in covered]
    if missing:
        raise SignatureRejected("uncovered_components", ",".join(missing))
    if params.get("alg") != ALGORITHM.algorithm_id:
        raise SignatureRejected("algorithm_not_allowed")
    if params.get("keyid") != key_id:
        raise SignatureRejected("keyid_mismatch")
    for required in ("created", "expires", "nonce"):
        if required not in params:
            raise SignatureRejected(f"missing_{required}")
    created, expires = int(params["created"]), int(params["expires"])
    if expires <= created or expires - created > MAX_WINDOW_S:
        raise SignatureRejected("signature_window_invalid")
    return SignatureResult(key_id=key_id, nonce=str(params["nonce"]), created=created, expires=expires, covered=covered)


def mcp_required_components(*, has_body: bool, is_tools_call: bool, header_names: set[str]) -> tuple[str, ...]:
    """Coverage policy for MCP Streamable HTTP requests (scheme B).

    Every MCP HTTP request (initialize, notifications, tools/list, tools/call,
    DELETE, GET) is signed. The JSON-RPC method, id, tool name, arguments and
    _meta are covered through Content-Digest of the exact serialized body. MCP
    headers that steer routing/interpretation are covered whenever present; the
    workflow binding exists only for tools/call (control messages carry no
    workflow and none is invented).
    """
    req = ["@method", "@authority", "@target-uri", H_REQUEST_ID, H_AGENT_ID, H_WORKLOAD_ID]
    if has_body:
        req.append(H_CONTENT_DIGEST)
    if is_tools_call:
        req.append(H_WORKFLOW_RUN_ID)
    for h in (H_MCP_SESSION, H_MCP_PROTOCOL):
        if h in header_names:
            req.append(h)
    return tuple(req)
