from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from .decision_signing import verify_decision_headers


class PDPUnavailable(RuntimeError):
    pass


class InvalidPDPDecision(RuntimeError):
    pass


def authorize_or_fail_closed(
    *,
    pdp_url: str,
    signed_request: dict[str, Any],
    pdp_public_key: str | Path,
    timeout_seconds: float = 1.0,
) -> dict[str, Any]:
    """PEP-side example: verify the signed PDP response before enforcement."""

    try:
        response = httpx.post(
            f"{pdp_url.rstrip('/')}/v1/authorize",
            json=signed_request,
            timeout=timeout_seconds,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise PDPUnavailable("PDP unavailable; deny operation") from exc

    body = response.json()
    if not verify_decision_headers(
        body, response.headers, pdp_public_key, expected_request_hash=str(signed_request.get("request_hash", ""))
    ):
        raise InvalidPDPDecision("PDP decision signature or digest is invalid")
    if body.get("request_id") != signed_request.get("request_id"):
        raise InvalidPDPDecision("PDP decision is not bound to the current request_id")
    if body.get("trace_id") != signed_request.get("trace_id"):
        raise InvalidPDPDecision("PDP decision is not bound to the current trace_id")
    if body.get("decision") not in {"ALLOW", "ALLOW_WITH_OBLIGATIONS"}:
        raise PermissionError(f"operation not authorized: {body.get('decision')} ({body.get('reason')})")
    return body
