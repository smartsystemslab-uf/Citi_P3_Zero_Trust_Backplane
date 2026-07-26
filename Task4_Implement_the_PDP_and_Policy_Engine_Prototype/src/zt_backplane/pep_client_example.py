"""Minimal PEP-side client example.

TODO(CITI-PEP): Task 3-generated PEP wrappers should call this contract before
invoking an agent, MCP tool, banking API, database operation, or ledger write.
"""

from __future__ import annotations

from typing import Any

import httpx


class PDPUnavailable(RuntimeError):
    pass


def authorize_or_fail_closed(
    *,
    pdp_url: str,
    subject: str,
    resource: str,
    action: str,
    context: dict[str, Any],
    parameters: dict[str, Any] | None = None,
    timeout_seconds: float = 1.0,
) -> dict[str, Any]:
    payload = {
        "subject": subject,
        "resource": resource,
        "action": action,
        "context": context,
        "parameters": parameters or {},
    }
    try:
        response = httpx.post(f"{pdp_url.rstrip('/')}/v1/authorize", json=payload, timeout=timeout_seconds)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        # Task 4 has no Permit Lease yet. Therefore a PDP failure must not be
        # converted into an allow. Task 5 will add bounded lease fallback.
        raise PDPUnavailable("PDP unavailable; deny operation") from exc

    decision = response.json()
    if decision["decision"] not in {"ALLOW", "ALLOW_WITH_OBLIGATIONS"}:
        raise PermissionError(f"operation not authorized: {decision['decision']} ({decision['reason']})")
    return decision
