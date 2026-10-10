import json
from collections.abc import Mapping
from typing import Any


REQUEST_FIELDS = {
    "caller_runtime_id",
    "target_tool",
    "nonce",
    "timestamp",
}


def canonical_request_payload(payload: Mapping[str, Any]) -> bytes:
    if set(payload.keys()) != REQUEST_FIELDS:
        raise ValueError(
            "Signed request payload must contain exactly "
            "caller_runtime_id, target_tool, nonce, and timestamp"
        )

    for field in REQUEST_FIELDS:
        value = payload[field]

        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be a non-empty string")

        if value != value.strip():
            raise ValueError(f"{field} cannot contain surrounding whitespace")

    return json.dumps(
        dict(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")