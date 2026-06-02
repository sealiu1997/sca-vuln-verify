"""HMAC-SHA256 signing helpers for SCA OpenAPI."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
import uuid
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import quote


SIGNATURE_VERSION = "1.0"
SIGNATURE_METHOD = "HMAC-SHA256"


def _stringify_query_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _iter_query_items(params: Mapping[str, Any] | Iterable[tuple[str, Any]] | None) -> list[tuple[str, str]]:
    if not params:
        return []

    if hasattr(params, "multi_items"):
        raw_items = list(params.multi_items())  # type: ignore[attr-defined]
    elif isinstance(params, Mapping):
        raw_items = list(params.items())
    else:
        raw_items = list(params)

    items: list[tuple[str, str]] = []
    for key, value in raw_items:
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            for item in value:
                if item is not None:
                    items.append((str(key), _stringify_query_value(item)))
        else:
            items.append((str(key), _stringify_query_value(value)))
    return items


def canonicalize_query_string(params: Mapping[str, Any] | Iterable[tuple[str, Any]] | None) -> str:
    """Build the canonical query string required by the OpenAPI signing spec."""

    items = sorted(_iter_query_items(params), key=lambda item: (item[0], item[1]))
    return "&".join(
        f"{quote(key, safe='-_.~')}={quote(value, safe='-_.~')}" for key, value in items
    )


def hash_payload(body: bytes | str | None, *, is_multipart: bool = False) -> str:
    """Return the lowercase SHA256 hex digest for a request body."""

    if body is None:
        payload = b""
    elif isinstance(body, str):
        payload = body.encode("utf-8")
    else:
        payload = bytes(body)

    if is_multipart:
        payload = payload[: 4 * 1024]

    return hashlib.sha256(payload).hexdigest().lower()


def build_string_to_sign(
    *,
    timestamp: str | int,
    method: str,
    canonical_query_string: str,
    hashed_payload: str,
) -> str:
    return f"{timestamp}\n{method.upper()}\n{canonical_query_string}\n{hashed_payload}"


def sign_string(secret_key: str, string_to_sign: str) -> str:
    digest = hmac.new(secret_key.encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha256)
    return base64.b64encode(digest.digest()).decode("ascii")


def build_auth_headers(
    *,
    access_key: str,
    secret_key: str,
    method: str,
    params: Mapping[str, Any] | Iterable[tuple[str, Any]] | None = None,
    body: bytes | str | None = None,
    timestamp: str | int | None = None,
    nonce: str | None = None,
    is_multipart: bool = False,
) -> dict[str, str]:
    """Build SCA OpenAPI authentication headers."""

    current_timestamp = str(int(time.time()) if timestamp is None else timestamp)
    signature_nonce = nonce or str(uuid.uuid4())
    canonical_query = canonicalize_query_string(params)
    payload_hash = hash_payload(body, is_multipart=is_multipart)
    string_to_sign = build_string_to_sign(
        timestamp=current_timestamp,
        method=method,
        canonical_query_string=canonical_query,
        hashed_payload=payload_hash,
    )
    signature = sign_string(secret_key, string_to_sign)

    return {
        "SignatureVersion": SIGNATURE_VERSION,
        "SignatureMethod": SIGNATURE_METHOD,
        "Timestamp": current_timestamp,
        "SignatureNonce": signature_nonce,
        "AccessKey": access_key,
        "Signature": signature,
    }
