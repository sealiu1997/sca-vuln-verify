"""FIRST EPSS API adapter with small file-cache support."""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any

import httpx


EPSS_API_URL = "https://api.first.org/data/v1/epss"
DEFAULT_TTL_SECONDS = 24 * 60 * 60


def _cache_dir(cache_dir: str | Path | None) -> Path:
    return Path(cache_dir or os.getenv("SCA_CACHE_DIR") or ".cache/sca-vuln-verify")


def _safe_cache_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def _read_cache(path: Path, *, ttl_seconds: int, allow_stale: bool = False) -> tuple[dict[str, Any], str] | None:
    if not path.exists():
        return None
    cache_age = time.time() - path.stat().st_mtime
    if cache_age <= ttl_seconds:
        return json.loads(path.read_text(encoding="utf-8")), "cache"
    if allow_stale:
        return json.loads(path.read_text(encoding="utf-8")), "stale_cache"
    return None


def _write_cache(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def fetch_epss(
    cve_id: str,
    *,
    client: httpx.Client | None = None,
    cache_dir: str | Path | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    timeout_seconds: float = 30,
) -> tuple[dict[str, Any], str]:
    cache_path = _cache_dir(cache_dir) / f"epss-{_safe_cache_name(cve_id)}.json"
    cached = _read_cache(cache_path, ttl_seconds=ttl_seconds)
    if cached:
        return cached

    owns_client = client is None
    http_client = client or httpx.Client(timeout=timeout_seconds)
    try:
        response = http_client.get(EPSS_API_URL, params={"cve": cve_id})
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("EPSS response JSON is not an object")
        _write_cache(cache_path, payload)
        return payload, "network"
    except Exception:
        stale = _read_cache(cache_path, ttl_seconds=ttl_seconds, allow_stale=True)
        if stale:
            return stale
        raise
    finally:
        if owns_client:
            http_client.close()
