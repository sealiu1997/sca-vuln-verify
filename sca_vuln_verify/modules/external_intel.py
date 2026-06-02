"""External vulnerability intelligence helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from sca_vuln_verify.adapters.epss_api import EPSS_API_URL, fetch_epss
from sca_vuln_verify.adapters.kev_feed import KEV_FEED_URL, fetch_kev_feed


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _unknown(cve_id: str | None, source_api: str, reason: str, error: Exception | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "cve_id": cve_id,
        "source_api": source_api,
        "reason": reason,
        "fetched_at": _now_iso(),
    }
    if error is not None:
        result["raw_ref"] = {
            "error_type": type(error).__name__,
            "message": str(error),
        }
    return result


def _to_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def query_epss(
    cve_id: str | None,
    *,
    client: httpx.Client | None = None,
    cache_dir: str | Path | None = None,
    ttl_seconds: int = 24 * 60 * 60,
) -> dict[str, Any]:
    if not cve_id:
        return _unknown(cve_id, EPSS_API_URL, "missing CVE id")

    try:
        payload, cache_status = fetch_epss(
            cve_id,
            client=client,
            cache_dir=cache_dir,
            ttl_seconds=ttl_seconds,
        )
    except Exception as exc:
        return _unknown(cve_id, EPSS_API_URL, "EPSS request failed", exc)

    rows = payload.get("data") if isinstance(payload, dict) else None
    if not rows:
        result = _unknown(cve_id, EPSS_API_URL, "CVE not found in EPSS response")
        result["cache_status"] = cache_status
        return result

    row = rows[0]
    score = _to_float(row.get("epss"))
    percentile = _to_float(row.get("percentile"))
    return {
        "status": "known",
        "cve_id": row.get("cve") or cve_id,
        "score": score,
        "epss_score": score,
        "percentile": percentile,
        "source_timestamp": row.get("date"),
        "source_api": EPSS_API_URL,
        "cache_status": cache_status,
        "fetched_at": _now_iso(),
    }


def check_kev(
    cve_id: str | None,
    *,
    client: httpx.Client | None = None,
    cache_dir: str | Path | None = None,
    ttl_seconds: int = 24 * 60 * 60,
) -> dict[str, Any]:
    if not cve_id:
        return _unknown(cve_id, KEV_FEED_URL, "missing CVE id")

    try:
        payload, cache_status = fetch_kev_feed(
            client=client,
            cache_dir=cache_dir,
            ttl_seconds=ttl_seconds,
        )
    except Exception as exc:
        return _unknown(cve_id, KEV_FEED_URL, "KEV feed request failed", exc)

    vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, dict) else []
    for item in vulnerabilities or []:
        if item.get("cveID") != cve_id:
            continue
        return {
            "status": "known",
            "cve_id": cve_id,
            "kev_listed": True,
            "vendor_project": item.get("vendorProject"),
            "product": item.get("product"),
            "vulnerability_name": item.get("vulnerabilityName"),
            "date_added": item.get("dateAdded"),
            "due_date": item.get("dueDate"),
            "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"),
            "required_action": item.get("requiredAction"),
            "source_api": KEV_FEED_URL,
            "catalog_version": payload.get("catalogVersion"),
            "date_released": payload.get("dateReleased"),
            "cache_status": cache_status,
            "fetched_at": _now_iso(),
        }

    return {
        "status": "known",
        "cve_id": cve_id,
        "kev_listed": False,
        "source_api": KEV_FEED_URL,
        "catalog_version": payload.get("catalogVersion"),
        "date_released": payload.get("dateReleased"),
        "cache_status": cache_status,
        "fetched_at": _now_iso(),
    }
