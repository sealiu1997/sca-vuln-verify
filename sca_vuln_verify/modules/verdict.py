"""Baseline verdict suggestion rules."""

from __future__ import annotations

from typing import Any


def _bool_signal(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "y", "1", "使用", "used"}
    return False


def _version_match(signals: dict[str, Any]) -> bool | None:
    value = signals.get("version_match")
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, str):
        normalized = value.lower()
        if normalized in {"matched", "match", "true"}:
            return True
        if normalized in {"not_matched", "not_match", "false"}:
            return False
    if hasattr(value, "is_match"):
        return value.is_match
    return None


def _has_api_error(signals: dict[str, Any]) -> bool:
    if _bool_signal(signals.get("api_error")) or _bool_signal(signals.get("partial_fetch")):
        return True
    for item in signals.get("evidence", []) or []:
        if isinstance(item, dict) and item.get("type") == "api_error":
            return True
    return False


def _use_status_used(value: Any) -> bool:
    return _bool_signal(value)


def _use_status_unused(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"false", "no", "n", "0", "未使用", "unused"}
    if isinstance(value, bool):
        return not value
    return value == 0


def _with_review(verdict: dict[str, Any], needs_review: bool) -> dict[str, Any]:
    if needs_review and verdict["confidence"] == "high":
        verdict = {**verdict, "confidence": "medium"}
    verdict["requires_human_review"] = needs_review
    if needs_review:
        verdict.setdefault("review_reason", "key signal is missing or an API error occurred")
    return verdict


def suggest_verdict(signals: dict[str, Any]) -> dict[str, Any]:
    version_match = _version_match(signals)
    needs_review = _has_api_error(signals)

    if version_match is False:
        return _with_review(
            {
                "status": "not_exploitable",
                "confidence": "high",
                "reasoning": "component version is outside the affected range",
            },
            needs_review,
        )

    if version_match is None:
        return {
            "status": "inconclusive",
            "confidence": "low",
            "reasoning": "version impact could not be determined",
            "requires_human_review": True,
            "review_reason": "version match is unknown",
        }

    kev_listed = _bool_signal(signals.get("kev_listed"))
    epss_score = signals.get("epss_score")
    poc_enable = _bool_signal(signals.get("poc_enable"))
    is_direct = _bool_signal(signals.get("is_direct"))
    is_indirect = signals.get("is_direct") is False or _bool_signal(signals.get("is_indirect"))
    use_status = signals.get("use_status")

    if kev_listed and isinstance(epss_score, (int, float)) and epss_score > 0.9:
        return _with_review(
            {
                "status": "exploitable",
                "confidence": "high",
                "reasoning": "affected version is KEV-listed and EPSS is above 0.9",
            },
            needs_review,
        )

    if poc_enable and is_direct and _use_status_used(use_status):
        return _with_review(
            {
                "status": "likely_exploitable",
                "confidence": "high",
                "reasoning": "affected direct dependency has PoC and is reported as used",
            },
            needs_review,
        )

    if poc_enable and is_indirect:
        return _with_review(
            {
                "status": "likely_exploitable",
                "confidence": "medium",
                "reasoning": "affected transitive dependency has PoC",
            },
            needs_review,
        )

    if not poc_enable and is_direct:
        return _with_review(
            {
                "status": "inconclusive",
                "confidence": "medium",
                "reasoning": "affected direct dependency has no PoC signal",
            },
            needs_review,
        )

    if is_indirect and _use_status_unused(use_status):
        return _with_review(
            {
                "status": "likely_not_exploitable",
                "confidence": "medium",
                "reasoning": "affected transitive dependency is reported as unused",
            },
            needs_review,
        )

    return {
        "status": "inconclusive",
        "confidence": "low",
        "reasoning": "available signals are insufficient for a stronger baseline verdict",
        "requires_human_review": True,
        "review_reason": "missing reachability or exploitability signal",
    }
