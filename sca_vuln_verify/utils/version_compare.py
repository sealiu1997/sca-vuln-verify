"""Version range comparison helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from packaging.version import InvalidVersion, Version


@dataclass(frozen=True)
class VersionMatchResult:
    version: str
    affected_range: dict[str, Any]
    is_match: bool | None
    status: str
    reason: str | None = None


_MAVEN_RELEASE_SUFFIX_RE = re.compile(r"([._-])(final|release|ga)$", re.IGNORECASE)
_MAVEN_SNAPSHOT_RE = re.compile(r"([._-])snapshot$", re.IGNORECASE)


def _normalize_version(version: str) -> str:
    normalized = version.strip()
    if normalized.lower().startswith("v") and len(normalized) > 1 and normalized[1].isdigit():
        normalized = normalized[1:]
    normalized = _MAVEN_RELEASE_SUFFIX_RE.sub("", normalized)
    normalized = _MAVEN_SNAPSHOT_RE.sub(".dev0", normalized)
    return normalized


def _parse_version(version: str | None) -> Version | None:
    if version is None or version == "":
        return None
    try:
        return Version(_normalize_version(str(version)))
    except InvalidVersion:
        return None


def compare_version_range(
    version: str,
    affected_range: dict[str, Any],
    *,
    ecosystem: str | None = None,
) -> VersionMatchResult:
    parsed_version = _parse_version(version)
    if parsed_version is None:
        return VersionMatchResult(
            version=version,
            affected_range=affected_range,
            is_match=None,
            status="unknown",
            reason="version could not be parsed",
        )

    start_raw = affected_range.get("start_version")
    end_raw = affected_range.get("end_version")
    start = _parse_version(start_raw)
    end = _parse_version(end_raw)

    if start_raw and start is None:
        return VersionMatchResult(version, affected_range, None, "unknown", "start_version could not be parsed")
    if end_raw and end is None:
        return VersionMatchResult(version, affected_range, None, "unknown", "end_version could not be parsed")

    start_open = bool(affected_range.get("start_open", False))
    end_open = bool(affected_range.get("end_open", False))

    if start is not None:
        if start_open and parsed_version <= start:
            return VersionMatchResult(version, affected_range, False, "not_matched")
        if not start_open and parsed_version < start:
            return VersionMatchResult(version, affected_range, False, "not_matched")

    if end is not None:
        if end_open and parsed_version >= end:
            return VersionMatchResult(version, affected_range, False, "not_matched")
        if not end_open and parsed_version > end:
            return VersionMatchResult(version, affected_range, False, "not_matched")

    return VersionMatchResult(version, affected_range, True, "matched")


def sort_versions(versions: list[str]) -> list[str]:
    parsed: list[tuple[Version, str]] = []
    unparsed: list[str] = []
    for version in versions:
        parsed_version = _parse_version(version)
        if parsed_version is not None:
            parsed.append((parsed_version, version))
        else:
            unparsed.append(version)
    return [raw for _, raw in sorted(parsed, key=lambda item: item[0])] + unparsed
