"""Package URL helpers."""

from __future__ import annotations

from packageurl import PackageURL

from sca_vuln_verify.exceptions import NormalizationError


def parse_purl(purl: str) -> dict[str, str | None]:
    try:
        parsed = PackageURL.from_string(purl)
    except Exception as exc:  # packageurl raises multiple parsing exceptions.
        raise NormalizationError("parse_purl", purl, exc) from exc

    if not parsed.type or not parsed.name:
        raise NormalizationError("parse_purl", purl, "purl must include type and name")

    return {
        "ecosystem": parsed.type,
        "namespace": parsed.namespace,
        "name": parsed.name,
        "version": parsed.version,
    }


def build_maven_purl_from_gav(gav_coordinate: str) -> str:
    parts = gav_coordinate.split(":")
    if len(parts) != 3 or not all(parts):
        raise NormalizationError("build_maven_purl_from_gav", gav_coordinate, "expected group:artifact:version")

    group_id, artifact_id, version = parts
    return PackageURL(type="maven", namespace=group_id, name=artifact_id, version=version).to_string()
