"""Map SCA component rows into local component references."""

from __future__ import annotations

from typing import Any

from sca_vuln_verify.exceptions import NormalizationError
from sca_vuln_verify.utils.language import language_enum_to_ecosystem
from sca_vuln_verify.utils.purl import build_maven_purl_from_gav


def _infer_namespace_from_gav(gav_coordinate: str | None) -> str | None:
    if not gav_coordinate:
        return None
    parts = gav_coordinate.split(":")
    return parts[0] if len(parts) == 3 else None


def component_ref_from_sca_row(row: dict[str, Any], *, task_id: int | None = None) -> dict[str, Any]:
    name = row.get("name")
    version = row.get("version")
    if not name or not version:
        raise NormalizationError("component_ref_from_sca_row", row, "component name and version are required")

    language_enum = row.get("language_enum")
    if language_enum is None and isinstance(row.get("language"), int):
        language_enum = row.get("language")

    gav_coordinate = row.get("gav_coordinate")
    purl = row.get("purl")
    if not purl and gav_coordinate:
        try:
            purl = build_maven_purl_from_gav(gav_coordinate)
        except NormalizationError:
            purl = None

    ref = {
        "name": str(name),
        "version": str(version),
    }
    if row.get("id") is not None:
        ref["sca_comp_id"] = int(row["id"])
    if task_id is not None:
        ref["task_id"] = int(task_id)
    if row.get("project_id") is not None:
        ref["project_id"] = int(row["project_id"])
    if row.get("language") is not None and not isinstance(row.get("language"), int):
        ref["language"] = row.get("language")
    if language_enum is not None:
        ref["language_enum"] = int(language_enum)
        ref["ecosystem"] = language_enum_to_ecosystem(language_enum)
    if gav_coordinate:
        ref["gav_coordinate"] = gav_coordinate
    if purl:
        ref["purl"] = purl
    namespace = _infer_namespace_from_gav(gav_coordinate)
    if namespace:
        ref["namespace"] = namespace
    return ref
