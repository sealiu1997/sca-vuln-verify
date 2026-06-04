"""Data fetch and normalization functions backed by SCA OpenAPI."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sca_vuln_verify.adapters.sca_openapi import OpenAPIResponse
from sca_vuln_verify.exceptions import (
    FetchError,
    NormalizationError,
    OpenAPIError,
    OpenAPINotFoundError,
    OpenAPIResponseError,
    PartialFetchError,
    SCAVulnVerifyError,
)
from sca_vuln_verify.utils.language import language_enum_to_ecosystem
from sca_vuln_verify.utils.purl_sca_mapper import component_ref_from_sca_row


LOGGER = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _split_aliases(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return [item.strip() for item in str(value).replace(";", ",").split(",") if item.strip()]


def _first_present(raw: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = raw.get(key)
        if value not in (None, "", []):
            return value
    return None


def _normalize_leak_summary(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        key: raw.get(key)
        for key in (
            "cve_id",
            "cve",
            "moresec_id",
            "cnvd",
            "cnnvd",
            "name",
            "level",
            "cvss_three",
            "poc_enable",
            "solution",
            "summary",
        )
        if key in raw
    }


def _normalize_license(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        key: raw.get(key)
        for key in ("license", "spdx_id", "license_level", "license_problem", "explain")
        if key in raw
    }


def _normalize_affected_range(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "component_name": raw.get("name"),
        "language": raw.get("language"),
        "language_enum": raw.get("language_enum"),
        "ecosystem": language_enum_to_ecosystem(raw.get("language_enum")),
        "start_version": raw.get("start_version"),
        "end_version": raw.get("end_version"),
        "start_open": bool(raw.get("start_open", False)),
        "end_open": bool(raw.get("end_open", False)),
    }


def _normalize_path(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        key: raw.get(key)
        for key in ("className", "methodFullName", "packageName", "filename", "lineNumber", "symbol")
        if raw.get(key) not in (None, "")
    }


def _vuln_id(raw: dict[str, Any], fallback: str | None = None) -> str | None:
    return _first_present(raw, "cve_id", "cve", "moresec_id", "cnvd", "cnnvd") or fallback


def normalize_vuln_detail(
    raw: dict[str, Any],
    *,
    request_id: str | None,
    source_api: str,
    requested_vuln_id: str | None = None,
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise NormalizationError("fetch_vuln_detail", raw, "vulnerability detail must be an object")

    normalized_id = _vuln_id(raw, requested_vuln_id)
    if not normalized_id:
        raise NormalizationError("fetch_vuln_detail", raw, "at least one vulnerability id is required")

    aliases = []
    for key in ("moresec_id", "cnvd", "cnnvd"):
        if raw.get(key) and raw.get(key) != normalized_id:
            aliases.append(str(raw[key]))
    aliases.extend(_split_aliases(raw.get("osv_ids")))

    affected_ranges = [_normalize_affected_range(item) for item in _as_list(raw.get("comps")) if isinstance(item, dict)]
    path = [_normalize_path(item) for item in _as_list(raw.get("path")) if isinstance(item, dict)]

    result = {
        "vuln_id": str(normalized_id),
        "cve_id": raw.get("cve_id") or raw.get("cve"),
        "moresec_id": raw.get("moresec_id"),
        "cnvd": raw.get("cnvd"),
        "cnnvd": raw.get("cnnvd"),
        "osv_ids": _split_aliases(raw.get("osv_ids")),
        "aliases": aliases,
        "name": raw.get("name"),
        "summary": raw.get("summary"),
        "description": raw.get("summary"),
        "severity": raw.get("cvss_three_severity") or raw.get("level"),
        "level": raw.get("level"),
        "leak_level": raw.get("leak_level") or raw.get("leak_level_enum"),
        "cvss_v3_score": raw.get("cvss_three"),
        "cvss_v3_vector": raw.get("cvss_three_string"),
        "cvss_three": raw.get("cvss_three"),
        "cvss_three_base": raw.get("cvss_three_base"),
        "cvss_three_severity": raw.get("cvss_three_severity"),
        "cvss_three_difficulty": raw.get("cvss_three_difficulty"),
        "cvss_two": raw.get("cvss_two"),
        "cwe": raw.get("cwe"),
        "poc_enable": raw.get("poc_enable"),
        "poc_grade": raw.get("poc_grade"),
        "real_vuln_type": raw.get("real_vuln_type"),
        "affected_ranges": affected_ranges,
        "fixed_versions": [],
        "references": [str(item) for item in _as_list(raw.get("references")) if item],
        "solution": raw.get("solution"),
        "suggestion": raw.get("suggestion"),
        "path": path,
        "source_api": source_api,
        "request_id": request_id,
        "fetched_at": _now_iso(),
    }
    return {key: value for key, value in result.items() if value not in (None, [], {}) or key in {"affected_ranges", "fixed_versions", "references", "path", "aliases"}}


def fetch_vuln_detail(client: Any, vuln_id: str) -> dict[str, Any]:
    endpoint = "GET /openapi/v1/knowledge-base/leaks"
    try:
        response = client.get("/openapi/v1/knowledge-base/leaks", params={"id": vuln_id})
        if response.data:
            return normalize_vuln_detail(
                response.data,
                request_id=response.request_id,
                source_api=endpoint,
                requested_vuln_id=vuln_id,
            )
    except OpenAPIError:
        # Try the documented detail endpoint before surfacing a fetch failure.
        pass
    except NormalizationError:
        raise

    fallback_endpoint = "GET /openapi/v1/comps/third_party/leak/detail"
    try:
        fallback = client.get("/openapi/v1/comps/third_party/leak/detail", params={"cve": vuln_id})
        return normalize_vuln_detail(
            fallback.data,
            request_id=fallback.request_id,
            source_api=fallback_endpoint,
            requested_vuln_id=vuln_id,
        )
    except OpenAPIError as exc:
        raise FetchError("fetch_vuln_detail", fallback_endpoint, exc.request_id, exc) from exc


def normalize_component_detail(
    raw: dict[str, Any],
    *,
    request_id: str | None,
    source_api: str,
    input_ref: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise NormalizationError("fetch_component_detail", raw, "component detail must be an object")

    ref_source = dict(raw)
    if input_ref:
        ref_source = {**input_ref, **raw}
        if input_ref.get("sca_comp_id") is not None and raw.get("id") is None:
            ref_source["id"] = input_ref["sca_comp_id"]
        if input_ref.get("language_enum") is not None and raw.get("language_enum") is None:
            ref_source["language_enum"] = input_ref["language_enum"]
    ref = component_ref_from_sca_row(ref_source)

    result = {
        "ref": ref,
        "level": raw.get("level"),
        "risk_types": _as_list(raw.get("risk_types")),
        "leak_num": raw.get("leak_num") if raw.get("leak_num") is not None else raw.get("leak_count"),
        "leak_level_count": raw.get("leak_level_count") or raw.get("leak_count"),
        "dep_info": _as_list(raw.get("dep_info")),
        "dep_type": _as_list(raw.get("dep_type")),
        "comp_refer": raw.get("comp_refer"),
        "indirect_comp": _as_list(raw.get("indirect_comp")),
        "use_status": raw.get("use_status"),
        "latest_version": raw.get("latest_version"),
        "recommended_upgrade_version": raw.get("recommended_upgrade_version"),
        "latest_release_version": raw.get("latest_release_version"),
        "leaks": [_normalize_leak_summary(item) for item in _as_list(raw.get("leaks")) if isinstance(item, dict)],
        "licenses": [_normalize_license(item) for item in _as_list(raw.get("licenses")) if isinstance(item, dict)],
        "source_api": source_api,
        "request_id": request_id,
        "fetched_at": _now_iso(),
    }
    return result


def fetch_component_detail(
    client: Any,
    component_ref: dict[str, Any],
    project_id: int | None = None,
) -> dict[str, Any]:
    comp_id = component_ref.get("sca_comp_id") or component_ref.get("id")
    if comp_id is not None:
        endpoint = f"GET /openapi/v1/comps/{comp_id}"
        params = {"project_id": project_id or component_ref.get("project_id")}
        try:
            response = client.get(f"/openapi/v1/comps/{comp_id}", params=params)
            return normalize_component_detail(
                response.data,
                request_id=response.request_id,
                source_api=endpoint,
                input_ref=component_ref,
            )
        except OpenAPIError as exc:
            raise FetchError("fetch_component_detail", endpoint, exc.request_id, exc) from exc

    if not component_ref.get("name") or not component_ref.get("version") or not component_ref.get("language_enum"):
        raise NormalizationError(
            "fetch_component_detail",
            component_ref,
            "name, version, and language_enum are required for knowledge-base fallback",
        )

    endpoint = "GET /openapi/v1/knowledge-base/comps"
    params = {
        "name": component_ref["name"],
        "version": component_ref["version"],
        "language": component_ref["language_enum"],
    }
    try:
        response = client.get("/openapi/v1/knowledge-base/comps", params=params)
        return normalize_component_detail(
            response.data,
            request_id=response.request_id,
            source_api=endpoint,
            input_ref=component_ref,
        )
    except OpenAPIError as exc:
        raise FetchError("fetch_component_detail", endpoint, exc.request_id, exc) from exc


def _normalize_task(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        key: raw.get(key)
        for key in (
            "id",
            "name",
            "project_id",
            "project_name",
            "module_id",
            "module_name",
            "check_status_num",
            "language_details",
        )
        if key in raw
    }


def _normalize_project_component(raw: dict[str, Any], *, task_id: int) -> dict[str, Any]:
    ref = component_ref_from_sca_row(raw, task_id=task_id)
    return {
        "ref": ref,
        "level": raw.get("level"),
        "risk_types": _as_list(raw.get("risk_types")),
        "leak_num": raw.get("leak_num"),
        "dep_info": _as_list(raw.get("dep_info")),
        "dep_type": _as_list(raw.get("dep_type")),
        "comp_refer": raw.get("comp_refer"),
        "indirect_comp": _as_list(raw.get("indirect_comp")),
        "use_status": raw.get("use_status"),
        "latest_version": raw.get("latest_version"),
        "licenses": [_normalize_license(item) for item in _as_list(raw.get("licenses")) if isinstance(item, dict)],
    }


def _normalize_task_vuln(raw: dict[str, Any]) -> dict[str, Any]:
    vuln = {
        "vuln_id": raw.get("cve") or raw.get("moresec_id") or raw.get("cnvd") or raw.get("cnnvd") or raw.get("name"),
        "cve_id": raw.get("cve"),
        "moresec_id": raw.get("moresec_id"),
        "cnvd": raw.get("cnvd"),
        "cnnvd": raw.get("cnnvd"),
        "name": raw.get("name"),
        "level": raw.get("level"),
        "poc_enable": raw.get("poc_enable"),
        "poc_grade": raw.get("poc_grade"),
        "real_vuln_type": raw.get("real_vuln_type"),
        "description": raw.get("desc"),
        "languages": _as_list(raw.get("languages")),
        "components": [
            {
                "sca_comp_id": item.get("id"),
                "name": item.get("name"),
                "version": item.get("version"),
                "language_enum": item.get("language"),
                "level": item.get("level"),
            }
            for item in _as_list(raw.get("components"))
            if isinstance(item, dict)
        ],
    }
    return {key: value for key, value in vuln.items() if value not in (None, [], {}) or key == "components"}


def _page_items(response: OpenAPIResponse) -> list[dict[str, Any]]:
    if not isinstance(response.data, dict):
        return []
    return [item for item in _as_list(response.data.get("items")) if isinstance(item, dict)]


def _page_meta(response: OpenAPIResponse) -> dict[str, Any]:
    data = response.data if isinstance(response.data, dict) else {}
    return {
        "page": data.get("page"),
        "per_page": data.get("per_page"),
        "total": data.get("total"),
        "request_id": response.request_id,
    }


def _build_component_vulnerability_index(vulnerabilities: list[dict[str, Any]]) -> dict[str, Any]:
    by_component_id: dict[str, list[dict[str, Any]]] = {}
    by_component_key: dict[str, list[dict[str, Any]]] = {}
    for vuln in vulnerabilities:
        vuln_summary = {
            key: vuln.get(key)
            for key in ("vuln_id", "cve_id", "moresec_id", "name", "level", "poc_enable", "real_vuln_type")
            if vuln.get(key) is not None
        }
        for component in vuln.get("components", []):
            comp_id = component.get("sca_comp_id")
            if comp_id is not None:
                by_component_id.setdefault(str(comp_id), []).append(vuln_summary)
            if component.get("name") and component.get("version"):
                key = f"{component['name']}@{component['version']}"
                by_component_key.setdefault(key, []).append(vuln_summary)
    return {
        "by_component_id": by_component_id,
        "by_name_version": by_component_key,
    }


def _serialize_fetch_error(operation: str, endpoint: str, exc: Exception, page: int | None = None) -> dict[str, Any]:
    return {
        "operation": operation,
        "endpoint": endpoint,
        "page": page,
        "request_id": getattr(exc, "request_id", None),
        "error_type": type(exc).__name__,
        "message": str(exc),
    }


def fetch_project_scan_result(
    client: Any,
    task_id: int,
    page_size: int = 100,
    allow_partial: bool = False,
) -> dict[str, Any]:
    task_endpoint = f"GET /openapi/v1/tasks/{task_id}"
    components_endpoint = f"GET /openapi/v1/tasks/{task_id}/comps"
    leaks_endpoint = f"GET /openapi/v1/tasks/{task_id}/comp_leaks"

    errors: list[dict[str, Any]] = []
    task: dict[str, Any] = {}
    components: list[dict[str, Any]] = []
    vulnerabilities: list[dict[str, Any]] = []
    pages: dict[str, list[dict[str, Any]]] = {"components": [], "vulnerabilities": []}
    request_ids: list[str] = []

    try:
        task_response = client.get(f"/openapi/v1/tasks/{task_id}")
        request_ids.append(task_response.request_id)
        task = _normalize_task(task_response.data)
    except OpenAPIError as exc:
        raise FetchError("fetch_task_detail", task_endpoint, exc.request_id, exc) from exc

    partial_data = {
        "task": task,
        "components": components,
        "vulnerabilities": vulnerabilities,
        "component_vulnerability_index": {},
    }

    try:
        for response in client.iter_pages(
            f"/openapi/v1/tasks/{task_id}/comps",
            params={"num": page_size},
        ):
            if response.request_id:
                request_ids.append(response.request_id)
            pages["components"].append(_page_meta(response))
            components.extend(_normalize_project_component(item, task_id=task_id) for item in _page_items(response))
            partial_data["components"] = components
    except OpenAPIError as exc:
        page = len(pages["components"]) + 1
        errors.append(_serialize_fetch_error("fetch_task_components", components_endpoint, exc, page=page))
        if not allow_partial:
            raise PartialFetchError("fetch_project_scan_result", components_endpoint, exc.request_id, partial_data, errors) from exc

    try:
        for response in client.iter_pages(
            f"/openapi/v1/tasks/{task_id}/comp_leaks",
            params={"num": page_size},
        ):
            if response.request_id:
                request_ids.append(response.request_id)
            pages["vulnerabilities"].append(_page_meta(response))
            vulnerabilities.extend(_normalize_task_vuln(item) for item in _page_items(response))
            partial_data["vulnerabilities"] = vulnerabilities
    except OpenAPIError as exc:
        page = len(pages["vulnerabilities"]) + 1
        errors.append(_serialize_fetch_error("fetch_task_vulnerabilities", leaks_endpoint, exc, page=page))
        if not allow_partial:
            raise PartialFetchError("fetch_project_scan_result", leaks_endpoint, exc.request_id, partial_data, errors) from exc

    index = _build_component_vulnerability_index(vulnerabilities)
    result = {
        "task": task,
        "components": components,
        "vulnerabilities": vulnerabilities,
        "component_vulnerability_index": index,
        "fetch_meta": {
            "source_api": [task_endpoint, components_endpoint, leaks_endpoint],
            "request_ids": [request_id for request_id in request_ids if request_id],
            "pages": pages,
            "partial": bool(errors),
            "errors": errors,
            "fetched_at": _now_iso(),
        },
    }
    return result


def _normalize_dependency_node(raw: dict[str, Any]) -> dict[str, Any]:
    node = {
        key: raw.get(key)
        for key in (
            "id",
            "uuid",
            "name",
            "version",
            "language",
            "path",
            "type",
            "com_level",
            "leak_low",
            "leak_mid",
            "leak_high",
            "leak_serious",
            "leak_unknown",
        )
        if key in raw
    }
    children = [_normalize_dependency_node(item) for item in _as_list(raw.get("children")) if isinstance(item, dict)]
    if children:
        node["children"] = children
    return node


def _normalize_dependency_tree(data: Any) -> Any:
    if isinstance(data, list):
        return [_normalize_dependency_node(item) for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return _normalize_dependency_node(data)
    return data


def fetch_project_dependency_tree(
    client: Any,
    task_id: int,
    filters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    endpoint = f"GET /openapi/v1/tasks/{task_id}/comp-trees"
    try:
        response = client.get(f"/openapi/v1/tasks/{task_id}/comp-trees", params=filters or {})
    except OpenAPIError as exc:
        raise FetchError("fetch_project_dependency_tree", endpoint, exc.request_id, exc) from exc

    return {
        "task_id": task_id,
        "tree": _normalize_dependency_tree(response.data),
        "source_api": endpoint,
        "request_id": response.request_id,
        "fetched_at": _now_iso(),
    }


def _normalize_version_item(raw: Any, *, request_id: str | None, source_api: str) -> dict[str, Any] | None:
    if isinstance(raw, str):
        if not raw.strip():
            return None
        item = {"version": raw}
    elif isinstance(raw, dict):
        if raw.get("version") in (None, ""):
            return None
        item = {
            key: raw.get(key)
            for key in (
                "version",
                "is_latest_version",
                "is_recommended_version",
                "leak_level_count",
                "link",
                "release_date",
                "language",
                "comp_type",
            )
            if raw.get(key) is not None
        }
    else:
        return None

    item["source_api"] = source_api
    item["request_id"] = request_id
    item["fetched_at"] = _now_iso()
    return item


def _version_entries(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("items"), list):
            return data["items"]
        if isinstance(data.get("versions"), list):
            metadata = {
                key: data.get(key)
                for key in ("language", "comp_type")
                if data.get(key) is not None
            }
            return [
                {"version": version, **metadata}
                for version in data["versions"]
                if version not in (None, "")
            ]
        if data.get("version") is not None:
            return [data]
    return []


def fetch_component_versions(client: Any, component_ref: dict[str, Any]) -> list[dict[str, Any]]:
    comp_id = component_ref.get("sca_comp_id") or component_ref.get("id")
    if comp_id is not None:
        endpoint = f"GET /openapi/v1/comps/{comp_id}/versions"
        try:
            response = client.get(f"/openapi/v1/comps/{comp_id}/versions")
        except OpenAPIError as exc:
            raise FetchError("fetch_component_versions", endpoint, exc.request_id, exc) from exc
    else:
        if not component_ref.get("name") or not component_ref.get("language_enum"):
            raise NormalizationError(
                "fetch_component_versions",
                component_ref,
                "sca_comp_id or name and language_enum are required",
            )
        endpoint = "GET /openapi/v1/knowledge-base/comps/versions"
        try:
            response = client.get(
                "/openapi/v1/knowledge-base/comps/versions",
                params={"name": component_ref["name"], "language": component_ref["language_enum"]},
            )
        except OpenAPIError as exc:
            raise FetchError("fetch_component_versions", endpoint, exc.request_id, exc) from exc

    entries = _version_entries(response.data)
    versions: list[dict[str, Any]] = []
    skipped_count = 0
    for item in entries:
        normalized = _normalize_version_item(item, request_id=response.request_id, source_api=endpoint)
        if normalized is None:
            skipped_count += 1
            continue
        versions.append(normalized)

    if skipped_count:
        LOGGER.warning(
            "Skipped %s invalid component version entries from %s (request_id=%s)",
            skipped_count,
            endpoint,
            response.request_id,
        )

    if isinstance(response.data, dict) and response.data.get("total") is not None:
        try:
            total = int(response.data["total"])
        except (TypeError, ValueError):
            total = None
        if total is not None and total != len(versions):
            LOGGER.warning(
                "Component version total mismatch from %s (request_id=%s): total=%s valid_versions=%s",
                endpoint,
                response.request_id,
                total,
                len(versions),
            )

    return versions


def fetch_vuln_affected_components(client: Any, vuln_id: str) -> list[dict[str, Any]]:
    detail = fetch_vuln_detail(client, vuln_id)
    return [
        {
            **affected_range,
            "vuln_id": detail.get("vuln_id"),
            "source_api": detail.get("source_api"),
            "request_id": detail.get("request_id"),
            "fetched_at": detail.get("fetched_at"),
        }
        for affected_range in detail.get("affected_ranges", [])
    ]


def _component_ref_payload(component_ref: dict[str, Any]) -> dict[str, Any]:
    return component_ref.get("ref", component_ref)


def _component_ids(component_ref: dict[str, Any]) -> set[int]:
    ref = _component_ref_payload(component_ref)
    ids: set[int] = set()
    for key in ("sca_comp_id", "id"):
        value = ref.get(key)
        if value is None:
            continue
        try:
            ids.add(int(value))
        except (TypeError, ValueError):
            continue
    return ids


def _normalize_file_location(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_type": "file_tree",
        "path": raw.get("path"),
        "is_dir": raw.get("is_dir"),
        "component_ids": _as_list(raw.get("component_ids")),
    }


def _path_values(value: Any) -> list[str]:
    if value in (None, "", []):
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        paths: list[str] = []
        for item in value:
            if isinstance(item, str):
                paths.append(item)
            elif isinstance(item, dict):
                path = item.get("path") or item.get("file") or item.get("filename")
                if path:
                    paths.append(str(path))
        return paths
    return [str(value)]


def _component_refer_locations(component_ref: dict[str, Any]) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    comp_refer = component_ref.get("comp_refer") or {}
    for key in ("current_refer_path", "root_refer_path"):
        for path in _path_values(comp_refer.get(key)):
            locations.append({"source_type": "component_refer", "path": path, "refer_field": key})

    for item in _as_list(component_ref.get("indirect_comp")):
        if not isinstance(item, dict):
            continue
        for path in _path_values(item.get("refs_com_path")):
            locations.append({"source_type": "component_refer", "path": path, "refer_field": "refs_com_path"})
    return locations


def fetch_component_code_location(
    client: Any,
    task_id: int,
    component_ref: dict[str, Any],
    vuln_id: str | None = None,
    page_size: int = 100,
) -> dict[str, Any]:
    endpoint = f"GET /openapi/v2/tasks/{task_id}/file-path"
    target_ids = _component_ids(component_ref)
    locations: list[dict[str, Any]] = []
    request_ids: list[str] = []
    errors: list[dict[str, Any]] = []

    try:
        for response in client.iter_pages(
            f"/openapi/v2/tasks/{task_id}/file-path",
            params={"num": page_size},
        ):
            if response.request_id:
                request_ids.append(response.request_id)
            for item in _page_items(response):
                item_ids = {
                    int(value)
                    for value in _as_list(item.get("component_ids"))
                    if str(value).isdigit()
                }
                if target_ids and target_ids.isdisjoint(item_ids):
                    continue
                if not target_ids and item_ids:
                    continue
                locations.append(_normalize_file_location(item))
    except OpenAPIError as exc:
        raise FetchError("fetch_component_code_location", endpoint, exc.request_id, exc) from exc

    locations.extend(_component_refer_locations(component_ref))

    if vuln_id:
        try:
            vuln_detail = fetch_vuln_detail(client, vuln_id)
            if vuln_detail.get("request_id"):
                request_ids.append(vuln_detail["request_id"])
            for path in vuln_detail.get("path", []):
                locations.append({"source_type": "vuln_path", **path})
        except SCAVulnVerifyError as exc:  # best-effort enrichment; expose failure metadata.
            errors.append(_serialize_fetch_error("fetch_vuln_path", "GET /openapi/v1/knowledge-base/leaks", exc))

    return {
        "task_id": task_id,
        "component": _component_ref_payload(component_ref),
        "locations": locations,
        "source_api": [endpoint],
        "request_ids": [request_id for request_id in request_ids if request_id],
        "errors": errors,
        "fetched_at": _now_iso(),
    }


def fetch_vuln_fix_info(
    client: Any,
    vuln_id: str,
    component_ref: dict[str, Any] | None = None,
) -> dict[str, Any]:
    vuln_detail = fetch_vuln_detail(client, vuln_id)
    request_ids = [vuln_detail.get("request_id")]
    source_apis = [vuln_detail.get("source_api")]
    errors: list[dict[str, Any]] = []
    component_detail: dict[str, Any] | None = None
    versions: list[dict[str, Any]] = []

    if component_ref is not None:
        try:
            component_detail = fetch_component_detail(client, component_ref)
            request_ids.append(component_detail.get("request_id"))
            source_apis.append(component_detail.get("source_api"))
        except SCAVulnVerifyError as exc:
            errors.append(_serialize_fetch_error("fetch_component_detail", "GET /openapi/v1/comps/{comp_id}", exc))

        try:
            versions = fetch_component_versions(client, component_ref)
            request_ids.extend(item.get("request_id") for item in versions)
            source_apis.extend(item.get("source_api") for item in versions)
        except SCAVulnVerifyError as exc:
            errors.append(_serialize_fetch_error("fetch_component_versions", "GET /openapi/v1/comps/{comp_id}/versions", exc))

    recommended_upgrade_version = None
    latest_version = None
    latest_release_version = None
    if component_detail:
        recommended_upgrade_version = component_detail.get("recommended_upgrade_version")
        latest_version = component_detail.get("latest_version")
        latest_release_version = component_detail.get("latest_release_version")

    return {
        "vuln_id": vuln_detail.get("vuln_id") or vuln_id,
        "solution": vuln_detail.get("solution"),
        "suggestion": vuln_detail.get("suggestion"),
        "recommended_upgrade_version": recommended_upgrade_version,
        "latest_version": latest_version,
        "latest_release_version": latest_release_version,
        "versions": versions,
        "source_api": sorted({str(item) for item in source_apis if item}),
        "request_ids": [request_id for request_id in request_ids if request_id],
        "errors": errors,
        "fetched_at": _now_iso(),
    }


def _is_int_like(value: Any) -> bool:
    return isinstance(value, int) or (isinstance(value, str) and value.isdigit())


def _int_value(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _resolve_project_id(client: Any, project_id: int | str, page_size: int) -> int:
    if _is_int_like(project_id):
        return int(project_id)

    search_endpoint = "GET /openapi/v1/projects"
    for query_key in ("name", "pattern"):
        try:
            for response in client.iter_pages(
                "/openapi/v1/projects",
                params={query_key: project_id, "num": page_size},
            ):
                for item in _page_items(response):
                    if item.get("id") is not None and (
                        item.get("name") == project_id or query_key == "pattern"
                    ):
                        return int(item["id"])
        except OpenAPIError as exc:
            raise FetchError("discover_project_tasks", search_endpoint, exc.request_id, exc) from exc

    raise FetchError(
        "discover_project_tasks",
        search_endpoint,
        None,
        RuntimeError(f"project {project_id!r} could not be resolved to an id"),
    )


def _is_not_found_error(exc: OpenAPIError) -> bool:
    if isinstance(exc, OpenAPINotFoundError):
        return True
    return isinstance(exc, OpenAPIResponseError) and "not found" in str(exc).lower()


def _discover_project_tasks_by_scan(
    client: Any,
    project_id: int,
    task_scan_range: tuple[int, int],
) -> list[dict[str, Any]]:
    start_id, end_id = task_scan_range
    if start_id <= 0 or end_id <= 0 or end_id < start_id:
        raise ValueError("task_scan_range must be a positive (start_id, end_id) tuple")

    tasks: list[dict[str, Any]] = []
    for task_id in range(start_id, end_id + 1):
        endpoint = f"GET /openapi/v1/tasks/{task_id}"
        try:
            response = client.get(f"/openapi/v1/tasks/{task_id}")
        except OpenAPIError as exc:
            if _is_not_found_error(exc):
                continue
            raise FetchError("discover_project_tasks_by_scan", endpoint, exc.request_id, exc) from exc

        raw_task = response.data if isinstance(response.data, dict) else {}
        if _int_value(raw_task.get("project_id")) != project_id:
            continue
        tasks.append(
            {
                "id": task_id,
                "name": raw_task.get("name"),
                "status": raw_task.get("check_status_num") or raw_task.get("status"),
                "module_id": raw_task.get("module_id"),
                "module_name": raw_task.get("module_name"),
                "project_id": project_id,
                "project_name": raw_task.get("project_name"),
                "source_api": endpoint,
                "request_id": response.request_id,
            }
        )
    return tasks


def discover_project_tasks(
    client: Any,
    project_id: int | str,
    page_size: int = 100,
    task_scan_range: tuple[int, int] | None = None,
) -> list[dict[str, Any]]:
    resolved_project_id = _resolve_project_id(client, project_id, page_size)
    endpoint = "GET /openapi/v1/modules"
    tasks: list[dict[str, Any]] = []
    saw_module = False
    saw_tasks_field = False
    saw_task_names_field = False

    try:
        for response in client.iter_pages(
            "/openapi/v1/modules",
            params={"project_id": resolved_project_id, "num": page_size},
        ):
            for module in _page_items(response):
                saw_module = True
                if "task_names" in module:
                    saw_task_names_field = True
                if "tasks" not in module:
                    continue
                saw_tasks_field = True
                for task in _as_list(module.get("tasks")):
                    if not isinstance(task, dict):
                        continue
                    if task.get("id") is None:
                        raise FetchError(
                            "discover_project_tasks",
                            endpoint,
                            response.request_id,
                            RuntimeError("module task entry does not contain a stable id"),
                        )
                    tasks.append(
                        {
                            "id": task.get("id"),
                            "name": task.get("name"),
                            "status": task.get("status"),
                            "module_id": module.get("id"),
                            "module_name": module.get("name"),
                            "project_id": module.get("project_id") or resolved_project_id,
                            "project_name": module.get("project_name"),
                            "source_api": endpoint,
                            "request_id": response.request_id,
                        }
                    )
    except OpenAPIError as exc:
        raise FetchError("discover_project_tasks", endpoint, exc.request_id, exc) from exc

    if not tasks:
        if task_scan_range is not None:
            scanned_tasks = _discover_project_tasks_by_scan(client, resolved_project_id, task_scan_range)
            if scanned_tasks:
                return scanned_tasks

        reason = "module list response does not include usable tasks[] with task ids"
        if not saw_module:
            reason = "project has no modules in OpenAPI response"
        elif not saw_tasks_field:
            reason = "module list response lacks tasks[]; task_names[] is not a stable task id source"
        if saw_task_names_field:
            reason = f"{reason}; pass task_ids or enable explicit task id scan"
        raise FetchError("discover_project_tasks", endpoint, None, RuntimeError(reason))

    return tasks
