"""Batch project/task verification workflow."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from sca_vuln_verify.exceptions import SCAVulnVerifyError
from sca_vuln_verify.modules.data_fetch import (
    discover_project_tasks,
    fetch_component_detail,
    fetch_project_dependency_tree,
    fetch_project_scan_result,
    fetch_vuln_detail,
)
from sca_vuln_verify.modules.data_process import (
    analyze_dependency_depth,
    check_reachability,
    compare_versions,
)
from sca_vuln_verify.modules.external_intel import check_kev, query_epss
from sca_vuln_verify.modules.output import build_verification_result, validate_verification_result
from sca_vuln_verify.modules.verdict import suggest_verdict


IntelProvider = Callable[[str], dict[str, Any]]

SEVERITY_WEIGHT = {
    "critical": 5,
    "严重": 5,
    "超危": 5,
    "serious": 5,
    "high": 4,
    "高危": 4,
    "medium": 3,
    "中危": 3,
    "low": 2,
    "低危": 2,
}


def _utc_timestamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _error_metadata(operation: str, endpoint: str | None, exc: Exception) -> dict[str, Any]:
    return {
        "operation": operation,
        "endpoint": endpoint,
        "request_id": getattr(exc, "request_id", None),
        "error_type": type(exc).__name__,
        "message": str(exc),
    }


def _api_error_evidence(error: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "api_error",
        "description": f"{error['operation']} failed: {error['message']}",
        "source_module": error["operation"],
        "source_api": error.get("endpoint"),
        "request_id": error.get("request_id"),
        "confidence": "low",
        "raw_ref": error,
    }


def _severity(value: Any) -> str:
    return str(value or "unknown").strip().lower()


def _severity_score(value: Any) -> int:
    return SEVERITY_WEIGHT.get(_severity(value), 1)


def _cve_id(vulnerability: dict[str, Any]) -> str | None:
    cve = vulnerability.get("cve_id") or vulnerability.get("cve") or vulnerability.get("vuln_id")
    return str(cve) if cve and str(cve).upper().startswith("CVE-") else None


def _component_key(component_ref: dict[str, Any]) -> str | None:
    if component_ref.get("sca_comp_id") is not None:
        return str(component_ref["sca_comp_id"])
    if component_ref.get("name") and component_ref.get("version"):
        return f"{component_ref['name']}@{component_ref['version']}"
    return None


def _component_summary_index(scan_result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for component in scan_result.get("components", []):
        ref = component.get("ref", {})
        key = _component_key(ref)
        if key:
            index[key] = component
        if ref.get("name") and ref.get("version"):
            index[f"{ref['name']}@{ref['version']}"] = component
    return index


def _candidate_component_ref(task_id: int, raw_component: dict[str, Any]) -> dict[str, Any]:
    ref = {
        "name": str(raw_component.get("name") or "unknown"),
        "version": str(raw_component.get("version") or "unknown"),
        "task_id": task_id,
    }
    if raw_component.get("sca_comp_id") is not None:
        ref["sca_comp_id"] = int(raw_component["sca_comp_id"])
    if raw_component.get("language_enum") is not None:
        ref["language_enum"] = int(raw_component["language_enum"])
    return ref


def _build_candidates(scan_result: dict[str, Any], task_id: int) -> list[dict[str, Any]]:
    component_index = _component_summary_index(scan_result)
    candidates: list[dict[str, Any]] = []
    for vulnerability in scan_result.get("vulnerabilities", []):
        for raw_component in vulnerability.get("components", []):
            ref = _candidate_component_ref(task_id, raw_component)
            component_summary = component_index.get(str(ref.get("sca_comp_id"))) or component_index.get(
                f"{ref['name']}@{ref['version']}"
            )
            candidates.append(
                {
                    "component_ref": ref,
                    "component_summary": component_summary or {"ref": ref},
                    "vulnerability": vulnerability,
                }
            )
    return candidates


def _default_intel_provider(cve_id: str) -> dict[str, Any]:
    return {
        "epss": query_epss(cve_id),
        "kev": check_kev(cve_id),
    }


def _fetch_intel_map(
    cve_ids: set[str],
    intel_provider: IntelProvider,
    max_external_workers: int,
) -> dict[str, dict[str, Any]]:
    if not cve_ids:
        return {}

    intel: dict[str, dict[str, Any]] = {}
    max_workers = max(1, min(max_external_workers, len(cve_ids)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(intel_provider, cve_id): cve_id for cve_id in cve_ids}
        for future in as_completed(futures):
            cve_id = futures[future]
            try:
                intel[cve_id] = future.result()
            except Exception as exc:
                intel[cve_id] = {
                    "errors": [_error_metadata("external_intel", "EPSS/KEV", exc)]
                }
    return intel


def _candidate_sort_key(candidate: dict[str, Any]) -> tuple[int, int, float, int, int]:
    vulnerability = candidate["vulnerability"]
    intel = candidate.get("intel", {})
    kev = intel.get("kev", {}) if isinstance(intel.get("kev"), dict) else {}
    epss = intel.get("epss", {}) if isinstance(intel.get("epss"), dict) else {}
    component = candidate.get("component_summary", {})
    dep_values = {str(value) for value in _as_list(component.get("dep_type"))}
    direct = 1 if "0" in dep_values else 0
    return (
        _severity_score(vulnerability.get("level") or vulnerability.get("severity")),
        1 if kev.get("kev_listed") else 0,
        float(epss.get("epss_score") or epss.get("score") or 0),
        1 if vulnerability.get("poc_enable") else 0,
        direct,
    )


def _matching_affected_ranges(
    vulnerability: dict[str, Any],
    component_ref: dict[str, Any],
) -> list[dict[str, Any]]:
    ranges = vulnerability.get("affected_ranges") or []
    matched = []
    for affected_range in ranges:
        if affected_range.get("component_name") and affected_range.get("component_name") != component_ref.get("name"):
            continue
        matched.append(affected_range)
    return matched or ranges


def _version_match_result(vulnerability: dict[str, Any], component_ref: dict[str, Any]) -> Any:
    ranges = _matching_affected_ranges(vulnerability, component_ref)
    if not ranges:
        return None

    unknown = None
    for affected_range in ranges:
        result = compare_versions(
            component_ref["version"],
            affected_range,
            ecosystem=component_ref.get("ecosystem"),
        )
        if result.is_match is True:
            return result
        if result.is_match is None:
            unknown = result
    return unknown if unknown is not None else result


def _version_evidence(version_result: Any, component_ref: dict[str, Any]) -> dict[str, Any]:
    if version_result is None or version_result.is_match is None:
        return {
            "type": "version_match",
            "description": f"could not determine whether {component_ref['name']} {component_ref['version']} is affected",
            "source_module": "compare_versions",
            "confidence": "low",
        }
    if version_result.is_match:
        return {
            "type": "version_match",
            "description": f"{component_ref['name']} {component_ref['version']} is inside the affected range",
            "source_module": "compare_versions",
            "confidence": "high",
            "raw_ref": version_result.affected_range,
        }
    return {
        "type": "version_match",
        "description": f"{component_ref['name']} {component_ref['version']} is outside the affected range",
        "source_module": "compare_versions",
        "confidence": "high",
        "raw_ref": version_result.affected_range,
    }


def _external_intel_evidence(intel: dict[str, Any]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    epss = intel.get("epss") if isinstance(intel.get("epss"), dict) else {}
    kev = intel.get("kev") if isinstance(intel.get("kev"), dict) else {}

    if epss.get("status") == "known" and epss.get("epss_score") is not None:
        evidence.append(
            {
                "type": "external_intel",
                "description": f"EPSS score is {epss['epss_score']}",
                "source_module": "external_intel.query_epss",
                "source_api": epss.get("source_api"),
                "confidence": "medium",
                "raw_ref": {"percentile": epss.get("percentile"), "cache_status": epss.get("cache_status")},
            }
        )
    if kev.get("status") == "known":
        evidence.append(
            {
                "type": "external_intel",
                "description": "CVE is listed in CISA KEV" if kev.get("kev_listed") else "CVE is not listed in CISA KEV",
                "source_module": "external_intel.check_kev",
                "source_api": kev.get("source_api"),
                "confidence": "medium",
                "raw_ref": {"kev_listed": kev.get("kev_listed"), "cache_status": kev.get("cache_status")},
            }
        )
    for error in intel.get("errors", []) or []:
        evidence.append(_api_error_evidence(error))
    return evidence


def _dependency_depth_evidence(depth: dict[str, Any]) -> dict[str, Any]:
    if depth.get("status") == "found":
        return {
            "type": "dependency_depth",
            "description": f"component found at dependency depth {depth['depth']}",
            "source_module": "analyze_dependency_depth",
            "confidence": depth.get("confidence", "medium"),
            "raw_ref": {
                "depth": depth.get("depth"),
                "is_direct": depth.get("is_direct"),
                "matched_by": depth.get("matched_by"),
                "path": depth.get("path"),
            },
        }
    return {
        "type": "dependency_depth",
        "description": "dependency depth could not be determined",
        "source_module": "analyze_dependency_depth",
        "confidence": "low",
        "raw_ref": depth,
    }


def _recommended_actions(vulnerability: dict[str, Any], component: dict[str, Any]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    recommended = component.get("recommended_upgrade_version")
    if isinstance(recommended, dict) and recommended.get("version"):
        actions.append(
            {
                "action": "upgrade",
                "description": f"upgrade to {recommended['version']}",
                "target_version": recommended["version"],
            }
        )
    elif isinstance(recommended, str) and recommended:
        actions.append({"action": "upgrade", "description": f"upgrade to {recommended}", "target_version": recommended})

    if vulnerability.get("solution"):
        actions.append({"action": "mitigate", "description": vulnerability["solution"]})
    elif vulnerability.get("suggestion"):
        actions.append({"action": "mitigate", "description": vulnerability["suggestion"]})
    return actions


def _merge_project_context(scan_result: dict[str, Any], task_id: int) -> dict[str, Any]:
    task = scan_result.get("task", {})
    return {
        "task_id": task.get("id") or task_id,
        "task_name": task.get("name"),
        "project_id": task.get("project_id"),
        "project_name": task.get("project_name"),
        "module_id": task.get("module_id"),
        "module_name": task.get("module_name"),
    }


def _verify_candidate(
    client: Any,
    candidate: dict[str, Any],
    *,
    task_id: int,
    scan_result: dict[str, Any],
    dependency_tree: Any,
    scan_partial: bool,
) -> dict[str, Any]:
    component_ref = candidate["component_ref"]
    component = candidate["component_summary"]
    vulnerability = dict(candidate["vulnerability"])
    errors: list[dict[str, Any]] = []

    try:
        component_detail = fetch_component_detail(client, component_ref)
        component = {**component, **component_detail}
    except SCAVulnVerifyError as exc:
        errors.append(_error_metadata("fetch_component_detail", "GET /openapi/v1/comps/{comp_id}", exc))

    try:
        vulnerability_detail = fetch_vuln_detail(client, vulnerability["vuln_id"])
        vulnerability = {**vulnerability, **vulnerability_detail}
    except SCAVulnVerifyError as exc:
        errors.append(_error_metadata("fetch_vuln_detail", "GET /openapi/v1/knowledge-base/leaks", exc))

    version_result = _version_match_result(vulnerability, component_ref)
    reachability = check_reachability(component, vulnerability, _merge_project_context(scan_result, task_id))
    depth = analyze_dependency_depth(dependency_tree, component_ref) if dependency_tree is not None else {
        "status": "unknown",
        "confidence": "low",
        "reason": "dependency tree is unavailable",
    }
    intel = candidate.get("intel", {})

    evidence = [_version_evidence(version_result, component_ref)]
    evidence.extend(reachability.get("evidence", []))
    evidence.append(_dependency_depth_evidence(depth))
    evidence.extend(_external_intel_evidence(intel))
    evidence.extend(_api_error_evidence(error) for error in errors)
    if scan_partial:
        evidence.append(
            _api_error_evidence(
                {
                    "operation": "fetch_project_scan_result",
                    "endpoint": "GET /openapi/v1/tasks/{task_id}/comps or comp_leaks",
                    "request_id": None,
                    "error_type": "PartialFetchError",
                    "message": "project scan result is partial",
                }
            )
        )

    epss = intel.get("epss", {}) if isinstance(intel.get("epss"), dict) else {}
    kev = intel.get("kev", {}) if isinstance(intel.get("kev"), dict) else {}
    signals = {
        "version_match": None if version_result is None else version_result.is_match,
        "kev_listed": kev.get("kev_listed"),
        "epss_score": epss.get("epss_score") or epss.get("score"),
        "poc_enable": vulnerability.get("poc_enable"),
        "is_direct": depth.get("is_direct") if depth.get("status") == "found" else reachability.get("status") == "direct_dependency",
        "use_status": component.get("use_status"),
        "evidence": evidence,
        "partial_fetch": scan_partial,
    }
    verdict = suggest_verdict(signals)
    requires_human_review = bool(verdict.get("requires_human_review")) or any(item["type"] == "api_error" for item in evidence)

    result = build_verification_result(
        component=component_ref,
        vulnerability=vulnerability,
        verdict=verdict,
        evidence=evidence,
        risk_factors={
            "cvss_score": vulnerability.get("cvss_v3_score") or vulnerability.get("cvss_three"),
            "epss_score": signals["epss_score"],
            "kev_listed": kev.get("kev_listed"),
            "poc_available": bool(vulnerability.get("poc_enable")),
            "reachability": reachability["status"],
        },
        recommended_actions=_recommended_actions(vulnerability, component),
        project_context=_merge_project_context(scan_result, task_id),
    )
    result["requires_human_review"] = requires_human_review
    result["review_reason"] = verdict.get("review_reason") if requires_human_review else None
    validate_verification_result(result)
    return result


def _failure_result(task_id: int, error: dict[str, Any]) -> dict[str, Any]:
    evidence = [_api_error_evidence(error)]
    verdict = {
        "status": "inconclusive",
        "confidence": "low",
        "reasoning": "task verification could not fetch enough data",
        "requires_human_review": True,
        "review_reason": "task-level API failure",
    }
    result = build_verification_result(
        component={"name": "unknown", "version": "unknown", "task_id": task_id},
        vulnerability={"vuln_id": "unknown"},
        verdict=verdict,
        evidence=evidence,
        risk_factors={},
        recommended_actions=[],
        project_context={"task_id": task_id},
    )
    result["requires_human_review"] = True
    result["review_reason"] = "task-level API failure"
    validate_verification_result(result)
    return result


def _write_jsonl(path: Path, results: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for result in results:
            handle.write(json.dumps(result, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def _write_summary(path: Path, task_id: int, results: list[dict[str, Any]]) -> None:
    status_counts: dict[str, int] = {}
    for result in results:
        status = result["verdict"]["status"]
        status_counts[status] = status_counts.get(status, 0) + 1

    lines = [
        f"# SCA Verification Summary: task {task_id}",
        "",
        f"- Total results: {len(results)}",
        f"- Requires human review: {sum(1 for item in results if item.get('requires_human_review'))}",
        "",
        "## Verdict Counts",
        "",
    ]
    for status, count in sorted(status_counts.items()):
        lines.append(f"- {status}: {count}")
    lines.extend(["", "## Results", "", "| Component | Vulnerability | Verdict | Confidence | Review |", "| --- | --- | --- | --- | --- |"])
    for result in results:
        lines.append(
            "| {component} | {vuln} | {status} | {confidence} | {review} |".format(
                component=f"{result['component']['name']}@{result['component']['version']}",
                vuln=result["vulnerability"].get("vuln_id") or result["vulnerability"].get("cve_id"),
                status=result["verdict"]["status"],
                confidence=result["verdict"]["confidence"],
                review="yes" if result.get("requires_human_review") else "no",
            )
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_fetch_meta(path: Path, metadata: dict[str, Any]) -> None:
    path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def verify_task(
    client: Any,
    task_id: int,
    *,
    output_dir: str | Path = "sca-vuln-verify-output",
    top_n: int | None = None,
    severities: set[str] | list[str] | None = None,
    page_size: int = 100,
    timestamp: str | None = None,
    intel_provider: IntelProvider | None = None,
    max_external_workers: int = 4,
) -> dict[str, Any]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    stamp = timestamp or _utc_timestamp()
    fetch_meta: dict[str, Any] = {"task_id": task_id, "errors": []}

    try:
        scan_result = fetch_project_scan_result(client, task_id, page_size=page_size, allow_partial=True)
        fetch_meta["scan"] = scan_result.get("fetch_meta", {})
    except SCAVulnVerifyError as exc:
        error = _error_metadata("fetch_project_scan_result", f"GET /openapi/v1/tasks/{task_id}", exc)
        fetch_meta["errors"].append(error)
        results = [_failure_result(task_id, error)]
        return _write_task_outputs(output_path, task_id, stamp, results, fetch_meta)

    try:
        dependency_tree = fetch_project_dependency_tree(client, task_id)
        fetch_meta["dependency_tree"] = {
            "source_api": dependency_tree.get("source_api"),
            "request_id": dependency_tree.get("request_id"),
        }
        tree_data = dependency_tree.get("tree")
    except SCAVulnVerifyError as exc:
        error = _error_metadata("fetch_project_dependency_tree", f"GET /openapi/v1/tasks/{task_id}/comp-trees", exc)
        fetch_meta["errors"].append(error)
        tree_data = None

    candidates = _build_candidates(scan_result, task_id)
    if severities:
        allowed = {_severity(item) for item in severities}
        candidates = [
            candidate for candidate in candidates
            if _severity(candidate["vulnerability"].get("level") or candidate["vulnerability"].get("severity")) in allowed
        ]

    cve_ids = {_cve_id(candidate["vulnerability"]) for candidate in candidates}
    cve_ids = {cve_id for cve_id in cve_ids if cve_id}
    intel_map = _fetch_intel_map(cve_ids, intel_provider or _default_intel_provider, max_external_workers)
    for candidate in candidates:
        cve_id = _cve_id(candidate["vulnerability"])
        candidate["intel"] = intel_map.get(cve_id, {}) if cve_id else {}

    candidates.sort(key=_candidate_sort_key, reverse=True)
    if top_n is not None:
        candidates = candidates[:top_n]

    scan_partial = bool(scan_result.get("fetch_meta", {}).get("partial"))
    results = [
        _verify_candidate(
            client,
            candidate,
            task_id=task_id,
            scan_result=scan_result,
            dependency_tree=tree_data,
            scan_partial=scan_partial,
        )
        for candidate in candidates
    ]
    fetch_meta["result_count"] = len(results)
    fetch_meta["candidate_count"] = len(candidates)
    return _write_task_outputs(output_path, task_id, stamp, results, fetch_meta)


def _write_task_outputs(
    output_path: Path,
    task_id: int,
    timestamp: str,
    results: list[dict[str, Any]],
    fetch_meta: dict[str, Any],
) -> dict[str, Any]:
    jsonl_path = output_path / f"task-{task_id}-verification-{timestamp}.jsonl"
    summary_path = output_path / f"task-{task_id}-summary-{timestamp}.md"
    fetch_meta_path = output_path / f"task-{task_id}-fetch-meta-{timestamp}.json"
    _write_jsonl(jsonl_path, results)
    _write_summary(summary_path, task_id, results)
    _write_fetch_meta(fetch_meta_path, fetch_meta)
    return {
        "task_id": task_id,
        "results": results,
        "files": {
            "jsonl": str(jsonl_path),
            "summary": str(summary_path),
            "fetch_meta": str(fetch_meta_path),
        },
        "fetch_meta": fetch_meta,
    }


def verify_batch(
    client: Any,
    *,
    task_id: int | None = None,
    project_id: int | str | None = None,
    output_dir: str | Path = "sca-vuln-verify-output",
    top_n: int | None = None,
    severities: set[str] | list[str] | None = None,
    page_size: int = 100,
    timestamp: str | None = None,
    intel_provider: IntelProvider | None = None,
    max_external_workers: int = 4,
) -> dict[str, Any]:
    if task_id is None and project_id is None:
        raise ValueError("task_id or project_id is required")
    if task_id is not None and project_id is not None:
        raise ValueError("provide either task_id or project_id, not both")

    if task_id is not None:
        task_ids = [task_id]
    else:
        task_ids = [int(task["id"]) for task in discover_project_tasks(client, project_id, page_size=page_size)]

    tasks = [
        verify_task(
            client,
            task,
            output_dir=output_dir,
            top_n=top_n,
            severities=severities,
            page_size=page_size,
            timestamp=timestamp,
            intel_provider=intel_provider,
            max_external_workers=max_external_workers,
        )
        for task in task_ids
    ]
    return {"tasks": tasks, "output_dir": str(output_dir)}
