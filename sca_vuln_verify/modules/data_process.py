"""Data processing helpers."""

from __future__ import annotations

import copy
from typing import Any

from sca_vuln_verify.utils.purl import parse_purl
from sca_vuln_verify.utils.version_compare import VersionMatchResult, compare_version_range, sort_versions


def compare_versions(
    version: str,
    affected_range: dict[str, Any],
    ecosystem: str | None = None,
) -> VersionMatchResult:
    return compare_version_range(version, affected_range, ecosystem=ecosystem)


def create_analysis_context(task: dict[str, Any]) -> dict[str, Any]:
    return {
        "task": copy.deepcopy(task),
        "fetched_data": {},
        "key_findings": [],
        "current_conclusion": None,
        "next_steps": [],
    }


def update_analysis_context(
    context: dict[str, Any],
    fetched_data: dict[str, Any] | None = None,
    key_findings: list[str] | str | None = None,
    current_conclusion: str | None = None,
    next_steps: list[str] | str | None = None,
) -> dict[str, Any]:
    updated = copy.deepcopy(context)
    updated.setdefault("fetched_data", {})
    updated.setdefault("key_findings", [])
    updated.setdefault("next_steps", [])

    if fetched_data:
        updated["fetched_data"].update(fetched_data)
    if key_findings:
        findings = [key_findings] if isinstance(key_findings, str) else key_findings
        updated["key_findings"].extend(str(item) for item in findings)
    if current_conclusion is not None:
        updated["current_conclusion"] = current_conclusion
    if next_steps is not None:
        steps = [next_steps] if isinstance(next_steps, str) else next_steps
        updated["next_steps"] = [str(item) for item in steps]
    return updated


def _tree_roots(dependency_tree: Any) -> list[dict[str, Any]]:
    if isinstance(dependency_tree, dict) and "tree" in dependency_tree:
        dependency_tree = dependency_tree["tree"]
    if isinstance(dependency_tree, dict):
        return [dependency_tree]
    if isinstance(dependency_tree, list):
        return [item for item in dependency_tree if isinstance(item, dict)]
    return []


def _node_ref(node: dict[str, Any]) -> dict[str, Any]:
    return {
        key: node.get(key)
        for key in ("id", "name", "version", "language", "path", "type")
        if node.get(key) is not None
    }


def _match_node(node: dict[str, Any], component_ref: dict[str, Any]) -> str | None:
    comp_id = component_ref.get("sca_comp_id") or component_ref.get("id")
    if comp_id is not None and node.get("id") is not None and str(node.get("id")) == str(comp_id):
        return "sca_comp_id"

    if node.get("name") != component_ref.get("name") or node.get("version") != component_ref.get("version"):
        return None

    ref_language = component_ref.get("language_enum") or component_ref.get("language")
    node_language = node.get("language")
    if ref_language is not None and node_language is not None and str(ref_language) == str(node_language):
        return "name_version_language"
    return "name_version"


def analyze_dependency_depth(dependency_tree: Any, component_ref: dict[str, Any]) -> dict[str, Any]:
    roots = _tree_roots(dependency_tree)
    if not roots:
        return {
            "status": "unknown",
            "depth": None,
            "path": [],
            "is_direct": None,
            "matched_by": None,
            "confidence": "low",
            "reason": "dependency tree is empty",
        }

    stack: list[tuple[dict[str, Any], int, list[dict[str, Any]]]] = [
        (root, 0, [_node_ref(root)])
        for root in roots
    ]
    while stack:
        node, depth, path = stack.pop(0)
        matched_by = _match_node(node, component_ref)
        if matched_by:
            return {
                "status": "found",
                "depth": depth,
                "path": path,
                "is_direct": depth == 1,
                "matched_by": matched_by,
                "confidence": "high" if matched_by == "sca_comp_id" else "medium",
            }
        for child in node.get("children", []) or []:
            if isinstance(child, dict):
                stack.append((child, depth + 1, [*path, _node_ref(child)]))

    return {
        "status": "unknown",
        "depth": None,
        "path": [],
        "is_direct": None,
        "matched_by": None,
        "confidence": "low",
        "reason": "component was not found in dependency tree",
    }


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _component_ref(component: dict[str, Any]) -> dict[str, Any]:
    ref = component.get("ref")
    return ref if isinstance(ref, dict) else component


def _dep_values(component: dict[str, Any]) -> set[int]:
    values: set[int] = set()
    for value in _as_list(component.get("dep_type")):
        try:
            values.add(int(value))
        except (TypeError, ValueError):
            continue
    for item in _as_list(component.get("dep_info")):
        if not isinstance(item, dict):
            continue
        try:
            values.add(int(item.get("value")))
        except (TypeError, ValueError):
            continue
    return values


def _is_java_or_go(component: dict[str, Any]) -> bool:
    ref = _component_ref(component)
    language_value = ref.get("language_enum") or ref.get("language") or component.get("language")
    try:
        return int(language_value) in {1, 10}
    except (TypeError, ValueError):
        return str(language_value).strip().lower() in {"java", "go", "golang"}


def _use_status_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "reported_used" if value else "reported_unused"
    if isinstance(value, (int, float)):
        return "reported_used" if value != 0 else "reported_unused"
    normalized = str(value).strip().lower()
    if normalized in {"使用", "used", "true", "yes", "1"}:
        return "reported_used"
    if normalized in {"未使用", "unused", "false", "no", "0"}:
        return "reported_unused"
    return None


def _refer_paths(component: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    comp_refer = component.get("comp_refer")
    if isinstance(comp_refer, dict):
        for key in ("current_refer_path", "root_refer_path"):
            for value in _as_list(comp_refer.get(key)):
                if value:
                    paths.append(str(value))
    for item in _as_list(component.get("indirect_comp")):
        if not isinstance(item, dict):
            continue
        for value in _as_list(item.get("refs_com_path")):
            if value:
                paths.append(str(value))
    return paths


def _symbol_paths(vulnerability: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not vulnerability:
        return []
    paths: list[dict[str, Any]] = []
    for item in _as_list(vulnerability.get("path")):
        if not isinstance(item, dict):
            continue
        if any(item.get(key) for key in ("className", "methodFullName", "symbol", "filename")):
            paths.append(
                {
                    key: item.get(key)
                    for key in ("className", "methodFullName", "symbol", "filename", "lineNumber")
                    if item.get(key) not in (None, "")
                }
            )
    return paths


def _reachability_evidence(
    description: str,
    confidence: str,
    raw_ref: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence = {
        "type": "reachability",
        "description": description,
        "source_module": "check_reachability",
        "confidence": confidence,
    }
    if raw_ref:
        evidence["raw_ref"] = raw_ref
    return evidence


def check_reachability(
    component: dict[str, Any],
    vulnerability: dict[str, Any] | None = None,
    project_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    dep_values = _dep_values(component)
    refer_paths = _refer_paths(component)
    symbol_paths = _symbol_paths(vulnerability)
    evidence: list[dict[str, Any]] = []
    signals: list[str] = []

    if 0 in dep_values:
        signals.append("direct_dependency")
        evidence.append(
            _reachability_evidence(
                "component is reported as a direct dependency",
                "low",
                {"dep_type": component.get("dep_type"), "dep_info": component.get("dep_info")},
            )
        )
    elif 1 in dep_values:
        signals.append("transitive_dependency")
        evidence.append(
            _reachability_evidence(
                "component is reported as a transitive dependency",
                "low",
                {"dep_type": component.get("dep_type"), "dep_info": component.get("dep_info")},
            )
        )

    use_status_signal = None
    if _is_java_or_go(component):
        use_status_signal = _use_status_value(component.get("use_status"))
        if use_status_signal:
            signals.append(use_status_signal)
            evidence.append(
                _reachability_evidence(
                    "SCA reports component use status as used"
                    if use_status_signal == "reported_used"
                    else "SCA reports component use status as unused",
                    "medium",
                    {"use_status": component.get("use_status")},
                )
            )

    if refer_paths:
        evidence.append(
            _reachability_evidence(
                "component reference path is available",
                "medium",
                {"paths": refer_paths[:10]},
            )
        )

    if symbol_paths:
        signals.append("symbol_level")
        evidence.append(
            _reachability_evidence(
                "vulnerability detail includes symbol-level path data",
                "medium",
                {"path": symbol_paths[:10]},
            )
        )

    if symbol_paths:
        status = "symbol_level"
        confidence = "medium"
    elif use_status_signal:
        status = use_status_signal
        confidence = "medium"
    elif 0 in dep_values:
        status = "direct_dependency"
        confidence = "low"
    elif 1 in dep_values:
        status = "transitive_dependency"
        confidence = "low"
    else:
        status = "unknown"
        confidence = "low"
        evidence.append(
            _reachability_evidence(
                "no dependency, use-status, reference-path, or symbol-level signal is available",
                "low",
            )
        )

    return {
        "status": status,
        "confidence": confidence,
        "signals": signals or ["unknown"],
        "evidence": evidence,
        "project_context": copy.deepcopy(project_context),
    }


def _version_value(item: Any) -> str | None:
    if isinstance(item, str):
        return item
    if isinstance(item, dict) and item.get("version") is not None:
        return str(item["version"])
    return None


def _is_greater_than_current(candidate: str, current_version: str, ecosystem: str | None) -> bool:
    result = compare_version_range(
        candidate,
        {"start_version": current_version, "start_open": True, "end_version": None},
        ecosystem=ecosystem,
    )
    return result.is_match is True


def _is_unaffected(candidate: str, affected_ranges: list[dict[str, Any]], ecosystem: str | None) -> bool:
    for affected_range in affected_ranges:
        result = compare_version_range(candidate, affected_range, ecosystem=ecosystem)
        if result.is_match is not False:
            return False
    return True


def match_fix_version(
    current_version: str,
    versions: list[Any],
    affected_ranges: list[dict[str, Any]],
    ecosystem: str | None = None,
) -> str | None:
    version_values = [value for value in (_version_value(item) for item in versions) if value]
    for candidate in sort_versions(version_values):
        if not _is_greater_than_current(candidate, current_version, ecosystem):
            continue
        if _is_unaffected(candidate, affected_ranges, ecosystem):
            return candidate
    return None


__all__ = [
    "parse_purl",
    "compare_versions",
    "VersionMatchResult",
    "create_analysis_context",
    "update_analysis_context",
    "analyze_dependency_depth",
    "check_reachability",
    "match_fix_version",
]
