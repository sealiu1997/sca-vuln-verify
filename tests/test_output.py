import json
from pathlib import Path

import pytest
from jsonschema import ValidationError

from sca_vuln_verify.modules.data_process import (
    analyze_dependency_depth,
    check_reachability,
    create_analysis_context,
    update_analysis_context,
)
from sca_vuln_verify.modules.output import build_verification_result, validate_with_schema


FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_design_style_verification_result_validates():
    result = {
        "analysis_id": "analysis-1",
        "timestamp": "2026-05-28T10:00:00Z",
        "component": {
            "name": "log4j-core",
            "version": "2.14.1",
            "sca_comp_id": 100,
            "task_id": 1,
            "language_enum": 1,
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        },
        "vulnerability": {
            "vuln_id": "CVE-2021-44228",
            "cve_id": "CVE-2021-44228",
            "affected_ranges": [],
            "references": [],
        },
        "verdict": {
            "status": "exploitable",
            "confidence": "high",
        },
        "evidence": [
            {
                "type": "version_match",
                "description": "version is affected",
                "source_module": "compare_versions",
                "confidence": "high",
            }
        ],
        "risk_factors": {
            "cvss_score": 10.0,
        },
        "recommended_actions": [],
    }

    validate_with_schema(result, "verification_result.schema.json")


def test_missing_verdict_status_fails_validation():
    result = {
        "analysis_id": "analysis-1",
        "timestamp": "2026-05-28T10:00:00Z",
        "component": {"name": "a", "version": "1"},
        "vulnerability": {"vuln_id": "CVE-1"},
        "verdict": {"confidence": "high"},
        "evidence": [],
        "risk_factors": {},
        "recommended_actions": [],
    }

    with pytest.raises(ValidationError):
        validate_with_schema(result, "verification_result.schema.json")


def test_evidence_requires_source_module():
    result = build_verification_result(
        component={"name": "a", "version": "1"},
        vulnerability={"vuln_id": "CVE-1"},
        verdict={"status": "inconclusive", "confidence": "low"},
        evidence=[],
        risk_factors={},
        recommended_actions=[],
    )
    result["evidence"] = [
        {
            "type": "version_match",
            "description": "missing source module",
            "confidence": "high",
        }
    ]

    with pytest.raises(ValidationError):
        validate_with_schema(result, "verification_result.schema.json")


def test_component_ref_valid_with_only_name_and_version():
    validate_with_schema({"name": "component", "version": "1.0.0"}, "component_ref.schema.json")


def test_vulnerability_info_accepts_any_single_identifier():
    validate_with_schema({"vuln_id": "MS-1"}, "vulnerability_info.schema.json")
    validate_with_schema({"cve_id": "CVE-2021-44228"}, "vulnerability_info.schema.json")


def test_vulnerability_info_requires_at_least_one_identifier():
    with pytest.raises(ValidationError):
        validate_with_schema({"name": "missing id"}, "vulnerability_info.schema.json")


def test_component_detail_fixture_shape_validates():
    component_detail = {
        "ref": {
            "sca_comp_id": 100,
            "name": "log4j-core",
            "version": "2.14.1",
            "language_enum": 1,
        },
        "leaks": load_fixture("openapi_component_detail.json")["leaks"],
        "licenses": load_fixture("openapi_component_detail.json")["licenses"],
        "risk_types": ["存在漏洞"],
        "dep_info": [],
    }

    validate_with_schema(component_detail, "component_detail.schema.json")


def test_analysis_context_is_json_schema_compatible():
    context = create_analysis_context({"type": "component_vuln_analysis"})
    updated = update_analysis_context(
        context,
        fetched_data={"vuln_detail": True},
        key_findings=["version is affected"],
        current_conclusion="inconclusive",
        next_steps=["query EPSS"],
    )

    validate_with_schema(updated, "analysis_context.schema.json")
    assert context["fetched_data"] == {}
    assert updated["key_findings"] == ["version is affected"]


def test_analyze_dependency_depth_detects_direct_dependency():
    tree = {
        "id": 1,
        "name": "root",
        "version": "1",
        "children": [
            {
                "id": 100,
                "name": "log4j-core",
                "version": "2.14.1",
                "language": 1,
            }
        ],
    }

    result = analyze_dependency_depth(tree, {"sca_comp_id": 100, "name": "log4j-core", "version": "2.14.1"})

    assert result["status"] == "found"
    assert result["depth"] == 1
    assert result["is_direct"] is True
    assert result["matched_by"] == "sca_comp_id"


def test_analyze_dependency_depth_detects_transitive_dependency():
    tree = {
        "name": "root",
        "version": "1",
        "children": [
            {
                "name": "spring-core",
                "version": "5.0.0",
                "children": [
                    {"name": "log4j-core", "version": "2.14.1", "language": 1}
                ],
            }
        ],
    }

    result = analyze_dependency_depth(tree, {"name": "log4j-core", "version": "2.14.1", "language_enum": 1})

    assert result["status"] == "found"
    assert result["depth"] == 2
    assert result["is_direct"] is False
    assert [node["name"] for node in result["path"]] == ["root", "spring-core", "log4j-core"]


def test_analyze_dependency_depth_unknown_when_missing():
    result = analyze_dependency_depth([], {"name": "log4j-core", "version": "2.14.1"})

    assert result["status"] == "unknown"
    assert result["confidence"] == "low"


def test_check_reachability_returns_symbol_level_evidence():
    result = check_reachability(
        {
            "ref": {"name": "log4j-core", "version": "2.14.1", "language_enum": 1},
            "dep_type": [0],
            "use_status": "使用",
            "comp_refer": {"current_refer_path": ["pom.xml"]},
        },
        {
            "vuln_id": "CVE-2021-44228",
            "path": [
                {
                    "className": "org.apache.logging.log4j.core.lookup.JndiLookup",
                    "methodFullName": "lookup",
                    "filename": "JndiLookup.java",
                }
            ],
        },
    )

    assert result["status"] == "symbol_level"
    assert result["confidence"] == "medium"
    assert any(item["type"] == "reachability" for item in result["evidence"])


def test_check_reachability_reports_unknown_without_signals():
    result = check_reachability({"ref": {"name": "a", "version": "1"}})

    assert result["status"] == "unknown"
    assert result["confidence"] == "low"
    assert result["evidence"][0]["source_module"] == "check_reachability"


def test_builder_does_not_mutate_input_evidence():
    evidence = [
        {
            "type": "version_match",
            "description": "version is affected",
            "source_module": "compare_versions",
            "confidence": "high",
        }
    ]

    result = build_verification_result(
        component={"name": "a", "version": "1"},
        vulnerability={"vuln_id": "CVE-1"},
        verdict={"status": "inconclusive", "confidence": "low"},
        evidence=evidence,
        risk_factors={},
        recommended_actions=[],
    )
    result["evidence"][0]["description"] = "changed"

    assert evidence[0]["description"] == "version is affected"
