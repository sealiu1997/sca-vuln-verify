import json
from pathlib import Path

import pytest

from sca_vuln_verify.adapters.sca_openapi import OpenAPIResponse
from sca_vuln_verify.exceptions import (
    FetchError,
    NormalizationError,
    OpenAPIResponseError,
    OpenAPIServerError,
    PartialFetchError,
)
from sca_vuln_verify.modules.data_fetch import (
    discover_project_tasks,
    fetch_component_detail,
    fetch_component_code_location,
    fetch_component_versions,
    fetch_project_dependency_tree,
    fetch_project_scan_result,
    fetch_vuln_affected_components,
    fetch_vuln_detail,
    fetch_vuln_fix_info,
)
from sca_vuln_verify.utils.language import language_enum_to_ecosystem
from sca_vuln_verify.utils.purl import build_maven_purl_from_gav, parse_purl
from sca_vuln_verify.utils.purl_sca_mapper import component_ref_from_sca_row


FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class FakeClient:
    def __init__(self, routes=None, pages=None):
        self.routes = routes or {}
        self.pages = pages or {}
        self.calls = []

    def get(self, path, params=None):
        self.calls.append(("get", path, params or {}))
        response = self.routes[path]
        if isinstance(response, Exception):
            raise response
        return response

    def iter_pages(self, path, params=None):
        self.calls.append(("iter_pages", path, params or {}))
        for response in self.pages[path]:
            if isinstance(response, Exception):
                raise response
            yield response


def response(data, request_id):
    return OpenAPIResponse(data=data, request_id=request_id, raw={"ok": True, "data": data, "request_id": request_id})


def test_maven_gav_maps_to_purl():
    assert (
        build_maven_purl_from_gav("org.apache.logging.log4j:log4j-core:2.14.1")
        == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    )


def test_unknown_language_returns_unknown():
    assert language_enum_to_ecosystem(999) == "unknown"


def test_invalid_purl_raises_typed_error():
    with pytest.raises(NormalizationError):
        parse_purl("not-a-purl")


def test_component_ref_from_task_component_row():
    row = {
        "id": 100,
        "name": "log4j-core",
        "version": "2.14.1",
        "language": 1,
        "gav_coordinate": "org.apache.logging.log4j:log4j-core:2.14.1",
    }

    ref = component_ref_from_sca_row(row, task_id=1)

    assert ref["sca_comp_id"] == 100
    assert ref["task_id"] == 1
    assert ref["ecosystem"] == "maven"
    assert ref["purl"] == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


def test_fetch_vuln_detail_normalizes_and_filters_fields():
    client = FakeClient(
        routes={
            "/openapi/v1/knowledge-base/leaks": response(load_fixture("openapi_vuln_detail.json"), "req-vuln"),
        }
    )

    vuln = fetch_vuln_detail(client, "CVE-2021-44228")

    assert vuln["vuln_id"] == "CVE-2021-44228"
    assert vuln["cvss_v3_score"] == 10.0
    assert vuln["affected_ranges"][0]["start_version"] == "2.0-beta9"
    assert vuln["references"] == ["https://logging.apache.org/log4j/2.x/security.html"]
    assert vuln["solution"] == "Upgrade to 2.17.0 or later."
    assert vuln["path"][0]["filename"] == "JndiLookup.java"
    assert "node" not in vuln["path"][0]
    assert "firm" not in vuln


def test_fetch_component_detail_normalizes_component_fields():
    client = FakeClient(
        routes={
            "/openapi/v1/comps/100": response(load_fixture("openapi_component_detail.json"), "req-comp"),
        }
    )

    detail = fetch_component_detail(client, {"sca_comp_id": 100, "name": "log4j-core", "version": "2.14.1"}, project_id=10)

    assert detail["ref"]["purl"] == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    assert detail["licenses"][0] == {
        "license": "Apache-2.0",
        "spdx_id": "Apache-2.0",
        "license_level": "safe",
        "license_problem": 0,
    }
    assert detail["leaks"][0]["cve_id"] == "CVE-2021-44228"
    assert "firm" not in detail["leaks"][0]
    assert "projects" not in detail


def test_fetch_project_scan_result_paginates_and_indexes_vulnerabilities():
    client = FakeClient(
        routes={
            "/openapi/v1/tasks/1": response(load_fixture("openapi_task_detail.json"), "req-task"),
        },
        pages={
            "/openapi/v1/tasks/1/comps": [
                response(load_fixture("openapi_task_comps_page1.json"), "req-comps-1"),
                response(load_fixture("openapi_task_comps_page2.json"), "req-comps-2"),
            ],
            "/openapi/v1/tasks/1/comp_leaks": [
                response(load_fixture("openapi_task_comp_leaks_page1.json"), "req-leaks-1"),
            ],
        },
    )

    result = fetch_project_scan_result(client, 1, page_size=1)

    assert result["task"]["project_name"] == "my-service"
    assert len(result["components"]) == 2
    assert len(result["vulnerabilities"]) == 1
    assert result["component_vulnerability_index"]["by_component_id"]["100"][0]["cve_id"] == "CVE-2021-44228"
    assert "req-comps-1" in result["fetch_meta"]["request_ids"]
    assert result["fetch_meta"]["partial"] is False


def test_fetch_project_dependency_tree_filters_children():
    client = FakeClient(
        routes={
            "/openapi/v1/tasks/1/comp-trees": response(load_fixture("openapi_dependency_tree.json"), "req-tree"),
        }
    )

    result = fetch_project_dependency_tree(client, 1)

    child = result["tree"]["children"][0]
    assert child["name"] == "log4j-core"
    assert child["leak_serious"] == 1
    assert "licenses" not in child


def test_project_scan_partial_failure_raises_by_default():
    client = FakeClient(
        routes={
            "/openapi/v1/tasks/1": response(load_fixture("openapi_task_detail.json"), "req-task"),
        },
        pages={
            "/openapi/v1/tasks/1/comps": [
                response(load_fixture("openapi_task_comps_page1.json"), "req-comps-1"),
                OpenAPIServerError("server error", endpoint="GET /openapi/v1/tasks/1/comps", request_id="req-fail"),
            ],
            "/openapi/v1/tasks/1/comp_leaks": [],
        },
    )

    with pytest.raises(PartialFetchError) as exc_info:
        fetch_project_scan_result(client, 1)

    assert exc_info.value.partial_data["components"][0]["ref"]["name"] == "log4j-core"
    assert exc_info.value.errors[0]["page"] == 2


def test_project_scan_allow_partial_returns_error_metadata():
    client = FakeClient(
        routes={
            "/openapi/v1/tasks/1": response(load_fixture("openapi_task_detail.json"), "req-task"),
        },
        pages={
            "/openapi/v1/tasks/1/comps": [
                response(load_fixture("openapi_task_comps_page1.json"), "req-comps-1"),
                OpenAPIServerError("server error", endpoint="GET /openapi/v1/tasks/1/comps", request_id="req-fail"),
            ],
            "/openapi/v1/tasks/1/comp_leaks": [
                response(load_fixture("openapi_task_comp_leaks_page1.json"), "req-leaks-1"),
            ],
        },
    )

    result = fetch_project_scan_result(client, 1, allow_partial=True)

    assert result["fetch_meta"]["partial"] is True
    assert result["fetch_meta"]["errors"][0]["error_type"] == "OpenAPIServerError"
    assert len(result["components"]) == 1


def test_fetch_component_versions_uses_component_id_endpoint():
    client = FakeClient(
        routes={
            "/openapi/v1/comps/100/versions": response(load_fixture("openapi_component_versions.json"), "req-versions"),
        }
    )

    versions = fetch_component_versions(client, {"sca_comp_id": 100, "name": "log4j-core", "version": "2.14.1"})

    assert versions[1]["version"] == "2.17.0"
    assert versions[1]["is_recommended_version"] is True
    assert versions[1]["source_api"] == "GET /openapi/v1/comps/100/versions"


def test_fetch_component_versions_falls_back_to_knowledge_base():
    client = FakeClient(
        routes={
            "/openapi/v1/knowledge-base/comps/versions": response(
                load_fixture("openapi_kb_component_versions.json"),
                "req-kb-versions",
            ),
        }
    )

    versions = fetch_component_versions(client, {"name": "log4j-core", "version": "2.14.1", "language_enum": 1})

    assert [item["version"] for item in versions] == ["2.14.1", "2.15.0", "2.16.0", "2.17.0"]
    assert client.calls[0][2] == {"name": "log4j-core", "language": 1}


def test_fetch_component_versions_skips_null_knowledge_base_versions(caplog):
    client = FakeClient(
        routes={
            "/openapi/v1/knowledge-base/comps/versions": response(
                {"comp_type": 1, "language": 1, "total": 1, "versions": [None]},
                "req-null-versions",
            ),
        }
    )
    caplog.set_level("WARNING")

    versions = fetch_component_versions(client, {"name": "log4j-core", "version": "2.14.1", "language_enum": 1})

    assert versions == []
    assert "valid_versions=0" in caplog.text


def test_fetch_vuln_affected_components_reuses_vuln_normalization():
    client = FakeClient(
        routes={
            "/openapi/v1/knowledge-base/leaks": response(load_fixture("openapi_vuln_detail.json"), "req-vuln"),
        }
    )

    affected = fetch_vuln_affected_components(client, "CVE-2021-44228")

    assert affected[0]["component_name"] == "log4j-core"
    assert affected[0]["vuln_id"] == "CVE-2021-44228"
    assert affected[0]["request_id"] == "req-vuln"


def test_fetch_component_code_location_combines_file_tree_and_vuln_path():
    client = FakeClient(
        routes={
            "/openapi/v1/knowledge-base/leaks": response(load_fixture("openapi_vuln_detail.json"), "req-vuln"),
        },
        pages={
            "/openapi/v2/tasks/1/file-path": [
                response(load_fixture("openapi_file_path_page1.json"), "req-file-path"),
            ],
        },
    )

    result = fetch_component_code_location(
        client,
        1,
        {
            "sca_comp_id": 100,
            "name": "log4j-core",
            "version": "2.14.1",
            "comp_refer": {"current_refer_path": "pom.xml"},
        },
        vuln_id="CVE-2021-44228",
    )

    assert {item["source_type"] for item in result["locations"]} == {
        "file_tree",
        "component_refer",
        "vuln_path",
    }
    assert result["locations"][0]["path"] == "pom.xml"
    assert "req-file-path" in result["request_ids"]


def test_fetch_vuln_fix_info_does_not_fabricate_commit_metadata():
    client = FakeClient(
        routes={
            "/openapi/v1/knowledge-base/leaks": response(load_fixture("openapi_vuln_detail.json"), "req-vuln"),
            "/openapi/v1/comps/100": response(load_fixture("openapi_component_detail.json"), "req-comp"),
            "/openapi/v1/comps/100/versions": response(load_fixture("openapi_component_versions.json"), "req-versions"),
        }
    )

    fix_info = fetch_vuln_fix_info(
        client,
        "CVE-2021-44228",
        {"sca_comp_id": 100, "name": "log4j-core", "version": "2.14.1"},
    )

    assert fix_info["solution"] == "Upgrade to 2.17.0 or later."
    assert fix_info["recommended_upgrade_version"]["version"] == "2.17.0"
    assert "commit" not in fix_info


def test_discover_project_tasks_reads_stable_task_ids_from_modules():
    client = FakeClient(
        pages={
            "/openapi/v1/modules": [
                response(load_fixture("openapi_modules_page1.json"), "req-modules"),
            ],
        },
    )

    tasks = discover_project_tasks(client, 99)

    assert tasks == [
        {
            "id": 1,
            "name": "main",
            "status": 3,
            "module_id": 10,
            "module_name": "backend",
            "project_id": 99,
            "project_name": "my-service",
            "source_api": "GET /openapi/v1/modules",
            "request_id": "req-modules",
        }
    ]


def test_discover_project_tasks_resolves_project_name_before_modules():
    client = FakeClient(
        pages={
            "/openapi/v1/projects": [
                response(load_fixture("openapi_projects_page1.json"), "req-projects"),
            ],
            "/openapi/v1/modules": [
                response(load_fixture("openapi_modules_page1.json"), "req-modules"),
            ],
        },
    )

    tasks = discover_project_tasks(client, "my-service")

    assert tasks[0]["project_id"] == 99
    assert client.calls[0] == ("iter_pages", "/openapi/v1/projects", {"name": "my-service", "num": 100})


def test_discover_project_tasks_reports_task_names_without_stable_ids():
    client = FakeClient(
        pages={
            "/openapi/v1/modules": [
                response(
                    {
                        "page": 1,
                        "per_page": 1,
                        "total": 1,
                        "items": [
                            {
                                "id": 10,
                                "name": "backend",
                                "project_id": 99,
                                "project_name": "my-service",
                                "task_names": ["main"],
                            }
                        ],
                    },
                    "req-modules",
                ),
            ],
        },
    )

    with pytest.raises(FetchError) as exc_info:
        discover_project_tasks(client, 99)

    assert "pass task_ids" in str(exc_info.value)


def test_discover_project_tasks_can_scan_explicit_task_id_range():
    client = FakeClient(
        routes={
            "/openapi/v1/tasks/1": OpenAPIResponseError(
                "record not found",
                endpoint="GET /openapi/v1/tasks/1",
                request_id="req-task-1",
            ),
            "/openapi/v1/tasks/2": response(
                {"id": 2, "name": "other-project-task", "project_id": 100},
                "req-task-2",
            ),
            "/openapi/v1/tasks/3": response(
                {
                    "id": 3,
                    "name": "main",
                    "project_id": 99,
                    "project_name": "my-service",
                    "module_id": 10,
                    "module_name": "backend",
                    "check_status_num": 3,
                },
                "req-task-3",
            ),
        },
        pages={
            "/openapi/v1/modules": [
                response(
                    {
                        "page": 1,
                        "per_page": 1,
                        "total": 1,
                        "items": [
                            {
                                "id": 10,
                                "name": "backend",
                                "project_id": 99,
                                "project_name": "my-service",
                                "task_names": ["main"],
                            }
                        ],
                    },
                    "req-modules",
                ),
            ],
        },
    )

    tasks = discover_project_tasks(client, 99, task_scan_range=(1, 3))

    assert [task["id"] for task in tasks] == [3]
    assert tasks[0]["source_api"] == "GET /openapi/v1/tasks/3"
