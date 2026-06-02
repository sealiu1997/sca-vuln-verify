import json
from pathlib import Path

from sca_vuln_verify.adapters.sca_openapi import OpenAPIResponse
from sca_vuln_verify.exceptions import OpenAPIServerError
from sca_vuln_verify.workflows.batch import verify_batch


FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def response(data, request_id):
    return OpenAPIResponse(data=data, request_id=request_id, raw={"ok": True, "data": data, "request_id": request_id})


class FakeClient:
    def __init__(self, routes=None, pages=None):
        self.routes = routes or {}
        self.pages = pages or {}
        self.calls = []

    def get(self, path, params=None):
        self.calls.append(("get", path, params or {}))
        value = self.routes[path]
        if isinstance(value, Exception):
            raise value
        return value

    def iter_pages(self, path, params=None):
        self.calls.append(("iter_pages", path, params or {}))
        for value in self.pages[path]:
            if isinstance(value, Exception):
                raise value
            yield value


def fake_intel(cve_id):
    return {
        "epss": {
            "status": "known",
            "cve_id": cve_id,
            "epss_score": 0.975,
            "score": 0.975,
            "percentile": 0.999,
            "source_api": "https://api.first.org/data/v1/epss",
            "cache_status": "test",
        },
        "kev": {
            "status": "known",
            "cve_id": cve_id,
            "kev_listed": True,
            "source_api": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "cache_status": "test",
        },
    }


def make_client():
    return FakeClient(
        routes={
            "/openapi/v1/tasks/1": response(load_fixture("openapi_task_detail.json"), "req-task"),
            "/openapi/v1/tasks/1/comp-trees": response(load_fixture("openapi_dependency_tree.json"), "req-tree"),
            "/openapi/v1/comps/100": response(load_fixture("openapi_component_detail.json"), "req-comp"),
            "/openapi/v1/knowledge-base/leaks": response(load_fixture("openapi_vuln_detail.json"), "req-vuln"),
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


def test_verify_batch_task_outputs_fixed_files(tmp_path):
    result = verify_batch(
        make_client(),
        task_id=1,
        output_dir=tmp_path,
        timestamp="20260602T010203Z",
        intel_provider=fake_intel,
    )

    task = result["tasks"][0]
    assert Path(task["files"]["jsonl"]).name == "task-1-verification-20260602T010203Z.jsonl"
    assert Path(task["files"]["summary"]).name == "task-1-summary-20260602T010203Z.md"
    assert Path(task["files"]["fetch_meta"]).name == "task-1-fetch-meta-20260602T010203Z.json"

    jsonl_rows = [json.loads(line) for line in Path(task["files"]["jsonl"]).read_text(encoding="utf-8").splitlines()]
    assert len(jsonl_rows) == 1
    assert jsonl_rows[0]["component"]["name"] == "log4j-core"
    assert jsonl_rows[0]["verdict"]["status"] == "exploitable"
    assert "Summary" in Path(task["files"]["summary"]).read_text(encoding="utf-8")


def test_verify_batch_marks_api_failure_for_human_review(tmp_path):
    client = make_client()
    client.routes["/openapi/v1/knowledge-base/leaks"] = OpenAPIServerError(
        "server error",
        endpoint="GET /openapi/v1/knowledge-base/leaks",
        request_id="req-vuln-fail",
    )
    client.routes["/openapi/v1/comps/third_party/leak/detail"] = OpenAPIServerError(
        "server error",
        endpoint="GET /openapi/v1/comps/third_party/leak/detail",
        request_id="req-vuln-fallback-fail",
    )

    result = verify_batch(
        client,
        task_id=1,
        output_dir=tmp_path,
        timestamp="20260602T010203Z",
        intel_provider=fake_intel,
    )

    verification = result["tasks"][0]["results"][0]
    assert verification["requires_human_review"] is True
    assert verification["verdict"]["status"] == "inconclusive"
    assert any(item["type"] == "api_error" for item in verification["evidence"])


def test_verify_batch_project_id_discovers_tasks_and_runs(tmp_path):
    client = make_client()
    client.pages["/openapi/v1/modules"] = [
        response(load_fixture("openapi_modules_page1.json"), "req-modules"),
    ]

    result = verify_batch(
        client,
        project_id=99,
        output_dir=tmp_path,
        timestamp="20260602T010203Z",
        intel_provider=fake_intel,
    )

    assert result["tasks"][0]["task_id"] == 1
    assert Path(result["tasks"][0]["files"]["jsonl"]).exists()
    assert ("iter_pages", "/openapi/v1/modules", {"project_id": 99, "num": 100}) in client.calls


def test_verify_batch_severity_filter_can_exclude_candidates(tmp_path):
    result = verify_batch(
        make_client(),
        task_id=1,
        output_dir=tmp_path,
        timestamp="20260602T010203Z",
        severities=["medium"],
        intel_provider=fake_intel,
    )

    task = result["tasks"][0]
    assert task["results"] == []
    assert task["fetch_meta"]["candidate_count"] == 0
    assert Path(task["files"]["jsonl"]).read_text(encoding="utf-8") == ""


def test_verify_batch_top_n_keeps_highest_sorted_candidate(tmp_path):
    client = make_client()
    leaks = load_fixture("openapi_task_comp_leaks_page1.json")
    leaks["items"].append(
        {
            "cve": "CVE-2022-0001",
            "name": "Low severity issue",
            "level": "low",
            "poc_enable": 0,
            "components": [
                {
                    "id": 101,
                    "name": "commons-io",
                    "version": "2.6",
                    "language": 1,
                    "level": 2,
                }
            ],
        }
    )
    client.pages["/openapi/v1/tasks/1/comp_leaks"] = [response(leaks, "req-leaks-1")]

    result = verify_batch(
        client,
        task_id=1,
        output_dir=tmp_path,
        timestamp="20260602T010203Z",
        top_n=1,
        intel_provider=fake_intel,
    )

    verification = result["tasks"][0]["results"][0]
    assert result["tasks"][0]["fetch_meta"]["candidate_count"] == 1
    assert verification["component"]["name"] == "log4j-core"
