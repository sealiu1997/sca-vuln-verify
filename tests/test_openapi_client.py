import re

import pytest

import sca_vuln_verify.adapters.sca_openapi as sca_openapi
from sca_vuln_verify.adapters.sca_openapi import SCAOpenAPIClient
from sca_vuln_verify.exceptions import OpenAPIAuthError, OpenAPIResponseError, OpenAPIServerError


def make_client():
    return SCAOpenAPIClient(base_url="https://sca.example.com", access_key="ak", secret_key="sk")


def test_success_response_returns_data_and_request_id(httpx_mock):
    httpx_mock.add_response(
        method="GET",
        url="https://sca.example.com/openapi/v1/tasks/1",
        json={"ok": True, "data": {"id": 1}, "request_id": "req-1"},
    )

    client = make_client()
    response = client.get("/openapi/v1/tasks/1")

    request = httpx_mock.get_requests()[0]
    assert request.headers["AccessKey"] == "ak"
    assert response.data == {"id": 1}
    assert response.request_id == "req-1"


def test_ok_false_raises_response_error(httpx_mock):
    httpx_mock.add_response(
        method="GET",
        url="https://sca.example.com/openapi/v1/tasks/1",
        json={"ok": False, "error": "bad request", "request_id": "req-2"},
    )

    client = make_client()

    with pytest.raises(OpenAPIResponseError) as exc_info:
        client.get("/openapi/v1/tasks/1")

    assert exc_info.value.request_id == "req-2"


def test_auth_status_raises_auth_error(httpx_mock):
    httpx_mock.add_response(
        method="GET",
        url="https://sca.example.com/openapi/v1/tasks/1",
        status_code=403,
        text="forbidden",
    )

    client = make_client()

    with pytest.raises(OpenAPIAuthError):
        client.get("/openapi/v1/tasks/1")


def test_iter_pages_stops_when_has_next_false(httpx_mock):
    httpx_mock.add_response(
        method="GET",
        url=re.compile(r"https://sca\.example\.com/openapi/v1/tasks/1/comps.*"),
        json={
            "ok": True,
            "data": {"page": 1, "has_next": True, "next_num": 2, "items": [{"id": 1}]},
            "request_id": "req-page-1",
        },
    )
    httpx_mock.add_response(
        method="GET",
        url=re.compile(r"https://sca\.example\.com/openapi/v1/tasks/1/comps.*"),
        json={
            "ok": True,
            "data": {"page": 2, "has_next": False, "items": [{"id": 2}]},
            "request_id": "req-page-2",
        },
    )

    client = make_client()
    pages = list(client.iter_pages("/openapi/v1/tasks/1/comps", params={"num": 1}))

    assert [page.request_id for page in pages] == ["req-page-1", "req-page-2"]
    requests = httpx_mock.get_requests()
    assert requests[0].url.params["page"] == "1"
    assert requests[1].url.params["page"] == "2"
    assert requests[1].url.params["num"] == "1"


def test_explicit_zero_max_retries_is_honored(httpx_mock):
    httpx_mock.add_response(
        method="GET",
        url="https://sca.example.com/openapi/v1/tasks/1",
        status_code=500,
        text="server error",
    )

    client = SCAOpenAPIClient(
        base_url="https://sca.example.com",
        access_key="ak",
        secret_key="sk",
        max_retries=0,
    )

    with pytest.raises(OpenAPIServerError):
        client.get("/openapi/v1/tasks/1")

    assert len(httpx_mock.get_requests()) == 1


def test_ssl_verify_parameter_is_passed_to_owned_client(monkeypatch):
    captured = {}

    class FakeHTTPXClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def close(self):
            pass

    monkeypatch.setattr(sca_openapi.httpx, "Client", FakeHTTPXClient)

    client = SCAOpenAPIClient(
        base_url="https://sca.example.com",
        access_key="ak",
        secret_key="sk",
        verify=False,
    )

    assert client.verify is False
    assert captured["verify"] is False


def test_ssl_verify_env_accepts_ca_bundle_path(monkeypatch):
    captured = {}

    class FakeHTTPXClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def close(self):
            pass

    monkeypatch.setattr(sca_openapi.httpx, "Client", FakeHTTPXClient)
    monkeypatch.setenv("SCA_OPENAPI_SSL_VERIFY", "/tmp/sca-ca.pem")

    client = SCAOpenAPIClient(
        base_url="https://sca.example.com",
        access_key="ak",
        secret_key="sk",
    )

    assert client.verify == "/tmp/sca-ca.pem"
    assert captured["verify"] == "/tmp/sca-ca.pem"


def test_ssl_verify_env_can_disable_verification(monkeypatch):
    captured = {}

    class FakeHTTPXClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def close(self):
            pass

    monkeypatch.setattr(sca_openapi.httpx, "Client", FakeHTTPXClient)
    monkeypatch.setenv("SCA_OPENAPI_SSL_VERIFY", "false")

    client = SCAOpenAPIClient(
        base_url="https://sca.example.com",
        access_key="ak",
        secret_key="sk",
    )

    assert client.verify is False
    assert captured["verify"] is False


def test_iter_pages_uses_total_when_has_next_is_missing(httpx_mock):
    httpx_mock.add_response(
        method="GET",
        url=re.compile(r"https://sca\.example\.com/openapi/v1/modules.*"),
        json={
            "ok": True,
            "data": {"page": 1, "per_page": 1, "total": 2, "items": [{"id": 1}]},
            "request_id": "req-page-1",
        },
    )
    httpx_mock.add_response(
        method="GET",
        url=re.compile(r"https://sca\.example\.com/openapi/v1/modules.*"),
        json={
            "ok": True,
            "data": {"page": 2, "per_page": 1, "total": 2, "items": [{"id": 2}]},
            "request_id": "req-page-2",
        },
    )

    client = make_client()
    pages = list(client.iter_pages("/openapi/v1/modules", params={"num": 1}))

    assert [page.request_id for page in pages] == ["req-page-1", "req-page-2"]
