"""SCA OpenAPI client."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Iterable

import httpx

from sca_vuln_verify.adapters.sca_openapi_auth import build_auth_headers
from sca_vuln_verify.exceptions import (
    OpenAPIAuthError,
    OpenAPIError,
    OpenAPINetworkError,
    OpenAPINotFoundError,
    OpenAPIRateLimitError,
    OpenAPIResponseError,
    OpenAPIServerError,
)


@dataclass(frozen=True)
class OpenAPIResponse:
    data: Any
    request_id: str | None
    raw: dict[str, Any]


class SCAOpenAPIClient:
    """Small signed client for the SCA OpenAPI."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        timeout_seconds: float | None = None,
        max_retries: int | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = (base_url or os.getenv("SCA_OPENAPI_BASE_URL") or "").rstrip("/")
        self.access_key = access_key or os.getenv("SCA_OPENAPI_ACCESS_KEY") or ""
        self.secret_key = secret_key or os.getenv("SCA_OPENAPI_SECRET_KEY") or ""
        self.timeout_seconds = (
            float(timeout_seconds)
            if timeout_seconds is not None
            else float(os.getenv("SCA_OPENAPI_TIMEOUT_SECONDS") or 30)
        )
        self.max_retries = (
            int(max_retries)
            if max_retries is not None
            else int(os.getenv("SCA_OPENAPI_MAX_RETRIES") or 2)
        )

        if not self.base_url:
            raise ValueError("SCA OpenAPI base_url is required")
        if not self.access_key:
            raise ValueError("SCA OpenAPI access_key is required")
        if not self.secret_key:
            raise ValueError("SCA OpenAPI secret_key is required")

        self._client = client or httpx.Client(base_url=self.base_url, timeout=self.timeout_seconds)
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "SCAOpenAPIClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def get(self, path: str, params: dict[str, Any] | None = None) -> OpenAPIResponse:
        return self._request("GET", path, params=params)

    def post(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        json: Any | None = None,
        files: Any | None = None,
    ) -> OpenAPIResponse:
        return self._request("POST", path, params=params, json=json, files=files)

    def iter_pages(
        self,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> Iterable[OpenAPIResponse]:
        page_params = dict(params or {})
        page_params.setdefault("page", 1)

        while True:
            response = self.get(path, params=page_params)
            yield response

            page_data = response.data if isinstance(response.data, dict) else {}
            has_next = bool(page_data.get("has_next"))
            if not has_next:
                break
            next_num = page_data.get("next_num") or int(page_params.get("page", 1)) + 1
            page_params["page"] = next_num

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any | None = None,
        files: Any | None = None,
    ) -> OpenAPIResponse:
        clean_params = {key: value for key, value in (params or {}).items() if value is not None}
        attempts = 1 + self.max_retries

        for attempt in range(attempts):
            last_attempt = attempt == attempts - 1

            request = self._client.build_request(
                method,
                path,
                params=clean_params,
                json=json if files is None else None,
                files=files,
            )
            body = request.read()
            request.headers.update(
                build_auth_headers(
                    access_key=self.access_key,
                    secret_key=self.secret_key,
                    method=method,
                    params=clean_params,
                    body=body,
                    is_multipart=files is not None,
                )
            )

            try:
                response = self._client.send(request)
            except httpx.RequestError as exc:
                if last_attempt:
                    raise OpenAPINetworkError(str(exc), endpoint=f"{method} {path}") from exc
                continue

            try:
                return self._handle_response(response, method=method, path=path)
            except OpenAPIServerError:
                if last_attempt:
                    raise
                continue

        # This should never be reached, but satisfies the type checker.
        raise OpenAPINetworkError("max retries exhausted", endpoint=f"{method} {path}")  # pragma: no cover

    def _handle_response(self, response: httpx.Response, *, method: str, path: str) -> OpenAPIResponse:
        endpoint = f"{method.upper()} {path}"
        request_id = response.headers.get("X-Request-Id")

        if response.status_code in {401, 403}:
            raise OpenAPIAuthError(
                response.text,
                endpoint=endpoint,
                request_id=request_id,
                status_code=response.status_code,
            )
        if response.status_code == 404:
            raise OpenAPINotFoundError(
                response.text,
                endpoint=endpoint,
                request_id=request_id,
                status_code=response.status_code,
            )
        if response.status_code == 429:
            raise OpenAPIRateLimitError(
                response.text,
                endpoint=endpoint,
                request_id=request_id,
                status_code=response.status_code,
            )
        if response.status_code >= 500:
            raise OpenAPIServerError(
                response.text,
                endpoint=endpoint,
                request_id=request_id,
                status_code=response.status_code,
            )
        if response.status_code >= 400:
            raise OpenAPIResponseError(
                response.text,
                endpoint=endpoint,
                request_id=request_id,
                status_code=response.status_code,
            )

        try:
            raw = response.json()
        except ValueError as exc:
            raise OpenAPIResponseError(
                "response body is not valid JSON",
                endpoint=endpoint,
                request_id=request_id,
                status_code=response.status_code,
            ) from exc

        if not isinstance(raw, dict):
            raise OpenAPIResponseError(
                "response JSON is not an object",
                endpoint=endpoint,
                request_id=request_id,
                status_code=response.status_code,
                response=raw,
            )

        request_id = raw.get("request_id") or request_id
        if raw.get("ok") is False:
            message = raw.get("error") or raw.get("message") or "OpenAPI response ok=false"
            raise OpenAPIResponseError(
                str(message),
                endpoint=endpoint,
                request_id=request_id,
                status_code=response.status_code,
                response=raw,
            )

        return OpenAPIResponse(data=raw.get("data"), request_id=request_id, raw=raw)


def map_http_error(exc: OpenAPIError) -> dict[str, Any]:
    """Serialize OpenAPI exceptions for fetch metadata."""

    return {
        "error_type": type(exc).__name__,
        "message": str(exc),
        "endpoint": exc.endpoint,
        "request_id": exc.request_id,
        "status_code": exc.status_code,
    }
