"""Typed exceptions used by adapters and domain modules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class SCAVulnVerifyError(Exception):
    """Base exception for this package."""


class OpenAPIError(SCAVulnVerifyError):
    """Base exception for SCA OpenAPI adapter failures."""

    def __init__(
        self,
        message: str,
        *,
        endpoint: str | None = None,
        request_id: str | None = None,
        status_code: int | None = None,
        response: Any | None = None,
    ) -> None:
        super().__init__(message)
        self.endpoint = endpoint
        self.request_id = request_id
        self.status_code = status_code
        self.response = response


class OpenAPIAuthError(OpenAPIError):
    """Authentication or authorization failure."""


class OpenAPINotFoundError(OpenAPIError):
    """The requested OpenAPI resource was not found."""


class OpenAPIRateLimitError(OpenAPIError):
    """The OpenAPI server rejected the request due to rate limiting."""


class OpenAPIServerError(OpenAPIError):
    """The OpenAPI server returned a 5xx response."""


class OpenAPIResponseError(OpenAPIError):
    """The OpenAPI server returned an invalid or unsuccessful payload."""


class OpenAPINetworkError(OpenAPIError):
    """Network-level failure while calling OpenAPI."""


class FetchError(SCAVulnVerifyError):
    """Domain-level fetch failure."""

    def __init__(
        self,
        operation: str,
        endpoint: str | None,
        request_id: str | None,
        cause: Exception,
    ) -> None:
        super().__init__(f"{operation} failed at {endpoint or 'unknown endpoint'}: {cause}")
        self.operation = operation
        self.endpoint = endpoint
        self.request_id = request_id
        self.cause = cause


class PartialFetchError(FetchError):
    """A paginated fetch failed after returning partial data."""

    def __init__(
        self,
        operation: str,
        endpoint: str | None,
        request_id: str | None,
        partial_data: Any,
        errors: list[dict[str, Any]],
    ) -> None:
        cause = RuntimeError(errors[-1]["message"] if errors else "partial fetch failed")
        super().__init__(operation, endpoint, request_id, cause)
        self.partial_data = partial_data
        self.errors = errors


class NormalizationError(SCAVulnVerifyError):
    """A raw OpenAPI object could not be normalized into the local schema."""

    def __init__(self, operation: str, raw_ref: Any, cause: Exception | str) -> None:
        super().__init__(f"{operation} normalization failed: {cause}")
        self.operation = operation
        self.raw_ref = raw_ref
        self.cause = cause


class VersionCompareError(SCAVulnVerifyError):
    """A version comparison could not be completed."""

    def __init__(self, version: str, affected_range: dict[str, Any], cause: Exception | str) -> None:
        super().__init__(f"cannot compare version {version!r} with range {affected_range!r}: {cause}")
        self.version = version
        self.affected_range = affected_range
        self.cause = cause


@dataclass(frozen=True)
class ErrorMetadata:
    """Serializable error details for evidence or fetch metadata."""

    error_type: str
    message: str
    request_id: str | None = None
    endpoint: str | None = None
