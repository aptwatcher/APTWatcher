"""
Tests for HTTPIOCProviderBase via httpx.MockTransport.

We define a minimal concrete subclass here and drive it through:
- Happy path (request shape, parsing).
- Unsupported IOC type → IOCUnsupportedError.
- Timeout → IOCTimeoutError.
- Transport error → IOCTransportError.
- Header + params + default_headers merging.
- Close idempotency, and owned vs injected client.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx
import pytest

from core.intel import (
    HTTPIOCProviderBase,
    IOCProviderError,
    IOCQuery,
    IOCTimeoutError,
    IOCTransportError,
    IOCUnsupportedError,
)
from core.types import IOCProviderResult


class _FakeIntelProvider(HTTPIOCProviderBase):
    name = "fake-intel"
    supported_types = frozenset({"ipv4", "domain"})

    def _build_request(
        self,
        request: IOCQuery,
    ) -> tuple[
        str,
        str,
        Mapping[str, str] | None,
        Mapping[str, Any] | None,
        Any,
    ]:
        return (
            "GET",
            f"/v1/lookup/{request.ioc_type}",
            {"X-Extra": "1"},
            {"value": request.value},
            None,
        )

    def _parse_response(self, response: httpx.Response) -> IOCProviderResult:
        if response.status_code != 200:
            raise IOCProviderError(
                f"{self.name} HTTP {response.status_code}"
            )
        body = response.json()
        return IOCProviderResult(
            name=self.name,
            verdict=body["verdict"],
            score=body.get("score"),
            raw=body,
        )


def _client_with_handler(
    handler,
    *,
    default_headers: Mapping[str, str] | None = None,
) -> _FakeIntelProvider:
    transport = httpx.MockTransport(handler)
    http = httpx.Client(transport=transport)
    return _FakeIntelProvider(
        base_url="https://intel.example",
        http_client=http,
        default_headers=default_headers or {"Authorization": "Bearer k"},
        timeout_s=5.0,
    )


def test_happy_path_builds_request_and_parses_response() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        captured["extra"] = request.headers.get("x-extra")
        return httpx.Response(
            200,
            json={"verdict": "malicious", "score": 0.9, "note": "test"},
        )

    provider = _client_with_handler(handler)
    result = provider.query(IOCQuery("1.2.3.4", "ipv4"))

    assert result.verdict == "malicious"
    assert result.score == 0.9
    assert result.name == "fake-intel"
    assert captured["method"] == "GET"
    assert captured["url"] == (
        "https://intel.example/v1/lookup/ipv4?value=1.2.3.4"
    )
    assert captured["auth"] == "Bearer k"
    assert captured["extra"] == "1"


def test_unsupported_ioc_type_raises_unsupported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("network must not be hit for unsupported types")

    provider = _client_with_handler(handler)
    with pytest.raises(IOCUnsupportedError):
        provider.query(IOCQuery("abcd1234" * 8, "sha256"))


def test_timeout_raises_ioctimeouterror() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("too slow", request=request)

    provider = _client_with_handler(handler)
    with pytest.raises(IOCTimeoutError):
        provider.query(IOCQuery("1.2.3.4", "ipv4"))


def test_transport_error_raises_ioctransporterror() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    provider = _client_with_handler(handler)
    with pytest.raises(IOCTransportError):
        provider.query(IOCQuery("1.2.3.4", "ipv4"))


def test_non_200_wraps_in_ioc_provider_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    provider = _client_with_handler(handler)
    with pytest.raises(IOCProviderError):
        provider.query(IOCQuery("1.2.3.4", "ipv4"))


def test_default_headers_merge_with_per_request_headers() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization", "")
        seen["extra"] = request.headers.get("x-extra", "")
        return httpx.Response(200, json={"verdict": "benign", "score": 0.0})

    provider = _client_with_handler(
        handler,
        default_headers={"Authorization": "Bearer default", "X-Common": "yes"},
    )
    provider.query(IOCQuery("1.2.3.4", "ipv4"))
    assert seen["auth"] == "Bearer default"
    assert seen["extra"] == "1"


def test_close_is_idempotent_and_closes_owned_client() -> None:
    # Owned client path: no http_client passed.
    provider = _FakeIntelProvider(
        base_url="https://intel.example", timeout_s=1.0
    )
    assert provider._closed is False
    provider.close()
    assert provider._closed is True
    provider.close()  # must not raise


def test_close_does_not_close_injected_client() -> None:
    transport = httpx.MockTransport(
        lambda r: httpx.Response(200, json={"verdict": "unknown"})
    )
    http = httpx.Client(transport=transport)
    provider = _FakeIntelProvider(
        base_url="https://intel.example", http_client=http, timeout_s=1.0,
    )
    provider.close()
    # injected client still usable by the test
    r = http.get("https://intel.example/v1/lookup/ipv4")
    assert r.status_code == 200
    http.close()


def test_query_after_close_raises() -> None:
    transport = httpx.MockTransport(
        lambda r: httpx.Response(200, json={"verdict": "unknown"})
    )
    http = httpx.Client(transport=transport)
    provider = _FakeIntelProvider(
        base_url="https://intel.example", http_client=http, timeout_s=1.0,
    )
    provider.close()
    with pytest.raises(IOCProviderError):
        provider.query(IOCQuery("1.2.3.4", "ipv4"))
    http.close()


def test_absolute_url_in_build_request_bypasses_base_url() -> None:
    captured: dict[str, Any] = {}

    class AbsUrlProvider(_FakeIntelProvider):
        def _build_request(self, request: IOCQuery):  # type: ignore[override]
            return (
                "GET",
                "https://other.example/absolute",
                None,
                None,
                None,
            )

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(200, json={"verdict": "unknown"})

    transport = httpx.MockTransport(handler)
    provider = AbsUrlProvider(
        base_url="https://intel.example",
        http_client=httpx.Client(transport=transport),
    )
    provider.query(IOCQuery("1.2.3.4", "ipv4"))
    assert captured["url"] == "https://other.example/absolute"
