"""
HTTPIOCProviderBase — reusable httpx-backed base for real providers.

Real providers (APT Watch, MS Threat Analytics, VirusTotal, AbuseIPDB)
subclass this class and implement:

- `_build_request(query)` → (method, url, headers, params, json_body)
- `_parse_response(response)` → IOCProviderResult

The base handles:

- httpx.Client construction (or uses an injected client for tests).
- Timeout → IOCTimeoutError.
- Transport failures → IOCTransportError.
- Connection close idempotency.

No retries at this layer — the aggregator already treats failures as
abstention, and repeated retries multiply cost against paid intel APIs.
"""

from __future__ import annotations

import contextlib
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

import httpx

from core.intel.base import (
    IOCProviderError,
    IOCQuery,
    IOCTimeoutError,
    IOCTransportError,
    IOCUnsupportedError,
)
from core.types import IOCProviderResult, IOCType


class HTTPIOCProviderBase(ABC):
    """Implements the `IOCProvider` Protocol structurally."""

    #: Subclasses MUST override this with a stable provider identifier.
    name: str = "http-ioc-provider-base"

    #: Subclasses MUST override this with the IOC types they actually support.
    supported_types: frozenset[IOCType] = frozenset()

    def __init__(
        self,
        *,
        base_url: str,
        timeout_s: float = 10.0,
        http_client: httpx.Client | None = None,
        default_headers: Mapping[str, str] | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout_s = timeout_s
        self._default_headers = dict(default_headers or {})
        self._owned_client = http_client is None
        self._http = http_client or httpx.Client(timeout=timeout_s)
        self._closed = False

    # --- Protocol surface -------------------------------------------------

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in self.supported_types

    def query(self, request: IOCQuery) -> IOCProviderResult:
        if self._closed:
            raise IOCProviderError(f"{self.name} is closed")
        if not self.supports(request.ioc_type):
            raise IOCUnsupportedError(
                f"{self.name} does not support ioc_type={request.ioc_type!r}"
            )

        method, path, headers, params, json_body = self._build_request(request)
        url = self._resolve_url(path)
        merged_headers = {**self._default_headers, **(headers or {})}

        try:
            response = self._http.request(
                method=method,
                url=url,
                headers=merged_headers,
                params=params,
                json=json_body,
                timeout=self._timeout_s,
            )
        except httpx.TimeoutException as exc:
            raise IOCTimeoutError(
                f"{self.name} timed out on {request.ioc_type} {request.value!r}"
            ) from exc
        except httpx.TransportError as exc:
            raise IOCTransportError(
                f"{self.name} transport error: {exc}"
            ) from exc

        return self._parse_response(response)

    def close(self) -> None:
        if self._closed:
            return
        if self._owned_client:
            # Shutdown must not raise.
            with contextlib.suppress(Exception):
                self._http.close()
        self._closed = True

    # --- URL helper -------------------------------------------------------

    def _resolve_url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return self._base_url + path

    # --- Subclass contract ------------------------------------------------

    @abstractmethod
    def _build_request(
        self,
        request: IOCQuery,
    ) -> tuple[
        str,                         # HTTP method
        str,                         # path (or absolute URL)
        Mapping[str, str] | None,    # extra headers
        Mapping[str, Any] | None,    # query params
        Any,                         # JSON body or None
    ]:
        """Return the HTTP call shape for a given IOCQuery."""

    @abstractmethod
    def _parse_response(self, response: httpx.Response) -> IOCProviderResult:
        """Turn one HTTP response into a normalized IOCProviderResult."""
