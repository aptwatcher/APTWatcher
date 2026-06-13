"""
TAXII 2.1 push adapter.

Distinct from ``core.analysis.export_stix`` — that module is a file-only
exporter that writes ``bundle.stix.json`` to disk. This adapter re-uses
the same bundle builder but POSTs the resulting objects to a TAXII 2.1
collection endpoint, so threat-sharing communities that consume via
TAXII (AIS, ISACs, ...) receive the feed over the wire.

Consent gating mirrors the rest of ``core.publish``: dry-run is the
default; the operator must opt out explicitly via ``--no-dry-run`` on
the CLI. The bearer token (or basic-auth password) is read from an
env var named by the config. No credential is ever logged, included
in an exception message, or returned in the result dict.

POST shape::

    POST <server_url>/collections/<collection_id>/objects/
    Accept:        application/taxii+json;version=2.1
    Content-Type:  application/taxii+json;version=2.1
    Authorization: Bearer <token>    # or HTTP basic auth
    Body:          {"objects": [ ...STIX SDOs... ]}

Accepted response: ``202 Accepted`` with a ``Location`` header pointing
at the per-submission status resource. The adapter returns that URL in
the ``details`` dict so the caller can poll later.

References:

- docs/design/analysis-output-pipeline.md
- OASIS TAXII 2.1 specification,
  https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html
"""

from __future__ import annotations

import base64
import json
import os
import uuid
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

from core.publish.protocol import (
    PublicationAdapter,
    PublicationError,
    PublicationResult,
)
from core.types import Finding, IOCVerdict

try:
    import httpx
except Exception:  # pragma: no cover - optional dep
    httpx = None  # type: ignore[assignment]


__all__ = ["TaxiiAdapter", "TaxiiPublicationError"]


_TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"


class TaxiiPublicationError(PublicationError):
    """Raised for TAXII-layer failures (non-202 status, auth, bad config)."""


def _utc_iso_now() -> str:
    return datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")


class TaxiiAdapter:
    """
    TAXII 2.1 POST adapter.

    Constructor args:

    - ``server_url``: Base TAXII server URL, e.g.
      ``https://taxii.example.org``. Trailing slash is tolerated.
    - ``collection_id``: UUID (or opaque id) of the target collection.
    - ``api_key_env``: Env var holding the bearer token. Default
      ``APTW_TAXII_API_KEY``. Ignored when ``username`` is set.
    - ``username`` / ``password_env``: Optional HTTP basic-auth pair.
      Mutually exclusive with the bearer flow.
    - ``timeout_seconds``: HTTP timeout. Defaults to ``30``.
    - ``transport``: Optional test hook (same shape as the Netcraft /
      MISP adapters): called as
      ``transport(method=..., url=..., headers=..., json=..., timeout=...)``
      and expected to return a dict with ``status_code`` + optional
      ``headers`` / ``json`` / ``body`` keys.

    The adapter is intentionally NOT a ``@dataclass(frozen=True)`` —
    existing ``core.publish`` adapters are plain classes and the
    ``transport`` injection hook is awkward to express on a frozen
    dataclass. The constructor is still argument-only and read-only in
    practice.
    """

    name: str = "taxii"

    def __init__(
        self,
        *,
        server_url: str,
        collection_id: str,
        api_key_env: str = "APTW_TAXII_API_KEY",
        username: str | None = None,
        password_env: str | None = None,
        timeout_seconds: int = 30,
        transport: Callable[..., Any] | None = None,
    ) -> None:
        if not server_url:
            raise ValueError("server_url is required")
        if not collection_id:
            raise ValueError("collection_id is required")
        self._server_url = server_url.rstrip("/")
        self._collection_id = collection_id
        self._api_key_env = api_key_env
        self._username = username or None
        self._password_env = password_env or None
        self._timeout = float(timeout_seconds)
        self._transport = transport

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def publish(
        self,
        *,
        findings: list[Finding],
        iocs: list[IOCVerdict],
        incident_id: str,
        campaign_tag: str,
        dry_run: bool = True,
    ) -> PublicationResult:
        endpoint = self._endpoint()
        correlation_id = f"taxii-{uuid.uuid4().hex}"

        objects = self._build_objects(
            iocs=iocs,
            incident_id=incident_id,
            campaign_tag=campaign_tag,
        )
        payload: dict[str, Any] = {"objects": objects}

        if dry_run:
            # Dry-run MUST NOT read env vars or touch the network. We
            # return the rendered payload + endpoint so the operator can
            # see exactly what would have been POSTed.
            return PublicationResult(
                adapter=self.name,
                target="taxii-dry-run",
                submitted_at=_utc_iso_now(),
                correlation_id=correlation_id,
                status="dry_run",
                details={
                    "action": "dry-run",
                    "endpoint": endpoint,
                    "collection_id": self._collection_id,
                    "server_url": self._server_url,
                    "object_count": len(objects),
                    "payload": payload,
                    "findings_count": len(list(findings)),
                },
            )

        headers = self._auth_headers()
        headers.update(
            {
                "Accept": _TAXII_CONTENT_TYPE,
                "Content-Type": _TAXII_CONTENT_TYPE,
            }
        )

        status, response_headers, body = self._post(endpoint, headers, payload)
        self._raise_for_status(status, body)

        # 2xx success (normally 202 Accepted).
        location = None
        for key in ("Location", "location", "Content-Location", "content-location"):
            if key in response_headers and response_headers[key]:
                location = response_headers[key]
                break

        return PublicationResult(
            adapter=self.name,
            target=location or f"taxii-collection-{self._collection_id}",
            submitted_at=_utc_iso_now(),
            correlation_id=correlation_id,
            status="submitted",
            details={
                "endpoint": endpoint,
                "collection_id": self._collection_id,
                "server_url": self._server_url,
                "object_count": len(objects),
                "http_status": status,
                "location": location,
            },
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _endpoint(self) -> str:
        return (
            f"{self._server_url}/api/collections/"
            f"{self._collection_id}/objects/"
        )

    def _build_objects(
        self,
        *,
        iocs: Iterable[IOCVerdict],
        incident_id: str,
        campaign_tag: str,
    ) -> list[dict[str, Any]]:
        """Render the STIX 2.1 objects that go in the POST body.

        We call into ``core.analysis.export_stix`` for indicator
        rendering so the file-exporter and the TAXII push agree on
        UUIDs, timestamps, and pattern grammar.
        """
        ioc_list = list(iocs)
        if not ioc_list:
            return []

        # Local import so a missing optional module does not break
        # adapter instantiation (mirrors the pattern in publish.py).
        from core.analysis.export_stix import (  # noqa: WPS433 (local import)
            _build_identity,
            _build_indicator,
            _stix_timestamp,
        )
        from core.types import utcnow  # noqa: WPS433

        _ = incident_id, campaign_tag  # reserved for future marking SDOs

        created_by = "identity--aptwatcher"
        now_iso = _stix_timestamp(utcnow())
        objects: list[dict[str, Any]] = [
            _build_identity(created_by, now_iso=now_iso),
        ]
        for ioc in ioc_list:
            try:
                objects.append(
                    _build_indicator(ioc, created_by=created_by, now_iso=now_iso)
                )
            except Exception:  # noqa: BLE001 — skip malformed IOCs silently
                continue
        return objects

    def _auth_headers(self) -> dict[str, str]:
        """Build Authorization header, preferring basic-auth when configured.

        Raises ``TaxiiPublicationError`` (never logging the secret) if
        the selected credential source is unset or empty.
        """
        if self._username:
            if not self._password_env:
                raise TaxiiPublicationError(
                    "taxii basic-auth requires password_env to be set",
                )
            password = os.environ.get(self._password_env, "")
            if not password:
                raise TaxiiPublicationError(
                    f"taxii basic-auth password env var "
                    f"{self._password_env!r} is missing or empty",
                )
            raw = f"{self._username}:{password}".encode()
            encoded = base64.b64encode(raw).decode("ascii")
            return {"Authorization": f"Basic {encoded}"}

        token = os.environ.get(self._api_key_env, "")
        if not token:
            raise TaxiiPublicationError(
                f"taxii bearer token env var "
                f"{self._api_key_env!r} is missing or empty",
            )
        return {"Authorization": f"Bearer {token}"}

    def _post(
        self,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
    ) -> tuple[int, dict[str, str], Any]:
        """POST ``payload``; return ``(status, response_headers, body)``."""
        if self._transport is not None:
            try:
                resp = self._transport(
                    method="POST",
                    url=url,
                    headers=headers,
                    json=payload,
                    timeout=self._timeout,
                )
            except TaxiiPublicationError:
                raise
            except Exception as exc:  # noqa: BLE001
                # Never surface the raw exception args — an httpx
                # error object can contain the full request including
                # the Authorization header.
                raise TaxiiPublicationError(
                    f"taxii transport failure: {type(exc).__name__}",
                ) from None
            return _coerce_transport_response(resp)

        if httpx is None:
            return _stdlib_post(url, headers, payload, timeout=self._timeout)

        try:
            response = httpx.post(
                url, headers=headers, json=payload, timeout=self._timeout,
            )
        except Exception as exc:  # noqa: BLE001
            raise TaxiiPublicationError(
                f"taxii httpx error: {type(exc).__name__}",
            ) from None

        status = int(getattr(response, "status_code", 0))
        resp_headers = dict(getattr(response, "headers", {}) or {})
        body: Any
        try:
            body = response.json()
        except Exception:  # noqa: BLE001
            body = getattr(response, "text", "")
        return status, resp_headers, body

    def _raise_for_status(self, status: int, body: Any) -> None:
        """Translate non-2xx HTTP codes into typed TAXII errors.

        The raised message never contains the Authorization header or
        bearer token — we only surface status + a short body excerpt.
        """
        if 200 <= status < 300:
            return
        excerpt = _short_excerpt(body)
        if status == 401:
            raise TaxiiPublicationError(
                f"taxii authentication failed (HTTP 401): {excerpt}",
            )
        if status == 403:
            raise TaxiiPublicationError(
                f"taxii forbidden (HTTP 403): {excerpt}",
            )
        if 400 <= status < 500:
            raise TaxiiPublicationError(
                f"taxii client error (HTTP {status}): {excerpt}",
            )
        raise TaxiiPublicationError(
            f"taxii server error (HTTP {status}): {excerpt}",
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _coerce_transport_response(resp: Any) -> tuple[int, dict[str, str], Any]:
    """Normalise a transport double into ``(status, headers, body)``."""
    if isinstance(resp, dict):
        status = int(resp.get("status_code", 200))
        resp_headers = dict(resp.get("headers", {}) or {})
        body: Any = resp.get("json", resp.get("body", {}))
        return status, resp_headers, body

    status = int(getattr(resp, "status_code", 200))
    resp_headers = dict(getattr(resp, "headers", {}) or {})
    json_fn = getattr(resp, "json", None)
    if callable(json_fn):
        try:
            body = json_fn()
        except Exception:  # noqa: BLE001
            body = getattr(resp, "text", "")
    else:
        body = getattr(resp, "text", "")
    return status, resp_headers, body


def _short_excerpt(body: Any) -> str:
    """Render a 200-char excerpt of a response body. Never the token."""
    if body is None:
        return ""
    if isinstance(body, (dict, list)):
        try:
            text = json.dumps(body)
        except Exception:  # noqa: BLE001
            text = str(body)
    else:
        text = str(body)
    if len(text) > 200:
        return text[:200] + "..."
    return text


def _stdlib_post(
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    *,
    timeout: float,
) -> tuple[int, dict[str, str], Any]:
    import urllib.error
    import urllib.request

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            status = resp.getcode()
            raw = resp.read().decode("utf-8", errors="replace")
            resp_headers = dict(resp.getheaders())
    except urllib.error.HTTPError as exc:
        # HTTPError carries status + reason. Surface them, but not the
        # outgoing headers (which contain the Authorization token).
        raise TaxiiPublicationError(
            f"taxii HTTP {exc.code}: {exc.reason}",
        ) from None
    except urllib.error.URLError as exc:
        raise TaxiiPublicationError(
            f"taxii URL error: {exc.reason}",
        ) from None

    try:
        decoded: Any = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        decoded = raw
    return status, resp_headers, decoded


# Protocol runtime check (structural typing sanity)
_PROTOCOL_CHECK: PublicationAdapter = TaxiiAdapter(
    server_url="https://taxii.example",
    collection_id="00000000-0000-0000-0000-000000000000",
)
del _PROTOCOL_CHECK
