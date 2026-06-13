"""
MISP event push adapter.

Renders the incident's IOCs + findings into a MISP `Event` JSON and
POSTs it to `<base_url>/events/add`. Dry-run returns the would-be
payload without any network call.

Attribute mapping:

    ipv4    -> ip-dst      (Network activity)
    ipv6    -> ip-dst      (Network activity)
    domain  -> domain      (Network activity)
    url     -> url         (Network activity)
    sha256  -> sha256      (Payload delivery)
    sha1    -> sha1        (Payload delivery)
    md5     -> md5         (Payload delivery)
    email   -> email-src   (Network activity)

Tags always include `tlp:<level>` plus `aptwatcher:<incident_id>` and
`campaign:<tag>` when non-empty.
"""

from __future__ import annotations

import json
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


__all__ = ["MispAdapter"]


# type -> (misp attribute type, misp category)
_MISP_MAP: dict[str, tuple[str, str]] = {
    "ipv4": ("ip-dst", "Network activity"),
    "ipv6": ("ip-dst", "Network activity"),
    "domain": ("domain", "Network activity"),
    "url": ("url", "Network activity"),
    "sha256": ("sha256", "Payload delivery"),
    "sha1": ("sha1", "Payload delivery"),
    "md5": ("md5", "Payload delivery"),
    "email": ("email-src", "Network activity"),
}

_VALID_TLP = frozenset({"white", "clear", "green", "amber", "red"})


def _utc_iso_now() -> str:
    return datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")


class MispAdapter:
    """Push a MISP event containing the incident IOCs + findings."""

    name: str = "misp"

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        tlp: str = "amber",
        timeout: float = 30.0,
        verify_tls: bool = True,
        transport: Callable[..., Any] | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("api_key is required")
        if not base_url:
            raise ValueError("base_url is required")
        tlp_normalized = tlp.lower()
        if tlp_normalized not in _VALID_TLP:
            raise ValueError(
                f"invalid tlp {tlp!r}; expected one of {sorted(_VALID_TLP)}"
            )
        self._api_key = api_key
        self._base_url = base_url.rstrip("/") + "/"
        self._tlp = tlp_normalized
        self._timeout = timeout
        self._verify_tls = verify_tls
        self._transport = transport

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
        payload = self._build_payload(
            iocs=iocs,
            findings=findings,
            incident_id=incident_id,
            campaign_tag=campaign_tag,
        )
        endpoint = self._endpoint()
        correlation_id = f"misp-{uuid.uuid4().hex}"

        if dry_run:
            return PublicationResult(
                adapter=self.name,
                target="misp-dry-run",
                submitted_at=_utc_iso_now(),
                correlation_id=correlation_id,
                status="dry_run",
                details={
                    "endpoint": endpoint,
                    "payload": payload,
                    "attribute_count": len(payload["Event"]["Attribute"]),
                },
            )

        response_json = self._post(endpoint, payload)
        event_id = _extract_event_id(response_json)
        return PublicationResult(
            adapter=self.name,
            target=event_id or "misp-submitted",
            submitted_at=_utc_iso_now(),
            correlation_id=correlation_id,
            status="submitted",
            details={
                "endpoint": endpoint,
                "attribute_count": len(payload["Event"]["Attribute"]),
                "response": response_json,
            },
        )

    # ------------------------------------------------------------------

    def _endpoint(self) -> str:
        return f"{self._base_url}events/add"

    def _build_payload(
        self,
        *,
        iocs: Iterable[IOCVerdict],
        findings: Iterable[Finding],
        incident_id: str,
        campaign_tag: str,
    ) -> dict[str, Any]:
        attributes: list[dict[str, Any]] = []
        for ioc in iocs:
            mapped = _MISP_MAP.get(ioc.ioc_type)
            if mapped is None:
                continue
            attr_type, category = mapped
            attributes.append(
                {
                    "type": attr_type,
                    "category": category,
                    "value": ioc.value,
                    "to_ids": ioc.verdict == "malicious",
                    "comment": ioc.notes or f"APTWatcher incident {incident_id}",
                }
            )

        tags: list[dict[str, str]] = [{"name": f"tlp:{self._tlp}"}]
        if incident_id:
            tags.append({"name": f"aptwatcher:{incident_id}"})
        if campaign_tag:
            tags.append({"name": f"campaign:{campaign_tag}"})

        info = campaign_tag or f"APTWatcher incident {incident_id}"

        event = {
            "info": info,
            "distribution": 1,
            "threat_level_id": 2,
            "analysis": 2,
            "date": datetime.now(tz=UTC).strftime("%Y-%m-%d"),
            "Attribute": attributes,
            "Tag": tags,
        }

        # Findings are not native MISP attributes; attach as a comment-only
        # text object so the event carries the narrative context.
        for finding in findings:
            summary = finding.summary or ""
            attributes.append(
                {
                    "type": "comment",
                    "category": "Other",
                    "value": summary[:2000],
                    "to_ids": False,
                    "comment": f"APTWatcher finding {finding.finding_id}",
                }
            )

        return {"Event": event}

    def _post(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {
            "Authorization": self._api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        if self._transport is not None:
            try:
                resp = self._transport(
                    method="POST",
                    url=url,
                    headers=headers,
                    json=payload,
                    timeout=self._timeout,
                    verify=self._verify_tls,
                )
            except PublicationError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise PublicationError(f"misp transport failure: {exc}") from exc
            return _parse_transport_response(resp)

        if httpx is None:
            return _stdlib_post(url, headers, payload, timeout=self._timeout)

        try:
            response = httpx.post(
                url,
                headers=headers,
                json=payload,
                timeout=self._timeout,
                verify=self._verify_tls,
            )
        except Exception as exc:  # noqa: BLE001
            raise PublicationError(f"misp httpx error: {exc}") from exc

        status = getattr(response, "status_code", 0)
        if 200 <= status < 300:
            try:
                data: dict[str, Any] = response.json()
                return data
            except Exception:  # noqa: BLE001
                return {}
        text = getattr(response, "text", "")
        raise PublicationError(f"misp returned HTTP {status}: {text[:500]}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_event_id(response_json: dict[str, Any]) -> str | None:
    event = response_json.get("Event")
    if isinstance(event, dict):
        value = event.get("id")
        if value is not None:
            return str(value)
    top_id = response_json.get("id")
    if top_id is not None:
        return str(top_id)
    return None


def _parse_transport_response(resp: Any) -> dict[str, Any]:
    if isinstance(resp, dict):
        status = int(resp.get("status_code", 200))
        body = resp.get("json", resp.get("body", {}))
        if 200 <= status < 300:
            return body if isinstance(body, dict) else {}
        raise PublicationError(f"misp returned HTTP {status}: {body!r}")

    status = int(getattr(resp, "status_code", 200))
    if 200 <= status < 300:
        json_fn = getattr(resp, "json", None)
        if callable(json_fn):
            try:
                data: dict[str, Any] = json_fn()
                return data
            except Exception:  # noqa: BLE001
                return {}
        return {}
    text = getattr(resp, "text", "")
    raise PublicationError(f"misp returned HTTP {status}: {text[:500]}")


def _stdlib_post(
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    *,
    timeout: float,
) -> dict[str, Any]:
    import urllib.error
    import urllib.request

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            status = resp.getcode()
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise PublicationError(
            f"misp returned HTTP {exc.code}: {exc.reason}"
        ) from exc
    except urllib.error.URLError as exc:
        raise PublicationError(f"misp URL error: {exc.reason}") from exc

    if not (200 <= status < 300):
        raise PublicationError(f"misp returned HTTP {status}: {raw[:500]}")
    if not raw:
        return {}
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


# Protocol runtime check
_PROTOCOL_CHECK: PublicationAdapter = MispAdapter(
    api_key="placeholder",
    base_url="https://misp.example/",
)
del _PROTOCOL_CHECK
