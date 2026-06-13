"""
Tests for the TAXII 2.1 publication adapter.

All HTTP traffic is intercepted via the ``transport`` injection hook so
the tests never need an actual TAXII server. Env vars are set per-test
and cleaned up via monkeypatch so accidental leakage across tests is
impossible.
"""

from __future__ import annotations

from typing import Any

import pytest

from core.publish.protocol import PublicationAdapter, PublicationResult
from core.publish.taxii import TaxiiAdapter, TaxiiPublicationError
from core.types import IOCVerdict

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _ioc(value: str, ioc_type: str) -> IOCVerdict:
    return IOCVerdict(
        value=value,
        ioc_type=ioc_type,  # type: ignore[arg-type]
        verdict="malicious",
        confidence=0.9,
    )


def _sample_iocs() -> list[IOCVerdict]:
    return [
        _ioc("evil.example", "domain"),
        _ioc("203.0.113.10", "ipv4"),
        _ioc("https://bad.example/path", "url"),
    ]


_SERVER_URL = "https://taxii.example.org"
_COLLECTION_ID = "abcd1234-0000-0000-0000-000000000001"
_TOKEN = "s3cr3t-bearer-token-never-logged"


def _adapter(
    *,
    transport: Any = None,
    username: str | None = None,
    password_env: str | None = None,
    api_key_env: str = "APTW_TAXII_API_KEY",
    timeout_seconds: int = 30,
) -> TaxiiAdapter:
    return TaxiiAdapter(
        server_url=_SERVER_URL,
        collection_id=_COLLECTION_ID,
        api_key_env=api_key_env,
        username=username,
        password_env=password_env,
        timeout_seconds=timeout_seconds,
        transport=transport,
    )


# ---------------------------------------------------------------------------
# Structural / construction
# ---------------------------------------------------------------------------


def test_taxii_adapter_is_a_publication_adapter() -> None:
    a = _adapter()
    assert isinstance(a, PublicationAdapter)
    assert a.name == "taxii"


def test_taxii_rejects_empty_server_url() -> None:
    with pytest.raises(ValueError):
        TaxiiAdapter(server_url="", collection_id=_COLLECTION_ID)


def test_taxii_rejects_empty_collection_id() -> None:
    with pytest.raises(ValueError):
        TaxiiAdapter(server_url=_SERVER_URL, collection_id="")


# ---------------------------------------------------------------------------
# Dry-run path
# ---------------------------------------------------------------------------


def test_taxii_dry_run_returns_result_and_never_touches_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Intentionally clear the env so that *any* env read during dry-run
    # would raise later; dry-run must not read env vars at all.
    monkeypatch.delenv("APTW_TAXII_API_KEY", raising=False)

    calls: list[dict[str, Any]] = []

    def sentinel_transport(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        return {"status_code": 202}

    a = _adapter(transport=sentinel_transport)
    result = a.publish(
        findings=[],
        iocs=_sample_iocs(),
        incident_id="INC-1",
        campaign_tag="CAMPAIGN-A",
        dry_run=True,
    )
    assert isinstance(result, PublicationResult)
    assert result.status == "dry_run"
    assert result.adapter == "taxii"
    assert calls == []  # transport must never be invoked in dry-run
    details = result.details
    assert details["action"] == "dry-run"
    assert details["collection_id"] == _COLLECTION_ID
    assert details["server_url"] == _SERVER_URL
    assert details["object_count"] >= 1  # identity SDO + per-IOC indicator
    assert "objects" in details["payload"]
    assert isinstance(details["payload"]["objects"], list)
    assert f"/collections/{_COLLECTION_ID}/objects/" in details["endpoint"]


def test_taxii_dry_run_with_empty_iocs_emits_zero_objects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("APTW_TAXII_API_KEY", raising=False)
    a = _adapter()
    result = a.publish(
        findings=[],
        iocs=[],
        incident_id="INC-EMPTY",
        campaign_tag="C",
        dry_run=True,
    )
    assert result.status == "dry_run"
    assert result.details["object_count"] == 0
    assert result.details["payload"]["objects"] == []


# ---------------------------------------------------------------------------
# Live: auth / env wiring
# ---------------------------------------------------------------------------


def test_taxii_live_missing_bearer_env_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("APTW_TAXII_API_KEY", raising=False)

    def unused_transport(**_kw: Any) -> dict[str, Any]:
        raise AssertionError("transport must not be called before auth check")

    a = _adapter(transport=unused_transport)
    with pytest.raises(TaxiiPublicationError) as exc_info:
        a.publish(
            findings=[],
            iocs=_sample_iocs(),
            incident_id="INC-2",
            campaign_tag="C",
            dry_run=False,
        )
    assert "APTW_TAXII_API_KEY" in str(exc_info.value)
    assert _TOKEN not in str(exc_info.value)


def test_taxii_live_bearer_token_path_reaches_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APTW_TAXII_API_KEY", _TOKEN)

    captured: dict[str, Any] = {}

    def fake_transport(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {
            "status_code": 202,
            "headers": {"Location": "/api/collections/abcd/status/11"},
            "json": {"status": "pending"},
        }

    a = _adapter(transport=fake_transport)
    result = a.publish(
        findings=[],
        iocs=_sample_iocs(),
        incident_id="INC-3",
        campaign_tag="C3",
        dry_run=False,
    )
    assert result.status == "submitted"
    assert result.target == "/api/collections/abcd/status/11"
    assert result.details["http_status"] == 202
    assert result.details["object_count"] >= 1

    assert captured["method"] == "POST"
    assert captured["url"].endswith(f"/collections/{_COLLECTION_ID}/objects/")
    headers = captured["headers"]
    assert headers["Authorization"] == f"Bearer {_TOKEN}"
    assert headers["Accept"].startswith("application/taxii+json")
    assert headers["Content-Type"].startswith("application/taxii+json")
    assert "objects" in captured["json"]


def test_taxii_live_basic_auth_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APTW_TAXII_PASSWORD", "pw-shh")
    # Ensure bearer env is *not* consulted when basic-auth is active.
    monkeypatch.delenv("APTW_TAXII_API_KEY", raising=False)

    captured: dict[str, Any] = {}

    def fake_transport(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"status_code": 202, "headers": {}}

    a = _adapter(
        transport=fake_transport,
        username="taxii-user",
        password_env="APTW_TAXII_PASSWORD",
    )
    result = a.publish(
        findings=[],
        iocs=[_ioc("evil.example", "domain")],
        incident_id="INC-BA",
        campaign_tag="C",
        dry_run=False,
    )
    assert result.status == "submitted"
    auth = captured["headers"]["Authorization"]
    assert auth.startswith("Basic ")
    # Basic <b64> should never be "Bearer ..."
    assert "Bearer" not in auth
    # b64("taxii-user:pw-shh") = dGF4aWktdXNlcjpwdy1zaGg=
    assert auth == "Basic dGF4aWktdXNlcjpwdy1zaGg="


def test_taxii_basic_auth_missing_password_env_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("APTW_TAXII_PASSWORD", raising=False)
    a = _adapter(username="u", password_env="APTW_TAXII_PASSWORD")
    with pytest.raises(TaxiiPublicationError) as exc_info:
        a.publish(
            findings=[],
            iocs=[_ioc("evil.example", "domain")],
            incident_id="INC-BA2",
            campaign_tag="C",
            dry_run=False,
        )
    assert "APTW_TAXII_PASSWORD" in str(exc_info.value)


def test_taxii_basic_auth_requires_password_env_configured() -> None:
    a = _adapter(username="u", password_env=None)
    with pytest.raises(TaxiiPublicationError) as exc_info:
        a.publish(
            findings=[],
            iocs=[_ioc("evil.example", "domain")],
            incident_id="INC-BA3",
            campaign_tag="C",
            dry_run=False,
        )
    assert "password_env" in str(exc_info.value)


# ---------------------------------------------------------------------------
# HTTP status handling
# ---------------------------------------------------------------------------


def test_taxii_401_raises_authentication_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APTW_TAXII_API_KEY", _TOKEN)

    def fake_transport(**_kw: Any) -> dict[str, Any]:
        return {"status_code": 401, "body": {"title": "unauth"}}

    a = _adapter(transport=fake_transport)
    with pytest.raises(TaxiiPublicationError) as exc_info:
        a.publish(
            findings=[],
            iocs=[_ioc("evil.example", "domain")],
            incident_id="INC-401",
            campaign_tag="C",
            dry_run=False,
        )
    msg = str(exc_info.value)
    assert "authentication" in msg.lower()
    assert "401" in msg
    assert _TOKEN not in msg


def test_taxii_403_raises_forbidden_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APTW_TAXII_API_KEY", _TOKEN)

    def fake_transport(**_kw: Any) -> dict[str, Any]:
        return {"status_code": 403, "body": {"title": "denied"}}

    a = _adapter(transport=fake_transport)
    with pytest.raises(TaxiiPublicationError) as exc_info:
        a.publish(
            findings=[],
            iocs=[_ioc("evil.example", "domain")],
            incident_id="INC-403",
            campaign_tag="C",
            dry_run=False,
        )
    msg = str(exc_info.value)
    assert "forbidden" in msg.lower()
    assert "403" in msg
    assert _TOKEN not in msg


def test_taxii_5xx_raises_publication_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APTW_TAXII_API_KEY", _TOKEN)

    def fake_transport(**_kw: Any) -> dict[str, Any]:
        return {"status_code": 503, "body": "service unavailable"}

    a = _adapter(transport=fake_transport)
    with pytest.raises(TaxiiPublicationError) as exc_info:
        a.publish(
            findings=[],
            iocs=[_ioc("evil.example", "domain")],
            incident_id="INC-503",
            campaign_tag="C",
            dry_run=False,
        )
    assert "503" in str(exc_info.value)
    assert _TOKEN not in str(exc_info.value)


# ---------------------------------------------------------------------------
# Payload shape (STIX bundle reuse)
# ---------------------------------------------------------------------------


def test_taxii_payload_objects_are_stix_indicators(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("APTW_TAXII_API_KEY", raising=False)
    a = _adapter()
    result = a.publish(
        findings=[],
        iocs=_sample_iocs(),
        incident_id="INC-STIX",
        campaign_tag="C",
        dry_run=True,
    )
    objects = result.details["payload"]["objects"]
    types = [o["type"] for o in objects]
    assert "identity" in types
    indicator_objs = [o for o in objects if o["type"] == "indicator"]
    assert len(indicator_objs) == len(_sample_iocs())
    for ind in indicator_objs:
        assert ind["spec_version"] == "2.1"
        assert ind["pattern_type"] == "stix"
        assert ind["id"].startswith("indicator--")


def test_taxii_posts_objects_field_to_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APTW_TAXII_API_KEY", _TOKEN)

    seen: dict[str, Any] = {}

    def fake_transport(**kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs)
        return {"status_code": 202, "headers": {"Location": "/status/1"}}

    a = _adapter(transport=fake_transport)
    a.publish(
        findings=[],
        iocs=_sample_iocs(),
        incident_id="INC-POST",
        campaign_tag="C",
        dry_run=False,
    )
    body = seen["json"]
    assert "objects" in body
    assert isinstance(body["objects"], list)
    assert any(o["type"] == "indicator" for o in body["objects"])


# ---------------------------------------------------------------------------
# Timeout + secret hygiene
# ---------------------------------------------------------------------------


def test_taxii_timeout_is_forwarded_to_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APTW_TAXII_API_KEY", _TOKEN)

    seen: dict[str, Any] = {}

    def fake_transport(**kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs)
        return {"status_code": 202, "headers": {}}

    a = _adapter(transport=fake_transport, timeout_seconds=7)
    a.publish(
        findings=[],
        iocs=[_ioc("evil.example", "domain")],
        incident_id="INC-T",
        campaign_tag="C",
        dry_run=False,
    )
    assert seen["timeout"] == 7.0


def test_taxii_bearer_token_never_leaks_into_result_or_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("APTW_TAXII_API_KEY", _TOKEN)

    # Success path: token must not appear in the returned dict.
    def ok_transport(**_kw: Any) -> dict[str, Any]:
        return {"status_code": 202, "headers": {"Location": "/status/X"}}

    a = _adapter(transport=ok_transport)
    result = a.publish(
        findings=[],
        iocs=[_ioc("evil.example", "domain")],
        incident_id="INC-SECRET",
        campaign_tag="C",
        dry_run=False,
    )
    dumped = result.model_dump_json()
    assert _TOKEN not in dumped

    # Error path: a 401 body that echoes the token (a hostile server
    # trick) must still not bleed the token into the exception since we
    # only surface an excerpt of the response body, not headers.
    def bad_transport(**_kw: Any) -> dict[str, Any]:
        return {"status_code": 401, "body": "unauth"}

    a2 = _adapter(transport=bad_transport)
    with pytest.raises(TaxiiPublicationError) as exc_info:
        a2.publish(
            findings=[],
            iocs=[_ioc("evil.example", "domain")],
            incident_id="INC-SECRET-401",
            campaign_tag="C",
            dry_run=False,
        )
    assert _TOKEN not in str(exc_info.value)
