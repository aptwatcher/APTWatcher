"""Unit tests for the feed search verbs (ThreatFox / TweetFeed)."""

from __future__ import annotations

import httpx

from core.intel.feeds import search_threatfox, search_tweetfeed


def _c(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_threatfox_match() -> None:
    body = {"query_status": "ok", "data": [{"ioc": "1.2.3.4", "malware": "x"}]}
    out = search_threatfox("1.2.3.4", http_client=_c(lambda r: httpx.Response(200, json=body)))
    assert out["matched"] is True and out["ioc_count"] == 1


def test_threatfox_no_match() -> None:
    body = {"query_status": "no_result", "data": []}
    out = search_threatfox("9.9.9.9", http_client=_c(lambda r: httpx.Response(200, json=body)))
    assert out["matched"] is False and out["ioc_count"] == 0


def test_threatfox_error_is_returned_not_raised() -> None:
    out = search_threatfox("x", http_client=_c(lambda r: httpx.Response(503)))
    assert "error" in out and out["provider"] == "threatfox"


def test_tweetfeed_filter_by_value() -> None:
    rows = [{"value": "1.2.3.4", "tags": ["phishing"]}, {"value": "5.6.7.8", "tags": ["c2"]}]
    out = search_tweetfeed(value="1.2.3.4", http_client=_c(lambda r: httpx.Response(200, json=rows)))
    assert out["count"] == 1 and out["entries"][0]["value"] == "1.2.3.4"


def test_tweetfeed_filter_by_tag() -> None:
    rows = [{"value": "1.2.3.4", "tags": ["phishing"]}, {"value": "5.6.7.8", "tags": ["c2"]}]
    out = search_tweetfeed(tag="c2", http_client=_c(lambda r: httpx.Response(200, json=rows)))
    assert out["count"] == 1 and out["entries"][0]["value"] == "5.6.7.8"


def test_tweetfeed_unfiltered_returns_all() -> None:
    rows = [{"value": "a", "tags": []}, {"value": "b", "tags": []}]
    out = search_tweetfeed(http_client=_c(lambda r: httpx.Response(200, json=rows)))
    assert out["count"] == 2
