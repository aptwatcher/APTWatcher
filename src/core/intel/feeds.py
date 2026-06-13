"""
Feed search verbs — ThreatFox and TweetFeed.

These are *search* tools, not per-IOC verdict providers: they return lists of
matching indicators, so they sit outside the `IOCProvider`/aggregator model
and are surfaced directly as MCP tools. Clean-room original clients.
"""

from __future__ import annotations

from typing import Any

import httpx

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
TWEETFEED_TODAY_URL = "https://api.tweetfeed.live/v1/today"


def search_threatfox(
    query: str,
    *,
    api_key: str | None = None,
    http_client: httpx.Client | None = None,
    timeout_s: float = 15.0,
) -> dict[str, Any]:
    """Search abuse.ch ThreatFox for an IOC (IP, domain, URL, or hash).

    Returns a dict with `provider`, `query`, `matched` (bool), `ioc_count`,
    and `iocs` (raw match list). Network/parse errors are returned as
    `{"provider": "threatfox", "query": ..., "error": ...}` rather than raised.
    """
    owned = http_client is None
    client = http_client or httpx.Client(timeout=timeout_s)
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Auth-Key"] = api_key
    body = {"query": "search_ioc", "search_term": query}
    try:
        r = client.post(THREATFOX_API_URL, json=body, headers=headers, timeout=timeout_s)
        r.raise_for_status()
        payload = r.json()
    except (httpx.HTTPError, ValueError) as exc:
        return {"provider": "threatfox", "query": query, "error": str(exc)}
    finally:
        if owned:
            client.close()
    data = payload.get("data") if isinstance(payload, dict) else None
    iocs = data if isinstance(data, list) else []
    return {"provider": "threatfox", "query": query, "matched": bool(iocs),
            "ioc_count": len(iocs), "iocs": iocs}


def search_tweetfeed(
    *,
    value: str | None = None,
    tag: str | None = None,
    http_client: httpx.Client | None = None,
    timeout_s: float = 15.0,
) -> dict[str, Any]:
    """Fetch today's TweetFeed indicators, optionally filtered by value/tag.

    Returns `{"provider": "tweetfeed", "count", "entries"}`. With neither
    filter, returns all of today's entries. Errors are returned, not raised.
    """
    owned = http_client is None
    client = http_client or httpx.Client(timeout=timeout_s)
    try:
        r = client.get(TWEETFEED_TODAY_URL, headers={"Accept": "application/json"}, timeout=timeout_s)
        r.raise_for_status()
        payload = r.json()
    except (httpx.HTTPError, ValueError) as exc:
        return {"provider": "tweetfeed", "error": str(exc)}
    finally:
        if owned:
            client.close()
    entries = payload if isinstance(payload, list) else []
    if value is not None:
        entries = [e for e in entries if e.get("value") == value]
    if tag is not None:
        entries = [e for e in entries if tag in (e.get("tags") or [])]
    return {"provider": "tweetfeed", "count": len(entries), "entries": entries}
