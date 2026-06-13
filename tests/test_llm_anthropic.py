"""
Tests for core.llm_anthropic.AnthropicModelClient.

httpx exposes MockTransport, which lets us inject a synchronous handler
in place of real network I/O. No anthropic SDK or external mocking
library is required.
"""

from __future__ import annotations

import json
import random
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from core.llm import ModelClient, ModelMessage, ModelRequest
from core.llm_anthropic import (
    AnthropicAdapterError,
    AnthropicAPIError,
    AnthropicAuthError,
    AnthropicModelClient,
    AnthropicRateLimitError,
    AnthropicTransportError,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ok_body(
    *,
    text: str = "hi",
    stop_reason: str = "end_turn",
    model: str = "claude-test",
    usage: dict[str, int] | None = None,
) -> dict[str, Any]:
    usage = usage or {"input_tokens": 12, "output_tokens": 7}
    return {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{"type": "text", "text": text}],
        "stop_reason": stop_reason,
        "usage": usage,
    }


def _make_client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    api_key: str = "sk-test",
    model: str = "claude-test",
    max_retries: int = 3,
    backoff_base_s: float = 0.0,  # zero jitter basis -> instant retries
    rng: random.Random | None = None,
) -> tuple[AnthropicModelClient, list[float]]:
    sleeps: list[float] = []

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    transport = httpx.MockTransport(handler)
    http = httpx.Client(transport=transport)
    client = AnthropicModelClient(
        api_key=api_key,
        model=model,
        max_retries=max_retries,
        backoff_base_s=backoff_base_s,
        http_client=http,
        sleep=fake_sleep,
        rng=rng or random.Random(0),
    )
    return client, sleeps


def _plain_request(user: str = "hello") -> ModelRequest:
    return ModelRequest(
        system="sys prompt",
        messages=[ModelMessage(role="user", content=user)],
        max_tokens=256,
        temperature=0.3,
    )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_missing_api_key_raises_auth_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(AnthropicAuthError):
        AnthropicModelClient()


def test_api_key_falls_back_to_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "env-key")
    # Construction alone should succeed.
    c = AnthropicModelClient()
    assert c is not None
    c.close()


def test_is_protocol_compatible(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    c = AnthropicModelClient()
    try:
        assert isinstance(c, ModelClient)
    finally:
        c.close()


# ---------------------------------------------------------------------------
# Happy path + payload shape
# ---------------------------------------------------------------------------


def test_complete_happy_path_parses_content_and_usage() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["json"] = json.loads(request.content.decode())
        return httpx.Response(
            200,
            json=_ok_body(
                text="planner output",
                usage={"input_tokens": 42, "output_tokens": 18},
            ),
        )

    client, sleeps = _make_client(handler)
    try:
        resp = client.complete(_plain_request("where is the timeline"))
    finally:
        client.close()

    assert resp.content == "planner output"
    assert resp.stop_reason == "end_turn"
    assert resp.usage == {"input_tokens": 42, "output_tokens": 18}
    assert resp.model == "claude-test"
    assert resp.raw is not None
    assert sleeps == []

    # URL + headers
    assert captured["url"].endswith("/v1/messages")
    assert captured["headers"]["x-api-key"] == "sk-test"
    assert captured["headers"]["anthropic-version"] == "2023-06-01"

    # Payload: system lifted to top-level, user message preserved.
    p = captured["json"]
    assert p["model"] == "claude-test"
    assert p["system"] == "sys prompt"
    assert p["max_tokens"] == 256
    assert p["temperature"] == 0.3
    assert p["messages"] == [{"role": "user", "content": "where is the timeline"}]
    assert "stop_sequences" not in p  # not sent when empty


def test_complete_omits_system_when_not_set() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["json"] = json.loads(request.content.decode())
        return httpx.Response(200, json=_ok_body())

    client, _ = _make_client(handler)
    try:
        client.complete(
            ModelRequest(messages=[ModelMessage(role="user", content="x")]),
        )
    finally:
        client.close()
    assert "system" not in captured["json"]


def test_complete_passes_stop_sequences_when_set() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["json"] = json.loads(request.content.decode())
        return httpx.Response(200, json=_ok_body())

    client, _ = _make_client(handler)
    try:
        client.complete(
            ModelRequest(
                messages=[ModelMessage(role="user", content="x")],
                stop_sequences=["</end>"],
            ),
        )
    finally:
        client.close()
    assert captured["json"]["stop_sequences"] == ["</end>"]


def test_complete_filters_system_role_messages_from_array() -> None:
    # ModelRequest allows role=system on messages; the adapter must
    # keep only user/assistant when building the Anthropic payload
    # (system is a top-level field).
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["json"] = json.loads(request.content.decode())
        return httpx.Response(200, json=_ok_body())

    client, _ = _make_client(handler)
    try:
        client.complete(
            ModelRequest(
                system="top-level",
                messages=[
                    ModelMessage(role="system", content="ignored"),
                    ModelMessage(role="user", content="hi"),
                    ModelMessage(role="assistant", content="hi back"),
                    ModelMessage(role="user", content="again"),
                ],
            ),
        )
    finally:
        client.close()

    roles = [m["role"] for m in captured["json"]["messages"]]
    assert roles == ["user", "assistant", "user"]
    assert captured["json"]["system"] == "top-level"


# ---------------------------------------------------------------------------
# Stop-reason mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("end_turn", "end_turn"),
        ("max_tokens", "max_tokens"),
        ("stop_sequence", "stop_sequence"),
        ("tool_use", "error"),
        (None, "error"),
    ],
)
def test_stop_reason_mapping(raw: str | None, expected: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = _ok_body(stop_reason=raw) if raw is not None else _ok_body()
        if raw is None:
            body["stop_reason"] = None
        return httpx.Response(200, json=body)

    client, _ = _make_client(handler)
    try:
        resp = client.complete(_plain_request())
    finally:
        client.close()
    assert resp.stop_reason == expected


def test_empty_content_block_list_yields_empty_string() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = _ok_body()
        body["content"] = []
        return httpx.Response(200, json=body)

    client, _ = _make_client(handler)
    try:
        resp = client.complete(_plain_request())
    finally:
        client.close()
    assert resp.content == ""


# ---------------------------------------------------------------------------
# Error paths: auth, rate-limit, server, transport
# ---------------------------------------------------------------------------


def test_auth_error_not_retried() -> None:
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        return httpx.Response(401, json={"error": {"message": "bad key"}})

    client, sleeps = _make_client(handler, max_retries=3)
    try:
        with pytest.raises(AnthropicAuthError):
            client.complete(_plain_request())
    finally:
        client.close()
    assert attempts["n"] == 1
    assert sleeps == []


def test_forbidden_error_not_retried() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    client, _ = _make_client(handler)
    try:
        with pytest.raises(AnthropicAuthError):
            client.complete(_plain_request())
    finally:
        client.close()


def test_rate_limit_retries_then_succeeds() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) < 3:
            return httpx.Response(429, headers={"retry-after": "2"})
        return httpx.Response(200, json=_ok_body(text="after retry"))

    client, sleeps = _make_client(handler, max_retries=3)
    try:
        resp = client.complete(_plain_request())
    finally:
        client.close()
    assert resp.content == "after retry"
    assert len(calls) == 3
    # First two 429s triggered two sleeps honoring retry-after=2.
    assert sleeps == [2.0, 2.0]


def test_rate_limit_without_retry_after_falls_back_to_backoff() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) < 2:
            return httpx.Response(429)
        return httpx.Response(200, json=_ok_body())

    client, sleeps = _make_client(handler, max_retries=3, backoff_base_s=0.25)
    try:
        client.complete(_plain_request())
    finally:
        client.close()
    assert len(sleeps) == 1
    # First 429 -> backoff(attempt=0) = 0.25 + jitter in [0, 0.25].
    assert 0.25 <= sleeps[0] <= 0.5


def test_rate_limit_exhausts_retries_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429)

    client, sleeps = _make_client(handler, max_retries=3)
    try:
        with pytest.raises(AnthropicRateLimitError):
            client.complete(_plain_request())
    finally:
        client.close()
    # 3 attempts, 2 sleeps between them.
    assert len(sleeps) == 2


def test_5xx_retries_then_succeeds() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(503)
        return httpx.Response(200, json=_ok_body())

    client, _ = _make_client(handler, max_retries=3)
    try:
        resp = client.complete(_plain_request())
    finally:
        client.close()
    assert resp.content == "hi"
    assert len(calls) == 2


def test_5xx_exhausts_retries_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    client, _ = _make_client(handler, max_retries=2)
    try:
        with pytest.raises(AnthropicAPIError) as excinfo:
            client.complete(_plain_request())
    finally:
        client.close()
    assert "500" in str(excinfo.value)


def test_4xx_non_auth_non_429_is_not_retried() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(400, json={"error": {"message": "bad req"}})

    client, _ = _make_client(handler, max_retries=3)
    try:
        with pytest.raises(AnthropicAPIError):
            client.complete(_plain_request())
    finally:
        client.close()
    assert calls == [1]


def test_connection_error_retried_then_raises_transport_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    client, sleeps = _make_client(handler, max_retries=3)
    try:
        with pytest.raises(AnthropicTransportError):
            client.complete(_plain_request())
    finally:
        client.close()
    assert len(sleeps) == 2  # 3 attempts -> 2 sleeps


def test_connection_error_then_success() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            raise httpx.ConnectError("transient")
        return httpx.Response(200, json=_ok_body(text="recovered"))

    client, _ = _make_client(handler, max_retries=3)
    try:
        resp = client.complete(_plain_request())
    finally:
        client.close()
    assert resp.content == "recovered"


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------


def test_adapter_error_hierarchy() -> None:
    # Every concrete error inherits from AnthropicAdapterError (which
    # itself inherits from RuntimeError).
    assert issubclass(AnthropicAuthError, AnthropicAdapterError)
    assert issubclass(AnthropicRateLimitError, AnthropicAdapterError)
    assert issubclass(AnthropicAPIError, AnthropicAdapterError)
    assert issubclass(AnthropicTransportError, AnthropicAdapterError)
    assert issubclass(AnthropicAdapterError, RuntimeError)


def test_close_is_idempotent_and_context_manager_works(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    with AnthropicModelClient() as c:
        assert c is not None
    # After exit, calling close again should not raise.
    c.close()
