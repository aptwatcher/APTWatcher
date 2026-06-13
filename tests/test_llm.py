"""
Tests for core.llm -- model adapter layer.

Covers:
- ModelRequest construction and `with_user` helper immutability
- FakeModelClient replay semantics (ordering, exhaustion, string lift)
- ModelClient protocol satisfied by FakeModelClient (runtime_checkable)
- load_prompt happy path + traversal / absolute / missing rejections
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.llm import (
    FakeClientExhausted,
    FakeModelClient,
    ModelClient,
    ModelMessage,
    ModelRequest,
    ModelResponse,
    PromptNotFoundError,
    load_prompt,
)

# ---------------------------------------------------------------------------
# ModelRequest shape
# ---------------------------------------------------------------------------


def test_model_request_defaults() -> None:
    req = ModelRequest(messages=[ModelMessage(role="user", content="hi")])
    assert req.system is None
    assert req.max_tokens == 1024
    assert 0.0 <= req.temperature <= 2.0
    assert req.stop_sequences == []


def test_model_request_rejects_extra_fields() -> None:
    # ConfigDict(extra="forbid") is inherited from the base _Model.
    with pytest.raises(Exception):  # pydantic ValidationError
        ModelRequest(
            messages=[ModelMessage(role="user", content="hi")],
            unexpected="no",  # type: ignore[call-arg]
        )


def test_model_request_with_user_is_non_mutating() -> None:
    req = ModelRequest(
        system="be careful",
        messages=[ModelMessage(role="user", content="first")],
    )
    req2 = req.with_user("second")
    # Original is unchanged.
    assert len(req.messages) == 1
    # Copy has the appended message.
    assert len(req2.messages) == 2
    assert req2.messages[-1].role == "user"
    assert req2.messages[-1].content == "second"
    # System prompt carries over.
    assert req2.system == "be careful"


# ---------------------------------------------------------------------------
# FakeModelClient replay semantics
# ---------------------------------------------------------------------------


def test_fake_model_client_replays_in_order() -> None:
    client = FakeModelClient(responses=["first", "second"])
    r1 = client.complete(ModelRequest(messages=[ModelMessage(role="user", content="a")]))
    r2 = client.complete(ModelRequest(messages=[ModelMessage(role="user", content="b")]))
    assert r1.content == "first"
    assert r1.stop_reason == "fake"
    assert r2.content == "second"
    assert client.remaining == 0


def test_fake_model_client_raises_when_exhausted() -> None:
    client = FakeModelClient(responses=["only one"])
    client.complete(ModelRequest(messages=[ModelMessage(role="user", content="a")]))
    with pytest.raises(FakeClientExhausted):
        client.complete(ModelRequest(messages=[ModelMessage(role="user", content="b")]))


def test_fake_model_client_records_calls() -> None:
    client = FakeModelClient(responses=["ok", "ok"])
    req_a = ModelRequest(messages=[ModelMessage(role="user", content="alpha")])
    req_b = ModelRequest(messages=[ModelMessage(role="user", content="beta")])
    client.complete(req_a)
    client.complete(req_b)
    assert len(client.calls) == 2
    assert client.calls[0].messages[-1].content == "alpha"
    assert client.calls[1].messages[-1].content == "beta"


def test_fake_model_client_accepts_model_response_objects() -> None:
    canned = ModelResponse(
        content="structured",
        stop_reason="max_tokens",
        usage={"input_tokens": 12, "output_tokens": 4},
    )
    client = FakeModelClient(responses=[canned])
    resp = client.complete(
        ModelRequest(messages=[ModelMessage(role="user", content="go")]),
    )
    assert resp.content == "structured"
    assert resp.stop_reason == "max_tokens"
    assert resp.usage == {"input_tokens": 12, "output_tokens": 4}


def test_fake_model_client_satisfies_protocol() -> None:
    client = FakeModelClient(responses=["x"])
    # runtime_checkable Protocol: isinstance works.
    assert isinstance(client, ModelClient)


# ---------------------------------------------------------------------------
# load_prompt
# ---------------------------------------------------------------------------


def test_load_prompt_finds_real_prompts() -> None:
    # This walks up from core/llm.py to the repo prompts/ dir.
    body = load_prompt("system")
    assert isinstance(body, str)
    assert len(body.strip()) > 0


def test_load_prompt_accepts_explicit_root(tmp_path: Path) -> None:
    (tmp_path / "mine.md").write_text("hello from a custom prompt", encoding="utf-8")
    body = load_prompt("mine", prompts_root=tmp_path)
    assert body == "hello from a custom prompt"


def test_load_prompt_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(PromptNotFoundError):
        load_prompt("does-not-exist", prompts_root=tmp_path)


def test_load_prompt_rejects_traversal(tmp_path: Path) -> None:
    with pytest.raises(PromptNotFoundError):
        load_prompt("../outside", prompts_root=tmp_path)


def test_load_prompt_rejects_absolute_path(tmp_path: Path) -> None:
    with pytest.raises(PromptNotFoundError):
        load_prompt("/etc/passwd", prompts_root=tmp_path)


def test_load_prompt_rejects_empty_name(tmp_path: Path) -> None:
    with pytest.raises(PromptNotFoundError):
        load_prompt("", prompts_root=tmp_path)
