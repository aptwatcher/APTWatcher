"""
LLM adapter layer.

Defines the contract between the agent loop and any concrete model
backend (Anthropic API, an MCP sampling transport, an on-host local
model, or a deterministic fake for tests).

Keep this module **dependency-free** beyond the standard library and
pydantic. Concrete adapters (Anthropic, etc.) live in their own
sub-module and import from here, not the other way around.

Contract at a glance:

    class ModelClient(Protocol):
        def complete(self, request: ModelRequest) -> ModelResponse: ...

- `ModelRequest` carries the system prompt, ordered user/assistant
  messages, and generation knobs (max_tokens, temperature).
- `ModelResponse` carries the assistant text, a stop reason, and a
  best-effort token-usage dict.
- `FakeModelClient` is provided so tests and offline runs never need a
  real model. It replays canned responses in call order and raises
  cleanly when exhausted.
- `load_prompt(name)` reads from the repository's `prompts/` directory
  and returns the file contents as a single string.

Design notes:

- The protocol is synchronous on purpose. AgentLoop runs one step at
  a time; streaming / async concurrency is a later concern. An async
  adapter can always wrap a sync call.
- Messages carry `role` and `content` only. Tool-call structured
  payloads, image parts, etc. are deferred until we actually need
  them. YAGNI is cheap; premature abstractions are not.
- Token usage is Optional because some adapters (the fake one, or a
  local model) do not report it. Callers should not rely on it.

References:
- docs/architecture/self-correction.md (where LLMPlanner plugs in)
- prompts/system.md (default system prompt)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

MessageRole = Literal["system", "user", "assistant"]
StopReason = Literal["end_turn", "max_tokens", "stop_sequence", "error", "fake"]


class _Model(BaseModel):
    """Base config mirroring core.types._Model. Kept local to avoid cycles."""

    model_config = ConfigDict(
        frozen=False,
        extra="forbid",
        populate_by_name=True,
    )


class ModelMessage(_Model):
    """One turn in a chat-style request. `system` messages may appear
    only as the first entry (enforced by ModelRequest validation)."""

    role: MessageRole
    content: str


class ModelRequest(_Model):
    """
    Input to `ModelClient.complete`.

    `messages` must contain at least one user message. If the caller
    wants a system prompt, set it on `system` rather than prepending a
    `system` role message -- this keeps adapters consistent regardless
    of whether their native API takes system as a top-level field (the
    Anthropic Messages API) or as a leading message.
    """

    system: str | None = None
    messages: list[ModelMessage] = Field(default_factory=list)
    max_tokens: int = Field(default=1024, ge=1, le=32_000)
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    stop_sequences: list[str] = Field(default_factory=list)

    def with_user(self, text: str) -> ModelRequest:
        """Return a copy with one additional user message appended."""
        return self.model_copy(
            update={
                "messages": [*self.messages, ModelMessage(role="user", content=text)],
            },
        )


class ModelResponse(_Model):
    """Output of `ModelClient.complete`. Always has non-None `content`
    (even if empty string); usage/stop_reason are best-effort."""

    content: str
    stop_reason: StopReason = "end_turn"
    usage: dict[str, int] | None = None
    model: str | None = None
    raw: dict[str, Any] | None = None


@runtime_checkable
class ModelClient(Protocol):
    """The single call every strategy layer uses to reach the model."""

    def complete(self, request: ModelRequest) -> ModelResponse:
        ...  # pragma: no cover -- Protocol method


# ---------------------------------------------------------------------------
# Fake client -- canned replay for tests / offline mode
# ---------------------------------------------------------------------------


class FakeClientExhausted(RuntimeError):  # noqa: N818 — established public name
    """Raised when FakeModelClient runs out of canned responses."""


class FakeModelClient:
    """
    Deterministic replay-based model client.

    Construct with a list of canned `ModelResponse` objects (or plain
    strings, which are lifted into a default response). Each call to
    `complete` returns the next one in order. Running out raises
    `FakeClientExhausted` -- tests should always provide exactly the
    responses they expect.

    Recorded calls can be inspected via `.calls` (list of ModelRequest).
    """

    def __init__(
        self,
        responses: list[ModelResponse | str] | None = None,
        *,
        model_name: str = "fake-model",
    ) -> None:
        self._queue: list[ModelResponse] = []
        for item in responses or []:
            if isinstance(item, str):
                self._queue.append(
                    ModelResponse(
                        content=item,
                        stop_reason="fake",
                        model=model_name,
                    ),
                )
            else:
                self._queue.append(item)
        self.calls: list[ModelRequest] = []
        self._model_name = model_name

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.calls.append(request)
        if not self._queue:
            raise FakeClientExhausted(
                f"FakeModelClient has no more canned responses (call #{len(self.calls)}).",
            )
        return self._queue.pop(0)

    @property
    def remaining(self) -> int:
        return len(self._queue)


# ---------------------------------------------------------------------------
# Prompt loading
# ---------------------------------------------------------------------------


class PromptNotFoundError(FileNotFoundError):
    """Raised when load_prompt cannot resolve a prompt file."""


def load_prompt(
    name: str,
    *,
    prompts_root: Path | None = None,
) -> str:
    """
    Load a prompt file from the repository's `prompts/` directory.

    `name` may be a bare name (`"system"`, `"self-correction-checklist"`)
    -- the `.md` extension is appended if missing. Path traversal is
    rejected (`"../etc/passwd"` raises). Absolute paths are rejected.
    """
    if not name:
        raise PromptNotFoundError("prompt name must be non-empty")
    if ".." in Path(name).parts or Path(name).is_absolute():
        raise PromptNotFoundError(
            f"prompt name {name!r} is not allowed (no traversal, no absolute paths).",
        )
    root = prompts_root or _default_prompts_root()
    candidate = root / name
    if not candidate.suffix:
        candidate = candidate.with_suffix(".md")
    if not candidate.exists() or not candidate.is_file():
        raise PromptNotFoundError(
            f"prompt {name!r} not found under {root!s}",
        )
    return candidate.read_text(encoding="utf-8")


def _default_prompts_root() -> Path:
    """
    Default prompts/ root: walk up from this file until we find a
    sibling `prompts/` directory. src/core/llm.py -> repo_root/prompts.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "prompts"
        if candidate.is_dir():
            return candidate
    # Fallback: repo root guess.
    return here.parent.parent.parent / "prompts"


__all__ = [
    "FakeClientExhausted",
    "FakeModelClient",
    "MessageRole",
    "ModelClient",
    "ModelMessage",
    "ModelRequest",
    "ModelResponse",
    "PromptNotFoundError",
    "StopReason",
    "load_prompt",
]
