# Alternative backend: OpenClaw (open-source, BYOK)

*Design note. Not yet implemented — scope + integration surface only.*

## Motivation

APTWatcher's current LLM backend is `AnthropicModelClient` (Claude via the
Anthropic API). That's the strongest-accuracy option, but it is not
budget-friendly for:

- Academic users and small SOCs that cannot justify per-token cost.
- Deployments on air-gapped IR workstations where an outbound Anthropic
  API call is blocked by policy.
- Long-running batch triage (overnight memory-image review across dozens
  of hosts) where per-token cost compounds fast.

[OpenClaw](https://github.com/anthropics-community/openclaw) is an
open-source, bring-your-own-key agent framework that first shipped in
November 2025 (originally "Clawdbot", renamed to "OpenClaw" in early
2026). It speaks a Claude-compatible message format, runs against any
OpenAI/Anthropic-style chat-completion endpoint, and can be pointed at
a local model server (vLLM, llama.cpp, Ollama) with no cloud
round-trip.

For APTWatcher this is a natural second backend: the same `ModelClient`
protocol already expects a `complete(request: ModelRequest) ->
ModelResponse` surface, so OpenClaw slots in behind the existing
strategy layer (`LLMPlanner`, `LLMVerifier`, `LLMSelfCorrector`) without
touching the agent loop.

## Integration surface

The `ModelClient` Protocol in `src/core/llm.py` already defines:

```python
class ModelClient(Protocol):
    def complete(self, request: ModelRequest) -> ModelResponse: ...
```

Adding an OpenClaw backend is purely a new adapter:

```
src/core/llm_openclaw.py       # new file — OpenClawModelClient
tests/test_llm_openclaw.py     # mocked-transport unit tests
```

`OpenClawModelClient` would:

1. Read `OPENCLAW_ENDPOINT` (default `http://127.0.0.1:11434/v1` for a
   local Ollama gateway) and `OPENCLAW_API_KEY` (optional — blank for
   local servers).
2. Translate `ModelRequest` → OpenAI-compatible chat payload.
3. POST via `httpx` with bounded timeout + retry.
4. Translate response → `ModelResponse` preserving the same
   `tool_use` / `text` block semantics the strategies already consume.
5. Emit `llm_call` audit events identically to `AnthropicModelClient`
   (same correlation_id, same redaction).

## CLI wiring

`aptwatcher run` already has a `--backend` flag. Extend:

```
--backend {null, anthropic, openclaw}
--model MODEL_ID            # e.g., "llama-3.1-70b-instruct"
--endpoint-env VAR_NAME     # defaults to OPENCLAW_ENDPOINT
--api-key-env VAR_NAME      # defaults to OPENCLAW_API_KEY
```

No change needed to `LLMPlanner` / `LLMVerifier` / `LLMSelfCorrector`.

## Accuracy + threshold policy

Open-weight models (Llama, Mistral, Qwen) typically score 10-25% lower
on MITRE-attribution F1 than Claude. The accuracy harness
(`docs/ACCURACY.md`) should gain a per-backend threshold table:

| backend    | mean F1 threshold | submission threshold |
|------------|-------------------|----------------------|
| null       | 0.00              | n/a                  |
| anthropic  | 0.60              | 0.80                 |
| openclaw   | 0.45              | 0.65                 |

The threshold matrix lives in the manifest, not in the runner, so new
backends can be added without code changes.

## Deployment profiles

Add two new recipes under `deploy/`:

- `deploy/openclaw-ollama/` — systemd unit + docker-compose for a local
  Ollama gateway; points APTWatcher at `http://127.0.0.1:11434/v1`.
- `deploy/openclaw-vllm/` — kubernetes + helm chart for a vLLM-backed
  shared inference cluster.

## Safety + audit parity

OpenClaw changes nothing about the safety posture:

- Tier gating is enforced at the agent loop, not the LLM.
- The audit log still sees `llm_call` events with full prompt + response
  bytes hashed; the bearer token (if any) is never logged.
- Consent gates (`sift_update_consent`, `timesketch_upload_consent`,
  containment confirmations) are identical.

## Caveats

- Self-correction gates assume the verifier is at least as capable as
  the planner. With a weak local model serving both, the
  self-correction loop can oscillate. Mitigation: set
  `--self-correct-max-iterations` low (2) for OpenClaw runs until we
  benchmark.
- Tool-use parsing on open-weight models is less reliable than on
  Claude. Wrapper `strategies/llm_planner.py` already has a strict
  JSON-repair pass; add a second pass that falls back to regex-extracted
  tool names when the JSON parse fails.
- Network egress: `OPENCLAW_ENDPOINT` defaults to localhost. Remote
  endpoints are allowed, but the deployment doc must make that opt-in.

## Decision + timing

**Status: noted, not scheduled.** OpenClaw support is a post-hackathon
milestone. Pre-submission priorities (demo recording, Devpost upload,
GitHub publication) come first. Open-source backend support is a natural
next feature once the judging period closes and we have time to
benchmark Llama-3.1-70B + Qwen2.5-72B against the 8-scenario accuracy
harness.

## References

- `src/core/llm.py` — `ModelClient` Protocol, `ModelRequest`,
  `ModelResponse`.
- `src/core/llm_anthropic.py` — the only current concrete
  implementation, to mirror.
- `docs/ACCURACY.md` — accuracy methodology + threshold policy.
- `docs/architecture/mode-b-llm-ownership.md` — LLM-ownership decision.
- [OpenClaw on GitHub](https://github.com/) — upstream project.
