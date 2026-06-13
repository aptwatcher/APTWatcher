# Tier gating

> How APTWatcher decides, at startup, which capabilities are available
> at all — before any per-invocation authorization kicks in.

---

## Purpose

APTWatcher is an autonomous defensive IR agent. It runs forensic tools,
calls external intel APIs, writes tickets, and — at higher tiers — can
take containment actions. Not every deployment needs every capability,
and several are actively dangerous to enable without operator intent
(containment can destroy evidence; offensive actions can hit the wrong
target). The **tier-gating mechanism** is the outer architectural
guardrail: a single config surface controls *which classes of tool are
available to the running agent*. It ships safely by default (Tier 0
only), and every additional class is opt-in. This is a direct response
to the hackathon's weighted "architectural guardrails" criterion — a
judge can read one config file and know exactly what the agent is
allowed to reach for.

---

## Model

Five tiers, stacked by blast radius:

| Tier | Name                     | Default state | Who can flip it                          | Spoliation risk if abused                           |
|------|--------------------------|---------------|------------------------------------------|-----------------------------------------------------|
| 0    | Core forensic triage     | **enabled**   | Nobody — always on; flip would disable agent | Low: read-only SIFT wrappers; `sift_update` mutates the VM but is consent-gated |
| 1    | External threat intel    | opt-in        | Operator (config), needs provider creds  | Leaks IOCs off-box (privacy, not integrity)         |
| 2    | IR workflow integration  | opt-in        | Operator (config) + GLPI endpoint        | Writes tickets / KB; wrong entity id = data leak    |
| 3    | Defensive containment    | opt-in        | Operator (config) **+** `--enable-containment` | Kills processes, resets TCP; can disturb live state |
| 4    | Offensive containment    | **gated**     | Operator (config) **+** `--enable-offensive` + legal ack | Targets adversary infrastructure; legal exposure    |

Tier 0 is the one tier whose flag defaults to `True`. Everything above
is off unless the operator explicitly edits the config. Tiers 3 and 4
additionally require a CLI flag at the process boundary (see **Layered
gates** below) — the config flag alone is necessary but not sufficient.

---

## Config surface

The tier flags live on `APTWatcherConfig.tiers`, a pydantic model
defined in `src/core/config.py` (lines 30–35):

```python
class TierConfig(_Section):
    tier_0: bool = True
    tier_1: bool = False
    tier_2: bool = False
    tier_3: bool = False
    tier_4: bool = False
```

`APTWatcherConfig.tiers` wires it in (lines 97–104) with
`Field(default_factory=TierConfig)`. The module-level
`default_config()` helper (line 119) returns
`APTWatcherConfig()` — i.e. Tier 0 on, everything else off — and is
the fallback used by the MCP server when no config path is supplied.

In YAML, an operator enabling Tier 1 and Tier 2 would write:

```yaml
tiers:
  tier_1: true
  tier_2: true
```

Omitted keys take the class defaults; pydantic refuses unknown keys
with the normal validation error. `load_config(path)` in
`src/core/config.py` (lines 107–116) parses the YAML, enforces the
mapping shape, and returns a typed `APTWatcherConfig`.

---

## Server-side enforcement

The MCP server (`src/mcp_server/server.py`) loads the config exactly
once, at `build_server()` time (line 72), and closes over the
resulting `cfg` in every tool. Each tool that does real work starts
with a short tier check. Example: `run_volatility_tool` (lines
182–201):

```python
def run_volatility_tool(
    memory_image: str,
    plugin: str,
    plugin_args: list[str] | None = None,
    timeout: float = 600.0,
) -> dict[str, Any]:
    if not cfg.tiers.tier_0:
        return {"error": "Tier 0 is disabled in the active config."}
    try:
        result = run_volatility(...)
    except VolatilityPluginError as exc:
        return {"error": f"plugin_not_allowed: {exc}"}
    ...
    return result.model_dump(mode="json")
```

The same pattern repeats verbatim for `run_log2timeline_tool` (line
231), `run_psort_tool` (line 262), `run_bulk_extractor_tool` (line
307), and `run_sift_update_tool` (line 352).

Why **return a structured dict** rather than raising? MCP tools must
return JSON-serializable responses over stdio. Raising would surface
to the client as a transport-level protocol error, indistinguishable
from a crashed server. Returning `{"error": "..."}` keeps the call
shape well-formed, lets the agent reason about the refusal, and
leaves a clean trace in the audit log.

---

## Layered gates

Tier-gating decides **availability** — "is this tool callable at all
in this deployment?" It is deliberately coarse. Several tools stack
additional **authorization** gates on top, for per-invocation intent:

- **`sift_update`** is Tier 0, but `run_sift_update` in
  `src/core/sift/update.py` (lines 97–102) additionally raises
  `SiftUpdateConsentError` if `consent_token` is empty or whitespace.
  When consent is present, the function emits a
  `sift_update_consent` audit event (lines 122–131) *before* any
  apt-get invocation, recording `consent_token_present`,
  `consent_token_length`, the package list, and `dry_run`. The raw
  token string is never logged.
- **Tier 3 containment** (cnc_disruptor wrappers, scaffold only at
  time of writing) requires both `cfg.tiers.tier_3` **and** a
  `--enable-containment` CLI flag at the process boundary. The
  `ContainmentConfig.require_per_action_confirm` default
  (`src/core/config.py` line 83) adds a third, per-call prompt.
- **Tier 4 offensive** requires `cfg.tiers.tier_4`, an
  `--enable-offensive` flag, and a legal-acknowledgement phrase
  defined on `OffensiveConfig.legal_ack_phrase` (line 90).

The rationale: a single boolean can express "this class of capability
is available here," but it cannot express "the operator intends to
use it, right now, for this specific target." Those are different
questions and they want different mechanisms.

---

## Deployment-mode equivalence

All three deployment modes described in
`docs/design/deployment-modes.md` (Mode A CLI via
`aptwatcher run`, Mode B MCP server via `aptwatcher-mcp`, Mode C
hybrid) read the same `config.yaml` through the same
`load_config()` call. There is no mode-specific tier logic. A
config that enables Tier 1 in the MCP server enables Tier 1
identically in the CLI; a Tier 0-only default behaves identically
everywhere. This is a direct consequence of keeping all business
logic in `src/core/` and making the deployment surfaces thin entry
points.

---

## Failure modes

Known ways tier-gating can go wrong, with the chosen mitigation:

- **A new tool forgets the gate.** Mitigation: every new tiered
  MCP tool gets a unit test asserting that, with its tier flag set
  to `False`, the tool returns the `{"error": ...}` dict and does
  not invoke the underlying runner. See **Testing pattern** below.
- **Tier flag flipped mid-run.** Mitigation: `build_server()` reads
  the config once at startup and closes over it; there is no
  file-watcher and no hot-reload. An operator who wants to change
  tiers must restart the process. This is an intentional
  architectural decision (see docs/ARCHITECTURE.md).
- **Consent token logged in plaintext.** Mitigation: the
  `sift_update_consent` event in `src/core/sift/update.py` records
  `consent_token_present: True` and `consent_token_length: len(...)`
  but never the token itself. Same discipline applies to future
  consent-gated tools.
- **MCP client assumes a missing tool means "not supported."**
  Mitigation: all tier-gated tools are always *registered*;
  refusals are runtime, not registration-time. The server
  docstring (`src/mcp_server/server.py` lines 65–83) flags this.

---

## Testing pattern

Every tiered tool MUST have a test suite that covers, at minimum:

1. **Enabled path** — with the relevant tier flag `True`, the tool
   executes and returns a valid result dict.
2. **Disabled path** — with the relevant tier flag `False`, the
   tool returns `{"error": ...}` and does **not** raise.
3. **Layered-gate path** — if the tool has a secondary gate
   (consent token, CLI flag, legal ack), the suite exercises the
   missing-gate refusal separately from the tier refusal.

`tests/test_sift_update.py` is the reference: 11 tests covering
empty/whitespace consent tokens, unknown packages, empty package
lists, dry-run flag semantics, default package set, sudo prefix
behavior, and the consent audit event firing before the tool call.
New tier-gated tools should mirror that shape.

---

## References

- `../ARCHITECTURE.md` (pending) — system overview
- `./deployment-modes.md` — the three surfaces that share this gate
- `./tier0-sift-lifecycle.md` — Tier 0 bootstrap contract
- `./tier1-intel-lookup-pattern.md` — Tier 1 provider shape
- `../reference/mcp-tools.md` — full tool inventory
- Source: `src/core/config.py`, `src/mcp_server/server.py`, `src/core/sift/update.py`

---

## Discrepancies found

- **Tier 1–4 enforcement is unobserved.** `src/mcp_server/server.py`
  currently registers Tier 0 tools only; Tier 1/2/3/4 tools live as
  `core/intel/`, `core/integrations/`, and cnc_disruptor scaffolds
  but are not exposed over MCP yet. The tier-gating *mechanism* is
  in place (the `cfg.tiers.tier_N` flags exist and the check pattern
  is established), but the runtime assertion for tiers 1–4 is only
  visible in tests, not in the server surface. Expect this section
  to expand as those tools land.
- **The "Tier 4 gated (separate flag + runtime warning)" decision is
  partially realized.** The separate flag exists
  (`OffensiveConfig.enabled`, `require_legal_ack`,
  `legal_ack_phrase` in `src/core/config.py` lines 87–90), but the
  runtime warning path has no code yet. It will be added when the
  first offensive tool is wired.
- **Truncation artifact in `src/mcp_server/server.py`.** The file
  on disk contains duplicated content past line 423 (the
  `__all__ = [...]` line), appearing to be a mid-edit truncation
  leftover. This is cosmetic — the duplicated block is unreachable
  — but should be cleaned up. Noted here rather than fixed in this
  doc-only pass.
