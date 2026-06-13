# Evidence integrity

> **Status**: design note, in force. Author: APTWatcher core.
> **Scope**: Tier 0 forensic triage on Protocol SIFT.
> **Related**: [`../ARCHITECTURE.md`](../ARCHITECTURE.md),
> [`../architecture/audit-logging.md`](../architecture/audit-logging.md),
> [`./tier-gating.md`](./tier-gating.md),
> [`./offline-to-online-handoff.md`](./offline-to-online-handoff.md),
> [`../reference/sift-tools.md`](../reference/sift-tools.md).

## Principle

APTWatcher is **read-only by default**. Every Tier 0 wrapper treats the
evidence it touches (memory images, disk images, pcap captures, triage
bundles, plaso storage files) as immutable input. Every state-changing
action — SIFT package upgrades, containment — logs a pre/post hash chain
tied to the operator consent that authorized it. Every wrapped tool
documents its spoliation posture in the `extra_audit_payload` of its
closing `tool_call` event so that after-the-fact review can verify, per
invocation, that no evidence surface was mutated during triage.

## Threat model

The agent explicitly defends against four failure modes. Operator error
and deliberate tampering are treated the same: the audit log must make
both detectable.

| Threat | Mitigation |
|---|---|
| **Accidental spoliation** — analyst runs a tool that writes back to the evidence drive (e.g., plaso indexing a mounted-rw image). | Wrappers only accept paths as inputs. Sources are documented read-only in the audit payload. Output paths are caller-provided and must sit outside the evidence tree (policed at a higher layer where `EvidenceFile` metadata is available). |
| **Silent mutation** — a tool produces output side-effects unnoticed (e.g., log2timeline appending to an existing `.plaso` file). | Refuse-to-overwrite guard in `plaso.py` and `bulk_extractor.py`: if the destination already exists (file) or is non-empty (directory), the wrapper raises `ToolRunError` before `subprocess.run`. |
| **Evidence forgery** — post-acquisition swap of a file, hash collision claim, or bit-flip on the evidence mount. | SHA-256 manifest recorded at preflight (`hash_evidence_file` / `build_evidence_manifest` in `src/core/preflight.py`). The manifest is part of the `PreflightReport` persisted verbatim to the audit log. |
| **Incomplete chain of custody** — audit events lost between acquisition, triage, and report. | Every `tool_call` emits paired `phase="start"` / `phase="end"` events sharing a `correlation_id`. A start without a matching end is a detectable tampering or crash signal. `run_start` / `run_end` bracket the whole session. |

## Hash chain primitives

`src/core/preflight.py` defines two primitives. The algorithm is
**SHA-256** with a **1 MiB chunked read**, so multi-gigabyte disk or
memory images do not OOM the triage VM:

```python
def hash_evidence_file(path: Path, *, chunk_size: int = 1 << 20) -> str:
    """SHA-256 of an evidence file. Chunked so multi-GB images don't OOM."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()
```

`build_evidence_manifest(paths)` hashes every path, classifies it via
naive heuristics (`disk_image`, `memory_image`, `pcap`, `triage_bundle`,
`log_bundle`, `other`), and returns a `list[EvidenceFile]`. The
classification is a hint for downstream wrappers — callers who know
better can pre-build `EvidenceFile` records.

## Preflight manifest

Before any triage task, `preflight(profile_name, evidence_paths=...)`
hashes every evidence file declared by the operator and records them in
the returned `PreflightReport`, which the caller is expected to persist
to the audit log as a `preflight` event. The manifest shape:

```python
class EvidenceFile(_Model):
    path: str
    sha256: str
    size_bytes: int
    kind: Literal["disk_image", "memory_image", "triage_bundle",
                  "pcap", "log_bundle", "other"]

class PreflightReport(_Model):
    profile: str
    tool_inventory: list[ToolVersion]
    missing_required: list[str]
    missing_optional: list[str]
    evidence_manifest: list[EvidenceFile]
    tier_config: dict[str, bool]
    warnings: list[str]
    ok: bool
    generated_at: datetime
```

> **Gap (documented; see "Future work")**: today the hashes are
> computed **once, at preflight only**. There is no end-of-task
> re-hash comparing the manifest against the final state. The audit
> log therefore proves what the agent *claimed* at the start; it does
> not yet prove the evidence files were byte-identical at the end of
> the run. A malicious or buggy wrapper could, in principle, mutate
> evidence after preflight without the current design detecting it at
> the manifest level. This is the single most important open item in
> this spec.

## Read-only assertions in tool wrappers

Every wrapper appends a per-invocation assertion to its closing
`tool_call` event via `run_tool(..., extra_audit_payload=...)`. The
convention is a boolean flag named after the source input, ending in
`_readonly_assumed`. One wrapper, one assertion, every run. Current
wrappers:

| Wrapper | Source | Audit flag | Spoliation posture |
|---|---|---|---|
| `volatility3` (`src/core/sift/volatility.py`) | memory image | `memory_image_readonly_assumed=True` | Image is read-only; output is stdout only. No `--dump`, no `--output-dir` in the allow-listed plugin set. |
| `plaso log2timeline` (`src/core/sift/plaso.py`) | disk image / mount / file | `source_readonly_assumed=True` | Source read-only; writes a **new** `.plaso` storage file. Refuse-to-overwrite enforced. |
| `plaso psort` (`src/core/sift/plaso.py`) | `.plaso` storage file | `storage_file_readonly_assumed=True` | Storage file read-only; writes a **new** timeline output file (CSV / JSON / dynamic). Refuse-to-overwrite enforced. |
| `bulk_extractor` (`src/core/sift/bulk_extractor.py`) | disk / memory / file tree | `source_readonly_assumed=True` | Source read-only; writes into a **new or empty** `output_dir`. Refuse-to-overwrite enforced. |
| `sift_update` (`src/core/sift/update.py`) | SIFT VM packages | `mutates_sift_vm=<bool>` | **MUTATES the SIFT VM, not evidence.** Gated by a non-empty `consent_token`; emits a `sift_update_consent` audit event *before* the `tool_call`. Default is `dry_run=True` (simulate only). Package set is allow-listed. |

> **Naming inconsistency (documented gap)**: three wrappers use
> `source_readonly_assumed`, `volatility3` uses
> `memory_image_readonly_assumed`, and `psort` uses
> `storage_file_readonly_assumed`. Semantically equivalent, lexically
> divergent. Reviewers must tolerate all three variants until the
> wrappers converge on a single key (tracked in Future work).

## Refuse-to-overwrite policy

Pattern: if the declared destination already exists in a form that
would mean overwriting prior output, the wrapper raises `ToolRunError`
**before** invoking the underlying binary. No byte is written, no
`tool_call` start event is emitted. From `bulk_extractor.py`:

```python
if output_dir.exists():
    if not output_dir.is_dir():
        raise ToolRunError(
            f"Output path exists and is not a directory: {output_dir}",
        )
    if any(output_dir.iterdir()):
        raise ToolRunError(
            f"Output directory is not empty: {output_dir}. "
            "Refusing to overwrite bulk_extractor results; "
            "pick a new output directory.",
        )
```

`plaso.py` uses the equivalent check on both the `.plaso` storage file
(`run_log2timeline`) and the final timeline output (`run_psort`). In
both cases, "exists" is an immediate refusal — there is no `--force`
flag. Operators who need to rerun must pick a new path or delete the
prior output themselves, an action they own.

## Audit pairing and correlation IDs

`src/core/sift/runner.py:run_tool()` generates one `correlation_id`
per invocation (`uuid.uuid4().hex`) and emits two events that share it:

- **Start event**: `event_type="tool_call"`, `phase="start"`, carrying
  the full argv, the resolved binary path, the wrapper's
  `extra_audit_payload` (which is where `*_readonly_assumed` lives),
  and `cwd` if any.
- **End event**: `event_type="tool_call"`, `phase="end"`, carrying
  `returncode`, `duration_seconds`, `timed_out`,
  `stdout_bytes` / `stderr_bytes`.

If the Python process crashes mid-run, the OS terminates the subprocess,
or the operator kills the VM, the start event survives on disk (the
audit log is line-appended JSONL). The absence of a matching end event
is a detectable tampering-or-crash signal for post-incident review and
for the `run_end` reconciliation pass. Every session is further bracketed
by `run_start` / `run_end` events that share the `incident_id`, so a
truncated log can be distinguished from a clean exit.

## Future work

Designed but not yet implemented. None of these bullets block the MVP;
all of them tighten the integrity guarantee end-to-end and are
prerequisites for the Phase 3.7 `IncidentBundle`.

- **Post-task re-hash.** Re-run `build_evidence_manifest()` against the
  same paths at `run_end` and emit a diff event against the preflight
  manifest. Any mismatch is an integrity violation and must surface as
  a run-level finding, not a warning buried in the log.
- **Detached signature on the audit log.** Ed25519-sign the canonical
  JSON of the completed audit log at `run_end`. Key material lives
  outside the SIFT VM; the signature travels with the bundle.
- **`IncidentBundle` carries the manifest + signature.** Phase 3.7's
  portable handoff payload embeds the evidence manifest and the
  detached signature so a downstream online agent can verify
  end-to-end integrity before acting on findings. See
  [`./offline-to-online-handoff.md`](./offline-to-online-handoff.md).
- **Spoliation-flag propagation.** `core.types.SpoliationRisk` is
  defined (`read_only` | `state_changing_operational` |
  `state_changing_external`) but **no model field consumes it today**.
  Plumb it through `ToolRunResult` → `FindingCitation` → `Finding` →
  report so readers can see at a glance which findings depend on a
  state-changing call (none, for Tier 0).
- **Uniform readonly-assertion key.** Converge volatility3's
  `memory_image_readonly_assumed` and psort's
  `storage_file_readonly_assumed` onto a single
  `source_readonly_assumed` key, with an optional `source_kind` label.
  Simplifies audit-log grep / jq queries.
- **Post-state hashing for Tier 3/4 containment.**
  `ContainmentResult` already declares `pre_state_hash` and
  `post_state_hash` fields, but there is no wrapper that computes
  them yet. This lands alongside the first cnc_disruptor wrapper.

## Testing patterns

Every new wrapper MUST ship tests asserting three invariants. See
`tests/test_bulk_extractor.py`
(11 tests) and
`tests/test_plaso.py` (12 tests) for the
current reference implementations:

1. **Readonly audit assertion is present.** After a successful
   (mocked) run, the captured audit events contain a `tool_call`
   `phase="start"` with the wrapper's `*_readonly_assumed` flag set
   to `True` (or `mutates_sift_vm` for `sift_update`).
2. **Refuse-to-overwrite path raises before subprocess.** When the
   destination exists and is non-empty, the wrapper raises
   `ToolRunError` **without** a `tool_call` event being emitted.
   The test asserts the mock subprocess runner was never called.
3. **Paired start/end events.** A successful invocation emits
   exactly two `tool_call` events with the same `correlation_id`,
   one `phase="start"` and one `phase="end"`, in order.

Allow-list tests are not in this spec's scope but remain a per-wrapper
requirement: unknown plugin names, parser presets, scanners, or
packages must raise a wrapper-specific `ValueError` subclass before
argv is constructed.

## References

- [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — system overview, shared
  brain boundary, deployment modes.
- [`../architecture/audit-logging.md`](../architecture/audit-logging.md)
  — full JSONL event catalogue, correlation-id rules, `run_start` /
  `run_end` bracketing.
- [`./tier-gating.md`](./tier-gating.md) — which tiers may emit
  state-changing `tool_call` events; Tier 0 is read-only by
  construction.
- [`./offline-to-online-handoff.md`](./offline-to-online-handoff.md)
  — `IncidentBundle` schema; how the evidence manifest and detached
  signature travel across the offline-online boundary.
- [`../reference/sift-tools.md`](../reference/sift-tools.md) — per-tool
  version minima, allow-listed plugin / parser / scanner sets, and
  spoliation-posture summaries mirrored from the wrappers.
