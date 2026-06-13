---
title: "MCP tool schemas"
status: draft
---

# MCP tool schemas

> Wire-level schema reference for every tool exposed by the APTWatcher MCP
> server. Covers request parameters, response shapes, error envelopes, and
> the audit correlation each tool emits.

This page is the byte-level contract. The higher-level tool inventory
lives in [`./mcp-tools.md`](./mcp-tools.md); the tier-gating rationale
lives in [`../design/tier-gating.md`](../design/tier-gating.md). When the
two pages disagree, this one wins for request and response shapes.

---

## 1. Overview

### Transport

- **Protocol:** Model Context Protocol (MCP) over the `FastMCP` runtime
  from the reference `mcp` Python package.
- **Transport:** `stdio` only. The `--transport` argparse option in
  `src/mcp_server/server.py` accepts a single choice (`stdio`); no HTTP
  or SSE surface is wired.
- **Entry point:** console script `aptwatcher-mcp` (registered in
  `pyproject.toml`), which calls `mcp_server.server:main`.
- **Server identity:** `FastMCP(name="aptwatcher", instructions=...)`.
  The instructions string is stale: it still claims "Tier 0 tools only
  in this build", but nine Tier 1 intel tools are registered (sections
  3.43-3.51). See section 7.
- **Session:** one process, one config. `build_server()` loads
  `APTWatcherConfig` once and closes over it. Operators changing tier
  flags must restart the process — there is no hot-reload.
- **Publication adapters are CLI-only.** `core.publish.*` adapters
  (Netcraft, MISP, GLPI, stub, TAXII 2.1) are **not** registered as
  MCP tools. They ship behind `aptwatcher publish --adapter <name>` so
  the dry-run / opt-in consent gate is controlled by the operator on a
  trusted shell, not exposed over an MCP session.

### Schema versioning approach

APTWatcher does **not** expose a server-wide `schema_version` on the
wire today. Schema evolution is tracked via three mechanisms:

1. **Package version.** The `aptwatcher_version` tool returns
   `{"version": "<semver>"}`. Clients that care about schema drift
   should call it once at session start and cache the result.
2. **Pydantic `extra="forbid"`.** Every request and response model in
   `src/core/types.py` and `src/core/sift/runner.py` rejects unknown
   keys at validation time. Adding a field is a backward-compatible
   change for producers but a breaking change for any client that
   round-trips the model through its own validator.
3. **Tool-level additions.** New tools are added, never silently
   renamed. Renames go through a one-release deprecation cycle with
   both names registered.

The future `IncidentBundle` export (Phase 3.7) carries its own
`schema_version` field; that is separate from the MCP wire schema
discussed here.

### Common envelope fields

MCP tools in this server return one of two shapes:

- **Success:** a JSON object whose keys are tool-specific. Most tools
  return `result.model_dump(mode="json")` from a pydantic model, so the
  shape is stable.
- **Failure:** a JSON object with exactly one key, `error`, whose value
  is a string of the form `"<error_code>: <detail>"`. See section 2.

There is **no top-level `ok`, `status`, or `data` envelope**. Callers
distinguish success from failure by testing for the presence of an
`error` key:

```python
resp = await mcp_client.call_tool("run_volatility", {...})
if "error" in resp:
    handle_refusal(resp["error"])
else:
    handle_result(resp)
```

---

## 2. Common types

### Error envelope

All Tier-gated tool errors follow this shape:

```json
{
  "error": "<code>: <detail>"
}
```

Error codes currently emitted by registered tools:

| Code                       | Meaning                                                            | Raised by                                      |
|----------------------------|--------------------------------------------------------------------|------------------------------------------------|
| `Tier 0 is disabled...`    | Tier 0 flag is `False` in the active config                        | Every Tier 0 tool that does real work          |
| `Tier 1 is disabled...`    | Tier 1 flag is `False` in the active config                        | `intel_lookup`, `enrich_*`, `feed_*` (not the `admin_*` tools) |
| `plugin_not_allowed`       | Volatility plugin outside the allow-list                           | `run_volatility`                               |
| `parser_not_allowed`       | Plaso parser preset outside the allow-list                         | `run_log2timeline`                             |
| `output_format_not_allowed`| Psort output format outside the allow-list                         | `run_psort`                                    |
| `scanner_not_allowed`      | Bulk-extractor scanner outside the allow-list                      | `run_bulk_extractor`                           |
| `consent_required`         | `consent_token` missing or whitespace-only                         | `sift_update`                                  |
| `package_not_allowed`      | Debian package outside the `SIFT_UPDATE_PACKAGES` allow-list       | `sift_update`                                  |
| `runner_error`             | Structural precondition failure (missing binary, empty argv, etc.) | Any SIFT runner (`ToolRunError`)               |

### Tier-gated-disabled error shape

When a tool is registered but its tier is flipped off in config, the
tool returns:

```json
{
  "error": "Tier 0 is disabled in the active config."
}
```

Tier 1 tools return the same shape with `"Tier 1 is disabled in the
active config."`. The string is returned verbatim. The tool still
exists on the wire (see `design/tier-gating.md` failure-mode: "MCP
client assumes a missing tool means not supported"); refusal is a
runtime response, not a registration-time absence. Tier-gated tools
always advertise.

### Shared response shapes

#### `ToolRunResult` (from `core.sift.runner`)

Returned by `run_volatility`, `run_log2timeline`, `run_psort`,
`run_bulk_extractor`, and `sift_update`. Verbatim as the payload of
the closing `tool_call` audit event.

```json
{
  "tool": "volatility3",
  "argv": ["/usr/local/bin/vol.py", "-f", "/evidence/mem.raw", "windows.pslist"],
  "correlation_id": "7a1f3c9e2b6d4a08a3d2e4f590c11a77",
  "returncode": 0,
  "stdout": "...",
  "stderr": "",
  "duration_seconds": 12.413,
  "timed_out": false,
  "started_at": "2026-04-19T15:28:41.512034+00:00",
  "ended_at": "2026-04-19T15:28:53.925112+00:00",
  "notes": null
}
```

- `correlation_id` pairs the `phase=start` and `phase=end` `tool_call`
  audit events for this invocation.
- `ok` is available as a property on the pydantic model but is **not**
  serialized; it is equivalent to `returncode == 0 and not timed_out`.
- `notes` carries wrapper-side annotations (for example, the dry-run
  marker from `sift_update`).

#### `PreflightReport` (from `core.types`)

Returned by `preflight`. Persisted verbatim in the audit log.

```json
{
  "profile": "windows-host-triage",
  "tool_inventory": [
    {"name": "volatility3", "version": "2.5.2", "path": "/usr/local/bin/vol.py", "meets_minimum": true}
  ],
  "missing_required": [],
  "missing_optional": ["yara"],
  "evidence_manifest": [
    {"path": "/evidence/mem.raw", "sha256": "...", "size_bytes": 8589934592, "kind": "memory_image"}
  ],
  "tier_config": {"tier_0": true, "tier_1": false, "tier_2": false, "tier_3": false, "tier_4": false},
  "warnings": [],
  "ok": true,
  "generated_at": "2026-04-19T15:23:01.412034+00:00"
}
```

---

## 3. Registered tools

Every tool in this section is verified against a live `@mcp.tool`
decorator in `src/mcp_server/server.py` — 51 registrations in total.
Sections 3.1-3.42 cover the Tier 0 and server-metadata tools; sections
3.43-3.51 cover the nine Tier 1 intel tools. Tools that are still
planned but unregistered (the Tier 1 remainder and all of Tier 2-4)
are in section 4.

### 3.1 `preflight`

- **Tier:** 0
- **Purpose:** Probe the SIFT tool inventory for a named profile,
  classify and hash evidence paths, and report gaps. Must run before
  any triage tool.
- **SIFT tool wrapped:** none (reads tool paths via
  `core.preflight.probe_tool`).

#### Request

```json
{
  "profile": "windows-host-triage",
  "evidence_paths": ["/evidence/mem.raw", "/evidence/disk.E01"]
}
```

| Field            | Type              | Required | Default                | Notes                                             |
|------------------|-------------------|----------|------------------------|---------------------------------------------------|
| `profile`        | string            | no       | `windows-host-triage`  | Must match a key in `ALL_PROFILES`                |
| `evidence_paths` | list[string]/null | no       | `null`                 | Absolute paths; each file is SHA-256 hashed       |

#### Response

A `PreflightReport` dict (shape in section 2). Never returns `error`.

#### Error cases

- Unknown profile name: raises at the `preflight()` call site, which
  surfaces as an MCP framework error (not caught by the tool).

---

### 3.2 `list_profiles`

- **Tier:** 0
- **Purpose:** Return the registered use-case profiles with their
  declared tool and artifact needs.
- **SIFT tool wrapped:** none.

#### Request

```json
{}
```

No parameters.

#### Response

```json
{
  "windows-host-triage": {
    "name": "windows-host-triage",
    "description": "...",
    "required_tools": ["volatility3", "plaso"],
    "optional_tools": ["yara"],
    "required_artifact_categories": ["memory_image"],
    "optional_artifact_categories": ["event_log"],
    "tier_prerequisites": {"tier_0": "required"}
  }
}
```

Keys are profile names; values are `ProfileDefinition` dicts.

#### Error cases

None. Always returns an object (possibly empty if no profiles
registered).

---

### 3.3 `knowledge_search`

- **Tier:** 0
- **Purpose:** Keyword search the clean-room knowledge base. Returns
  entry IDs and paths the caller can cite. Entry **bodies are not
  returned** — call `knowledge_get` after picking a hit.
- **SIFT tool wrapped:** none.

#### Request

```json
{
  "query": "malfind injected code",
  "top_k": 5
}
```

| Field   | Type   | Required | Default | Notes                       |
|---------|--------|----------|---------|-----------------------------|
| `query` | string | yes      | —       | Free-text keyword query     |
| `top_k` | int    | no       | `5`     | Maximum entries returned    |

#### Response

List of entry summaries:

```json
[
  {
    "id": "kb-volatility-malfind",
    "title": "Volatility3 malfind plugin",
    "source_type": "author-original",
    "path": "knowledge/volatility/malfind.md",
    "mitre_techniques": ["T1055"],
    "last_updated": "2026-03-12"
  }
]
```

Returns `[]` if the KB root does not exist on disk or no entries
match.

#### Error cases

None at the tool layer. Missing KB root is treated as empty, not an
error.

---

### 3.4 `knowledge_get`

- **Tier:** 0
- **Purpose:** Return a single KB entry's body and metadata by id.
- **SIFT tool wrapped:** none.

#### Request

```json
{"entry_id": "kb-volatility-malfind"}
```

| Field      | Type   | Required | Notes                              |
|------------|--------|----------|------------------------------------|
| `entry_id` | string | yes      | Stable id from `knowledge_search`  |

#### Response

A `KBEntry` dict (full schema in `src/core/types.py`): fields `id`,
`title`, `source_type`, `attribution`, `mitre_techniques`,
`artifact_types`, `tools`, `last_updated`, `body`, `path`. Returns
`null` if the KB root is missing or no entry matches.

#### Error cases

None at the tool layer. Missing entry returns `null`.

---

### 3.5 `list_volatility_plugins`

- **Tier:** 0
- **Purpose:** Return the Tier 0 allow-list of volatility3 plugins.
- **SIFT tool wrapped:** none (introspection only).

#### Request

```json
{}
```

#### Response

Map of `plugin_name -> reason`:

```json
{
  "windows.pslist.PsList": "read-only process enumeration",
  "windows.malfind.Malfind": "read-only injected-code scan"
}
```

#### Error cases

None.

---

### 3.6 `run_volatility`

- **Tier:** 0
- **Purpose:** Run one allow-listed volatility3 plugin against a memory
  image. Read-only.
- **SIFT tool wrapped:** `volatility3` (`vol.py`).

#### Request

```json
{
  "memory_image": "/evidence/mem.raw",
  "plugin": "windows.pslist.PsList",
  "plugin_args": ["--pid", "1234"],
  "timeout": 600.0
}
```

| Field          | Type              | Required | Default | Notes                                          |
|----------------|-------------------|----------|---------|------------------------------------------------|
| `memory_image` | string            | yes      | —       | Absolute path to the memory image              |
| `plugin`       | string            | yes      | —       | Must be in `VOLATILITY_PLUGINS`                |
| `plugin_args`  | list[string]/null | no       | `null`  | Pass-through args after the plugin name        |
| `timeout`      | float             | no       | `600.0` | Seconds                                        |

#### Response

`ToolRunResult` dict (see section 2) on success.

#### Error cases

| Trigger                                         | Response                                          |
|-------------------------------------------------|---------------------------------------------------|
| Tier 0 disabled                                 | `{"error": "Tier 0 is disabled in the active config."}` |
| Plugin not in allow-list (`VolatilityPluginError`) | `{"error": "plugin_not_allowed: <detail>"}`       |
| Missing binary / bad argv (`ToolRunError`)      | `{"error": "runner_error: <detail>"}`             |

A non-zero process exit is **not** an error envelope — it returns a
normal `ToolRunResult` with `returncode != 0`.

---

### 3.7 `list_plaso_parser_presets`

- **Tier:** 0
- **Purpose:** Return the Tier 0 allow-list of plaso parser presets for
  `log2timeline --parsers`.
- **SIFT tool wrapped:** none.

#### Request / Response

```json
{}
```

Returns `{"<preset_name>": "<reason>"}`, e.g.:

```json
{"win7": "Windows 7+ host triage preset", "webhist": "web history artifacts"}
```

---

### 3.8 `run_log2timeline`

- **Tier:** 0
- **Purpose:** Extract a plaso storage file from a source image or
  directory. Refuses to overwrite an existing storage file.
- **SIFT tool wrapped:** `log2timeline.py` (plaso).

#### Request

```json
{
  "source": "/evidence/disk.E01",
  "storage_file": "/runs/s01/timeline.plaso",
  "parsers": "win7",
  "timeout": 3600.0
}
```

| Field          | Type   | Required | Default  | Notes                                              |
|----------------|--------|----------|----------|----------------------------------------------------|
| `source`       | string | yes      | —        | Path to image or directory                         |
| `storage_file` | string | yes      | —        | Output `.plaso` path; MUST NOT exist               |
| `parsers`      | string | yes      | —        | Preset name from `list_plaso_parser_presets`       |
| `timeout`      | float  | no       | `3600.0` | Seconds                                            |

#### Response

`ToolRunResult` dict on success.

#### Error cases

| Trigger                                      | Response                                            |
|----------------------------------------------|-----------------------------------------------------|
| Tier 0 disabled                              | `{"error": "Tier 0 is disabled in the active config."}` |
| Preset not in allow-list                     | `{"error": "parser_not_allowed: <detail>"}`          |
| Missing binary / existing storage file       | `{"error": "runner_error: <detail>"}`                |

---

### 3.9 `run_psort`

- **Tier:** 0
- **Purpose:** Convert a plaso storage file into a human-readable
  timeline. Output format must be in the allow-list
  (`l2tcsv`, `dynamic`, `json_line`). Refuses to overwrite the output
  file.
- **SIFT tool wrapped:** `psort.py` (plaso).

#### Request

```json
{
  "storage_file": "/runs/s01/timeline.plaso",
  "output_file": "/runs/s01/timeline.csv",
  "output_format": "dynamic",
  "time_filter": "date > '2026-01-01'",
  "timeout": 1800.0
}
```

| Field           | Type        | Required | Default     | Notes                                                 |
|-----------------|-------------|----------|-------------|-------------------------------------------------------|
| `storage_file`  | string      | yes      | —           | Input `.plaso`                                        |
| `output_file`   | string      | yes      | —           | Output path; MUST NOT exist                           |
| `output_format` | string      | no       | `"dynamic"` | One of `l2tcsv`, `dynamic`, `json_line`               |
| `time_filter`   | string/null | no       | `null`      | Plaso filter expression passed to `--slice`           |
| `timeout`       | float       | no       | `1800.0`    | Seconds                                               |

#### Response

`ToolRunResult` dict on success.

#### Error cases

| Trigger                                      | Response                                                 |
|----------------------------------------------|----------------------------------------------------------|
| Tier 0 disabled                              | `{"error": "Tier 0 is disabled in the active config."}`  |
| Output format not in allow-list              | `{"error": "output_format_not_allowed: <detail>"}`       |
| Missing binary / existing output file        | `{"error": "runner_error: <detail>"}`                    |

---

### 3.10 `list_bulk_extractor_scanners`

- **Tier:** 0
- **Purpose:** Return the Tier 0 allow-list of `bulk_extractor`
  scanners. Scanners outside the list (`ccn`, `aes`, ...) are not
  exposed at Tier 0.
- **SIFT tool wrapped:** none.

#### Request / Response

```json
{}
```

Returns `{"<scanner_name>": "<reason>"}`.

---

### 3.11 `run_bulk_extractor`

- **Tier:** 0
- **Purpose:** Run `bulk_extractor` against a source with an
  allow-listed scanner subset. Refuses to overwrite a populated output
  directory.
- **SIFT tool wrapped:** `bulk_extractor`.

#### Request

```json
{
  "source": "/evidence/disk.E01",
  "output_dir": "/runs/s01/bulk/",
  "scanners": ["email", "net", "url"],
  "timeout": 3600.0
}
```

| Field        | Type         | Required | Default  | Notes                                                 |
|--------------|--------------|----------|----------|-------------------------------------------------------|
| `source`     | string       | yes      | —        | Disk image, directory, or device                      |
| `output_dir` | string       | yes      | —        | Must be absent or empty                               |
| `scanners`   | list[string] | yes      | —        | Every entry must be in `BULK_EXTRACTOR_SCANNERS`      |
| `timeout`    | float        | no       | `3600.0` | Seconds                                               |

#### Response

`ToolRunResult` dict on success.

#### Error cases

| Trigger                                      | Response                                                 |
|----------------------------------------------|----------------------------------------------------------|
| Tier 0 disabled                              | `{"error": "Tier 0 is disabled in the active config."}`  |
| Any scanner not in allow-list                | `{"error": "scanner_not_allowed: <detail>"}`             |
| Populated output dir / missing binary        | `{"error": "runner_error: <detail>"}`                    |

---

### 3.12 `list_sift_update_packages`

- **Tier:** 0
- **Purpose:** Return the allow-list of forensic packages
  `sift_update` may refresh.
- **SIFT tool wrapped:** none.

#### Request / Response

```json
{}
```

Returns `{"<debian_package>": "<reason>"}`.

---

### 3.13 `sift_update`

- **Tier:** 0 (consent-gated layered on top)
- **Purpose:** Refresh the SIFT forensic toolchain (plaso, volatility3,
  yara, bulk_extractor, sleuthkit, ...) after explicit user consent.
  Defaults to `dry_run=True` (`apt-get -s`); caller must set
  `dry_run=False` to mutate the VM.
- **SIFT tool wrapped:** `apt-get` / `sift-update` (Debian package
  manager).

#### Request

```json
{
  "consent_token": "operator-confirmed-2026-04-19T15:20Z",
  "packages": ["plaso", "volatility3"],
  "dry_run": true,
  "timeout": 1800.0
}
```

| Field           | Type              | Required | Default  | Notes                                                     |
|-----------------|-------------------|----------|----------|-----------------------------------------------------------|
| `consent_token` | string            | yes      | —        | Non-empty, non-whitespace; never logged in plaintext      |
| `packages`      | list[string]/null | no       | `null`   | Subset of `SIFT_UPDATE_PACKAGES`; `null` means full set   |
| `dry_run`       | bool              | no       | `true`   | When `false`, the VM is actually mutated                  |
| `timeout`       | float             | no       | `1800.0` | Seconds                                                   |

Consent enforcement lives in `core.sift.update.run_sift_update`, which
emits a `sift_update_consent` audit event **before** any `apt-get`
invocation. The event records `consent_token_present`,
`consent_token_length`, the package list, and `dry_run` — never the
raw token string.

#### Response

`ToolRunResult` dict on success. `notes` carries a `dry_run` marker
when applicable.

#### Error cases

| Trigger                                    | Response                                                 |
|--------------------------------------------|----------------------------------------------------------|
| Tier 0 disabled                            | `{"error": "Tier 0 is disabled in the active config."}`  |
| Empty / whitespace consent token           | `{"error": "consent_required: <detail>"}`                |
| Package outside allow-list                 | `{"error": "package_not_allowed: <detail>"}`             |
| Missing binary / privilege error           | `{"error": "runner_error: <detail>"}`                    |

---

### 3.14 `aptwatcher_version`

- **Tier:** server metadata (no tier gate).
- **Purpose:** Return the running server version. Safe to call at
  session start for schema-drift detection.
- **SIFT tool wrapped:** none.

#### Request

```json
{}
```

#### Response

```json
{"version": "0.1.0a0"}
```

#### Error cases

None.

---

### 3.15 `export_bundle`

- **Tier:** 0 (Phase 3.7 handoff surface).
- **Purpose:** Build a signed `IncidentBundle` directory on disk from
  findings, IOCs, and audit events. Writes the four payload files
  (`manifest.json`, `findings.json`, `iocs.json`, `audit.jsonl`) plus an
  Ed25519 `signature.json`. Returns the in-memory bundle aggregate so
  the caller can hash or re-sign without rereading from disk.

#### Request

| Field              | Type                    | Required | Notes                                                     |
|--------------------|-------------------------|----------|-----------------------------------------------------------|
| `bundle_dir`       | string                  | yes      | Target directory path; created if absent                  |
| `incident_id`      | string                  | yes      | Stable id shared with the offline audit log               |
| `operator`         | string                  | yes      | Human-readable signing operator identifier                |
| `sift_workstation` | string                  | yes      | Hostname / VM id the bundle was produced on               |
| `findings`         | list[object]            | yes      | Array of `Finding` dicts                                  |
| `audit_events`     | list[object]            | yes      | Chronological array of `AuditEvent` dicts                 |
| `private_key_hex`  | string                  | yes      | Raw 32-byte Ed25519 seed, hex-encoded                     |
| `iocs`             | list[object]/null       | no       | Array of `IOCVerdict` dicts; defaults to empty list       |
| `profile`          | string/null             | no       | Optional profile name that produced the bundle            |
| `notes`            | string/null             | no       | Optional free-form operator notes                         |

#### Response

An `IncidentBundle` dict (manifest + wrapped findings/iocs/audit + signature).

#### Error cases

| Trigger                              | Response                                        |
|--------------------------------------|-------------------------------------------------|
| Malformed findings / iocs / events   | `{"error": "invalid_input: <detail>"}`          |
| Non-hex `private_key_hex`            | `{"error": "invalid_private_key: <detail>"}`   |
| Signing failure                      | `{"error": "bundle_signature: <detail>"}`      |
| Payload write / digest failure       | `{"error": "bundle_integrity: <detail>"}`      |

---

### 3.16 `import_bundle`

- **Tier:** 0 (Phase 3.7 handoff surface).
- **Purpose:** Load a bundle directory produced by `export_bundle`,
  verify per-file sha256 digests against the manifest, and check the
  Ed25519 signature. Returns the in-memory `IncidentBundle` aggregate.

#### Request

| Field                     | Type         | Required | Default | Notes                                                                            |
|---------------------------|--------------|----------|---------|----------------------------------------------------------------------------------|
| `bundle_dir`              | string       | yes      | —       | Directory written by `export_bundle`                                             |
| `expected_public_key_hex` | string/null  | no       | `null`  | If provided, the signature's public key must match (pins the online-side signer) |
| `verify`                  | bool         | no       | `true`  | When `false`, digests and signature are not checked (offline inspection only)    |

#### Response

An `IncidentBundle` dict. When `verify=false`, `signature` may be
absent.

#### Error cases

| Trigger                                                        | Response                                  |
|----------------------------------------------------------------|-------------------------------------------|
| Missing payload file / digest mismatch / counts mismatch       | `{"error": "bundle_integrity: <detail>"}` |
| Missing signature file / bad signature / key-pin mismatch      | `{"error": "bundle_signature: <detail>"}` |

---

### 3.17 `generate_yara_rules`

- **Tier:** 0 (Phase 3.8 analysis surface).
- **Purpose:** Synthesize YARA rules from findings and IOCs. Emits one
  hash-match rule per SHA-256 value (explicit or carried on an IOC of
  type `sha256`) and one string-match rule per filename appearing
  across at least three finding citations. Rule identifiers are
  uppercase and prefixed with a sanitized `campaign_tag`.

#### Request

| Field          | Type                | Required | Default        | Notes                                                    |
|----------------|---------------------|----------|----------------|----------------------------------------------------------|
| `findings`     | list[object]        | yes      | —              | Array of `Finding` dicts                                 |
| `iocs`         | list[object]        | yes      | —              | Array of `IOCVerdict` dicts                              |
| `hashes`       | list[string]/null   | no       | `null`         | Additional explicit SHA-256 hex values                   |
| `campaign_tag` | string              | no       | `"APTWATCHER"` | Non-empty; used as the rule-name prefix                  |

#### Response

```json
{"rules": [{"name": "...", "text": "rule ... { ... }", "source_iocs": ["..."], "meta": {"...": "..."}}]}
```

#### Error cases

| Trigger                                    | Response                                 |
|--------------------------------------------|------------------------------------------|
| Malformed findings / IOCs                  | `{"error": "invalid_input: <detail>"}`   |
| Bad hash / empty campaign tag              | `{"error": "rule_generation: <detail>"}` |

---

### 3.18 `generate_suricata_rules`

- **Tier:** 0 (Phase 3.8 analysis surface).
- **Purpose:** Synthesize Suricata rules from findings and network
  IOCs (`domain`, `url`, `ipv4`, `ipv6`). Other IOC types are skipped
  silently. SIDs are assigned sequentially starting at `sid_start`; the
  caller keeps that value inside the deployment's private-use SID
  block.

#### Request

| Field          | Type         | Required | Default        | Notes                                                           |
|----------------|--------------|----------|----------------|-----------------------------------------------------------------|
| `findings`     | list[object] | yes      | —              | Array of `Finding` dicts                                        |
| `iocs`         | list[object] | yes      | —              | Array of `IOCVerdict` dicts                                     |
| `sid_start`    | int          | no       | `3000000`      | Non-negative; callers stay inside a private-use SID range       |
| `campaign_tag` | string       | no       | `"APTWATCHER"` | Non-empty; embedded in each rule's `msg:` field                 |

#### Response

```json
{"rules": [{"sid": 3000000, "text": "alert ...", "source_iocs": ["..."], "meta": {"...": "..."}}]}
```

#### Error cases

| Trigger                                          | Response                                 |
|--------------------------------------------------|------------------------------------------|
| Malformed findings / IOCs                        | `{"error": "invalid_input: <detail>"}`   |
| Unsafe IOC value / bad sid_start / empty tag     | `{"error": "rule_generation: <detail>"}` |

---

### 3.19 `export_stix_bundle`

- **Tier:** 0 (Phase 3.8 analysis surface).
- **Purpose:** Emit a STIX 2.1 `bundle.json` containing an `identity`
  SDO for APTWatcher plus one `indicator` SDO per IOC. Object IDs are
  deterministic (UUIDv5 over `(ioc_type, value)`) so two runs with the
  same input produce byte-identical output. Returns the in-memory
  bundle dictionary.

#### Request

| Field         | Type                    | Required | Default                   | Notes                                                  |
|---------------|-------------------------|----------|---------------------------|--------------------------------------------------------|
| `iocs`        | list[object]            | yes      | —                         | Non-empty array of `IOCVerdict` dicts                  |
| `output_path` | string                  | yes      | —                         | Target file path; parents are created                  |
| `incident_id` | string                  | yes      | —                         | Seeds the deterministic bundle id                      |
| `findings`    | list[object]/null       | no       | `null`                    | Accepted for API symmetry; not currently embedded      |
| `created_by`  | string                  | no       | `"identity--aptwatcher"`  | STIX identity id; must start with `identity--`         |

#### Response

The in-memory STIX bundle `{"type": "bundle", "id": "...", "objects": [...]}`.

#### Error cases

| Trigger                                                            | Response                               |
|--------------------------------------------------------------------|----------------------------------------|
| Malformed findings / IOCs                                          | `{"error": "invalid_input: <detail>"}` |
| Empty IOC list / unsupported type / bad value / bad `created_by`   | `{"error": "ioc_export: <detail>"}`    |

---

### 3.20 `export_community_yaml`

- **Tier:** 0 (Phase 3.8 analysis surface).
- **Purpose:** Emit a community-feed-style YAML submission template
  with a `DO NOT EDIT` banner. Human reviewers hand-tune the document
  before submitting it to a public feed. Returns the in-memory
  document.

#### Request

| Field          | Type         | Required | Notes                                             |
|----------------|--------------|----------|---------------------------------------------------|
| `iocs`         | list[object] | yes      | Array of `IOCVerdict` dicts                       |
| `findings`     | list[object] | yes      | Array of `Finding` dicts                          |
| `output_path`  | string       | yes      | Target file path; parents are created             |
| `campaign_tag` | string       | yes      | Non-empty; top-level `campaign` field             |
| `submitter`    | string       | yes      | Non-empty; top-level `submitter` field            |

#### Response

The in-memory YAML document (as a dict): `{"submission": {...}, "indicators": [...], "findings": [...]}`.

#### Error cases

| Trigger                                                   | Response                               |
|-----------------------------------------------------------|----------------------------------------|
| Malformed findings / IOCs                                 | `{"error": "invalid_input: <detail>"}` |
| Missing `campaign_tag` / `submitter`, or empty inputs     | `{"error": "ioc_export: <detail>"}`    |

---

### 3.21 `export_per_type_txt`

- **Tier:** 0 (Phase 3.8 analysis surface).
- **Purpose:** Emit one `<type>.txt` file per IOC type under
  `output_dir`, with values normalized (lowercase for domains /
  emails / hashes), sorted, and deduplicated. Refuses to overwrite
  existing per-type files.

#### Request

| Field        | Type         | Required | Notes                                        |
|--------------|--------------|----------|----------------------------------------------|
| `iocs`       | list[object] | yes      | Non-empty array of `IOCVerdict` dicts        |
| `output_dir` | string       | yes      | Target directory; created if absent          |

#### Response

```json
{"written": {"domain": "/runs/s01/iocs/domain.txt", "sha256": "/runs/s01/iocs/sha256.txt"}}
```

Keys are IOC types present in the input; values are the written paths.

#### Error cases

| Trigger                                                       | Response                               |
|---------------------------------------------------------------|----------------------------------------|
| Malformed IOCs                                                | `{"error": "invalid_input: <detail>"}` |
| Empty IOC list / empty value / overwrite conflict             | `{"error": "ioc_export: <detail>"}`    |

---

### 3.22 `render_docx_report`

- **Tier:** 0 (Phase 3.8 analysis surface).
- **Purpose:** Render a professional bilingual (`en`/`fr`) campaign
  report as a `.docx` file. Severity bands are derived from
  `Finding.confidence`. Refuses to overwrite an existing
  `output_path`.

#### Request

| Field          | Type             | Required | Default | Notes                                          |
|----------------|------------------|----------|---------|------------------------------------------------|
| `findings`     | list[object]     | yes      | —       | Array of `Finding` dicts; may be empty         |
| `iocs`         | list[object]     | yes      | —       | Array of `IOCVerdict` dicts                    |
| `output_path`  | string           | yes      | —       | Target path; MUST NOT exist                    |
| `incident_id`  | string           | yes      | —       | Non-empty                                      |
| `campaign_tag` | string           | yes      | —       | Non-empty                                      |
| `language`     | string           | no       | `"en"`  | `"en"` or `"fr"`                               |
| `operator`     | string/null      | no       | `null`  | Optional operator identifier on the title page |

#### Response

```json
{"output_path": "/runs/s01/campaign.docx"}
```

#### Error cases

| Trigger                                                | Response                                |
|--------------------------------------------------------|-----------------------------------------|
| Malformed findings / IOCs                              | `{"error": "invalid_input: <detail>"}`  |
| Unsupported language / missing fields / refuse-clobber | `{"error": "report_render: <detail>"}`  |

---

### 3.23 `render_analyst_markdown`

- **Tier:** 0 (Phase 3.8 analysis surface).
- **Purpose:** Render the English-only analyst narrative document
  (`ANALYSIS-<incident_id>.md`). Emits H1 metadata, auto-generated
  executive summary, per-finding H3 blocks with citations, an IOC
  table, and a stub "Next steps" section. Refuses to overwrite an
  existing `output_path`.

#### Request

| Field          | Type          | Required | Default | Notes                                       |
|----------------|---------------|----------|---------|---------------------------------------------|
| `findings`     | list[object]  | yes      | —       | Array of `Finding` dicts                    |
| `iocs`         | list[object]  | yes      | —       | Array of `IOCVerdict` dicts                 |
| `output_path`  | string        | yes      | —       | Target path; MUST NOT exist                 |
| `incident_id`  | string        | yes      | —       | Non-empty                                   |
| `campaign_tag` | string        | yes      | —       | Non-empty                                   |
| `operator`     | string/null   | no       | `null`  | Shown in the metadata block                 |

#### Response

```json
{"output_path": "/runs/s01/ANALYSIS-S01.md"}
```

#### Error cases

| Trigger                                    | Response                                |
|--------------------------------------------|-----------------------------------------|
| Malformed findings / IOCs                  | `{"error": "invalid_input: <detail>"}`  |
| Missing fields / refuse-clobber            | `{"error": "report_render: <detail>"}`  |

---

### 3.24 `render_generation_report`

- **Tier:** 0 (Phase 3.8 analysis surface).
- **Purpose:** Write `generation_report.json` -- the per-run stats
  manifest carrying counts, the Suricata SID range, and relative-path
  sha256 digests for every emitted artifact. Refuses to overwrite an
  existing `output_path`.

#### Request

| Field          | Type                 | Required | Default | Notes                                                             |
|----------------|----------------------|----------|---------|-------------------------------------------------------------------|
| `output_path`  | string               | yes      | —       | Target file path; MUST NOT exist                                  |
| `incident_id`  | string               | yes      | —       | Non-empty                                                         |
| `campaign_tag` | string               | yes      | —       | Non-empty                                                         |
| `counts`       | object[string, int]  | yes      | —       | Non-negative per-artifact counts (e.g. `{"findings": 12}`)        |
| `file_digests` | object[string, str]  | yes      | —       | Relative-path -> `"sha256:<hex>"` map                             |
| `sid_range`    | list[int]/null       | no       | `null`  | `[start, end]` pair or `null` if no Suricata rules were emitted   |

#### Response

```json
{"output_path": "/runs/s01/generation_report.json"}
```

#### Error cases

| Trigger                                                    | Response                                |
|------------------------------------------------------------|-----------------------------------------|
| Malformed counts / digests / sid_range / refuse-clobber    | `{"error": "report_render: <detail>"}`  |

---

### 3.25 `list_regripper_plugins`

- **Tier:** 0
- **Purpose:** Return the Tier 0 allow-list of RegRipper plugins used
  for Windows registry hive triage. Plugins outside the list (large
  swaths of the upstream catalog) are not exposed at Tier 0.
- **SIFT tool wrapped:** none.

#### Request / Response

```json
{}
```

Returns `{"<plugin_name>": "<reason>"}`. The allow-list covers
system-hive triage (`compname`, `winver`, `timezone`), persistence
(`run`, `runonce`, `services`), user activity (`userassist`,
`muicache`, `shellbags`), execution evidence (`appcompatcache`,
`shimcache`, `amcache`), removable-media history (`usb`,
`mountpoints2`), and logging policy (`auditpol`).

---

### 3.26 `list_regripper_profiles`

- **Tier:** 0
- **Purpose:** Return the Tier 0 allow-list of RegRipper hive profiles
  -- the classic per-hive-family triage sweeps invoked via the `-f`
  flag.
- **SIFT tool wrapped:** none.

#### Request / Response

```json
{}
```

Returns `{"<profile_name>": "<reason>"}`. Keys are fixed to the
five canonical RegRipper profiles: `software`, `system`, `ntuser`,
`sam`, `security`.

---

### 3.27 `run_regripper_plugin`

- **Tier:** 0
- **Purpose:** Run a single allow-listed RegRipper plugin against an
  offline registry hive. Read-only on the hive; refuses to open a path
  that is missing or that points at a directory.
- **SIFT tool wrapped:** `rip.pl` (falls back to `rip` when the Perl
  script is not on PATH).

#### Request

```json
{
  "hive": "/evidence/host01/SYSTEM",
  "plugin": "services",
  "timeout": 300.0
}
```

| Field     | Type   | Required | Default | Notes                                         |
|-----------|--------|----------|---------|-----------------------------------------------|
| `hive`    | string | yes      | —       | Offline registry hive file; must be a file    |
| `plugin`  | string | yes      | —       | Must be a key in `REGRIPPER_PLUGINS`          |
| `timeout` | float  | no       | `300.0` | Seconds                                       |

#### Response

`ToolRunResult` dict on success. The captured `stdout` field carries
the RegRipper plugin report; the wrapper itself writes no files.

#### Error cases

| Trigger                                       | Response                                                 |
|-----------------------------------------------|----------------------------------------------------------|
| Tier 0 disabled                               | `{"error": "Tier 0 is disabled in the active config."}`  |
| Plugin not in allow-list                      | `{"error": "plugin_not_allowed: <detail>"}`              |
| Missing hive, hive is a directory, no binary  | `{"error": "runner_error: <detail>"}`                    |

---

### 3.28 `run_regripper_profile`

- **Tier:** 0
- **Purpose:** Run an allow-listed RegRipper hive profile against an
  offline registry hive. Read-only on the hive; refuses to open a path
  that is missing or that points at a directory.
- **SIFT tool wrapped:** `rip.pl` (falls back to `rip` when the Perl
  script is not on PATH).

#### Request

```json
{
  "hive": "/evidence/host01/SOFTWARE",
  "profile": "software",
  "timeout": 600.0
}
```

| Field     | Type   | Required | Default | Notes                                           |
|-----------|--------|----------|---------|-------------------------------------------------|
| `hive`    | string | yes      | —       | Offline registry hive file; must be a file      |
| `profile` | string | yes      | —       | Must be a key in `REGRIPPER_PROFILES`           |
| `timeout` | float  | no       | `600.0` | Seconds                                         |

#### Response

`ToolRunResult` dict on success. The captured `stdout` field carries
the RegRipper profile report; the wrapper itself writes no files.

#### Error cases

| Trigger                                       | Response                                                 |
|-----------------------------------------------|----------------------------------------------------------|
| Tier 0 disabled                               | `{"error": "Tier 0 is disabled in the active config."}`  |
| Profile not in allow-list                     | `{"error": "profile_not_allowed: <detail>"}`             |
| Missing hive, hive is a directory, no binary  | `{"error": "runner_error: <detail>"}`                    |

---

### 3.29 `list_chainsaw_output_formats`

- **Tier:** 0
- **Purpose:** Return the allow-list of Chainsaw output formats and
  their short descriptions. Used by planners that need to choose
  between machine-readable `json` and analyst-facing `csv`.
- **SIFT tool wrapped:** none (metadata only).

#### Request / Response

```json
{}
```

Returns `{"<format>": "<reason>"}`:

```json
{
  "json": "Machine-readable JSON array. Default for agent consumption.",
  "csv": "CSV for analyst review."
}
```

---

### 3.30 `run_chainsaw_hunt`

- **Tier:** 0
- **Purpose:** Run Chainsaw's `hunt` subcommand against an EVTX source
  with a Sigma rules directory and a field-mapping YAML. Complements
  Hayabusa (same evidence, independently maintained ruleset).
- **SIFT tool wrapped:** `chainsaw hunt` (WithSecure Labs).
- **Evidence:** read-only. The wrapper emits
  `evidence_readonly_assumed=true` in the audit payload.

#### Request

| Field              | Type    | Required | Default  | Notes                                                                 |
|--------------------|---------|----------|----------|-----------------------------------------------------------------------|
| `evtx_source`      | string  | yes      | —        | Existing `.evtx` file OR directory of `.evtx` files                   |
| `sigma_rules_dir`  | string  | yes      | —        | Existing directory containing Sigma rules                             |
| `mapping`          | string  | yes      | —        | Existing Chainsaw field-mapping YAML file                             |
| `output_path`      | string  | yes      | —        | Must NOT be a non-empty file / non-empty directory                    |
| `output_format`    | string  | no       | `"json"` | One of `CHAINSAW_OUTPUT_FORMATS` (`json`, `csv`)                      |
| `timeout`          | number  | no       | `3600.0` | Seconds                                                               |

#### Response

`ToolRunResult` (see section 2.3) serialised with `model_dump(mode="json")`.

#### Error cases

| Trigger                                                    | Response                                   |
|------------------------------------------------------------|--------------------------------------------|
| Tier 0 disabled                                            | `{"error": "Tier 0 is disabled in the active config."}` |
| Unsupported `output_format`                                | `{"error": "chainsaw_policy: <detail>"}`   |
| Missing `evtx_source` / `sigma_rules_dir` / `mapping`      | `{"error": "runner_error: <detail>"}`     |
| `output_path` is a populated file or non-empty directory   | `{"error": "runner_error: <detail>"}`     |
| Binary not on PATH                                         | `{"error": "runner_error: <detail>"}`     |

---

### 3.31 `run_chainsaw_search`

- **Tier:** 0
- **Purpose:** Run Chainsaw's `search` subcommand for a full-text
  pivot over EVTX records. Useful for surfacing suspected IOCs
  (hostnames, tool names, process names) across a large EVTX corpus.
- **SIFT tool wrapped:** `chainsaw search` (WithSecure Labs).
- **Evidence:** read-only. The wrapper emits
  `evidence_readonly_assumed=true` in the audit payload.

#### Request

| Field           | Type    | Required | Default  | Notes                                                                 |
|-----------------|---------|----------|----------|-----------------------------------------------------------------------|
| `evtx_source`   | string  | yes      | —        | Existing `.evtx` file OR directory of `.evtx` files                   |
| `search_term`   | string  | yes      | —        | Non-empty; matches safe set `[A-Za-z0-9_\-.\s]+`                      |
| `output_path`   | string  | yes      | —        | Must NOT be a non-empty file / non-empty directory                    |
| `output_format` | string  | no       | `"json"` | One of `CHAINSAW_OUTPUT_FORMATS` (`json`, `csv`)                      |
| `timeout`       | number  | no       | `1800.0` | Seconds                                                               |

#### Response

`ToolRunResult` (see section 2.3).

#### Error cases

| Trigger                                                    | Response                                   |
|------------------------------------------------------------|--------------------------------------------|
| Tier 0 disabled                                            | `{"error": "Tier 0 is disabled in the active config."}` |
| Empty / whitespace / unsafe `search_term`                  | `{"error": "chainsaw_search: <detail>"}`  |
| Unsupported `output_format`                                | `{"error": "chainsaw_policy: <detail>"}`   |
| Missing `evtx_source`                                      | `{"error": "runner_error: <detail>"}`     |
| `output_path` is a populated file or non-empty directory   | `{"error": "runner_error: <detail>"}`     |
| Binary not on PATH                                         | `{"error": "runner_error: <detail>"}`     |

---

### 3.32 `list_timesketch_query_subcommands`

- **Tier:** 0
- **Purpose:** Return the allow-list of read-only Timesketch CLI query
  subcommands with short reasons. Inventory-only; does not touch a
  server.
- **SIFT tool wrapped:** none (metadata only).

#### Request / Response

```json
{}
```

Returns `{"<subcommand>": "<reason>"}`:

```json
{
  "list": "List sketches accessible to the authenticated user. Read-only.",
  "describe": "Describe a sketch's metadata and timelines. Read-only.",
  "search": "Run a Lucene query over a sketch's events. Read-only."
}
```

---

### 3.33 `run_timesketch_query`

- **Tier:** 0
- **Purpose:** Run a read-only Timesketch CLI subcommand against a
  Timesketch server -- list sketches, describe a sketch, or execute
  a Lucene query. No local evidence is touched; the server side is
  strictly read.
- **SIFT tool wrapped:** `timesketch` (Google Timesketch CLI).
- **Evidence:** read-only. The wrapper emits
  `evidence_readonly_assumed=true` in the audit payload for parity
  with the other Tier 0 wrappers.

#### Request

| Field         | Type           | Required                      | Default | Notes                                                                                   |
|---------------|----------------|-------------------------------|---------|-----------------------------------------------------------------------------------------|
| `subcommand`  | string         | yes                           | —       | One of `TIMESKETCH_QUERY_SUBCOMMANDS` (`list`, `describe`, `search`)                    |
| `host`        | string         | yes                           | —       | `http://` or `https://` URL; URL-safe characters only                                   |
| `sketch_id`   | int            | `describe` + `search` only    | `null`  | Positive integer                                                                        |
| `query`       | string         | `search` only                 | `null`  | Non-empty; safe set `[A-Za-z0-9_-\.\s:/()"'\\*[]{}]+` (Lucene operators allowed)        |
| `timeout`     | number         | no                            | `300.0` | Seconds                                                                                 |

#### Response

`ToolRunResult` (see section 2.3) serialised with `model_dump(mode="json")`.

#### Error cases

| Trigger                                                    | Response                                   |
|------------------------------------------------------------|--------------------------------------------|
| Tier 0 disabled                                            | `{"error": "Tier 0 is disabled in the active config."}` |
| Unsupported `subcommand`                                   | `{"error": "timesketch_policy: <detail>"}` |
| Invalid `host` (wrong scheme or shell metachars)           | `{"error": "timesketch_host: <detail>"}`   |
| Empty / unsafe `query`, missing `sketch_id`, etc.          | `{"error": "timesketch_query: <detail>"}`  |
| Binary not on PATH                                         | `{"error": "runner_error: <detail>"}`      |

---

### 3.34 `run_timesketch_upload`

- **Tier:** 0 (consent-gated layered on top)
- **Purpose:** Upload a local timeline (plaso `.plaso` storage file
  or CSV) to a Timesketch server, creating/appending a timeline in
  the target sketch. The local evidence file is read-only, but the
  overall operation is **state-changing-operational**: it mutates the
  Timesketch server's database. The wrapper emits a
  `timesketch_upload_consent` audit event BEFORE the subprocess runs
  (parallel to `sift_update`'s consent-event pattern), and the audit
  payload records `source_readonly_assumed=true` alongside
  `state_changing="operational"` so reviewers can see the
  distinction.
- **SIFT tool wrapped:** `timesketch_importer` (Google Timesketch).

#### Request

```json
{
  "timeline_source": "/cases/incident-42/plaso/host01.plaso",
  "sketch_id": 7,
  "timeline_name": "host01-plaso-2026-04-20",
  "consent_token": "i-consent-timesketch-upload",
  "host": "https://timesketch.lab.example/",
  "timeout": 3600.0
}
```

| Field             | Type         | Required | Default  | Notes                                                        |
|-------------------|--------------|----------|----------|--------------------------------------------------------------|
| `timeline_source` | string       | yes      | —        | Existing regular file (plaso storage or CSV)                 |
| `sketch_id`       | int          | yes      | —        | Positive integer                                             |
| `timeline_name`   | string       | yes      | —        | Non-empty; safe set `[A-Za-z0-9_-. ]+`                       |
| `consent_token`   | string       | yes      | —        | Must equal `"i-consent-timesketch-upload"`; never logged raw |
| `host`            | string/null  | no       | `null`   | `http://` / `https://` URL; null falls back to env vars      |
| `timeout`         | number       | no       | `3600.0` | Seconds                                                      |

Consent enforcement lives in
`core.sift.timesketch.run_timesketch_upload`, which emits a
`timesketch_upload_consent` audit event **before** the
`timesketch_importer` subprocess is spawned. The event records
`consent_token_present`, `consent_token_length`, `sketch_id`,
`timeline_name`, `host`, and `source` — never the raw token value.

#### Response

`ToolRunResult` dict on success.

#### Error cases

| Trigger                                                    | Response                                                 |
|------------------------------------------------------------|----------------------------------------------------------|
| Tier 0 disabled                                            | `{"error": "Tier 0 is disabled in the active config."}`  |
| Missing / wrong `consent_token`                            | `{"error": "consent_required: <detail>"}`                |
| Invalid `timeline_name`                                    | `{"error": "timesketch_timeline_name: <detail>"}`        |
| Non-positive `sketch_id`                                   | `{"error": "timesketch_query: <detail>"}`                |
| Invalid `host`                                             | `{"error": "timesketch_host: <detail>"}`                 |
| Source missing or not a regular file / binary missing       | `{"error": "runner_error: <detail>"}`                    |

---

### 3.35 `run_mmls`

- **Tier:** 0
- **Purpose:** List partitions in a disk image using sleuthkit's
  `mmls`. Returns the partition table with block offsets. Read-only on
  the image.
- **SIFT tool wrapped:** `mmls` (Sleuth Kit).

#### Request

```json
{"image": "/cases/incident-42/disk.raw", "timeout": 300.0}
```

| Field     | Type   | Required | Default | Notes                        |
|-----------|--------|----------|---------|------------------------------|
| `image`   | string | yes      | —       | Existing regular file        |
| `timeout` | number | no       | `300.0` | Seconds                      |

#### Response

`ToolRunResult` dict on success.

#### Error cases

| Trigger                    | Response                                                 |
|----------------------------|----------------------------------------------------------|
| Tier 0 disabled            | `{"error": "Tier 0 is disabled in the active config."}`  |
| Image missing / not a file | `{"error": "runner_error: <detail>"}`                    |

---

### 3.36 `run_fsstat`

- **Tier:** 0
- **Purpose:** Report filesystem metadata (type, block size, fs
  creation time, mount info) using sleuthkit's `fsstat`. Read-only on
  the image.
- **SIFT tool wrapped:** `fsstat` (Sleuth Kit).

#### Request

```json
{"image": "/cases/incident-42/disk.raw", "offset": 2048, "timeout": 300.0}
```

| Field     | Type        | Required | Default | Notes                        |
|-----------|-------------|----------|---------|------------------------------|
| `image`   | string      | yes      | —       | Existing regular file        |
| `offset`  | int / null  | no       | `null`  | Partition byte offset        |
| `timeout` | number      | no       | `300.0` | Seconds                      |

#### Response

`ToolRunResult` dict on success.

#### Error cases

| Trigger                    | Response                                                 |
|----------------------------|----------------------------------------------------------|
| Tier 0 disabled            | `{"error": "Tier 0 is disabled in the active config."}`  |
| Image missing / not a file | `{"error": "runner_error: <detail>"}`                    |

---

### 3.37 `run_fls`

- **Tier:** 0
- **Purpose:** List files from a filesystem image using sleuthkit's
  `fls`. Supports optional partition offset, recursive walk, and a
  starting inode. Read-only on the image.
- **SIFT tool wrapped:** `fls` (Sleuth Kit).

#### Request

```json
{
  "image": "/cases/incident-42/disk.raw",
  "offset": 2048,
  "inode": "5",
  "recursive": true,
  "timeout": 600.0
}
```

| Field       | Type        | Required | Default | Notes                                 |
|-------------|-------------|----------|---------|---------------------------------------|
| `image`     | string      | yes      | —       | Existing regular file                 |
| `offset`    | int / null  | no       | `null`  | Partition byte offset                 |
| `inode`     | string/null | no       | `null`  | Starting inode (tsk syntax)           |
| `recursive` | bool        | no       | `false` | Recursive walk                        |
| `timeout`   | number      | no       | `600.0` | Seconds                               |

#### Response

`ToolRunResult` dict on success.

#### Error cases

| Trigger                    | Response                                                 |
|----------------------------|----------------------------------------------------------|
| Tier 0 disabled            | `{"error": "Tier 0 is disabled in the active config."}`  |
| Image missing / not a file | `{"error": "runner_error: <detail>"}`                    |

---

### 3.38 `run_icat`

- **Tier:** 0
- **Purpose:** Extract a file by inode from a filesystem image using
  sleuthkit's `icat`. Read-only on the image. Refuses to overwrite an
  existing `output_path`.
- **SIFT tool wrapped:** `icat` (Sleuth Kit).

#### Request

```json
{
  "image": "/cases/incident-42/disk.raw",
  "inode": "12345",
  "output_path": "/cases/incident-42/extracted/hosts",
  "offset": 2048,
  "timeout": 300.0
}
```

| Field         | Type        | Required | Default | Notes                                           |
|---------------|-------------|----------|---------|-------------------------------------------------|
| `image`       | string      | yes      | —       | Existing regular file                           |
| `inode`       | string      | yes      | —       | Inode (tsk syntax)                              |
| `output_path` | string      | yes      | —       | Target path; must not exist                     |
| `offset`      | int / null  | no       | `null`  | Partition byte offset                           |
| `timeout`     | number      | no       | `300.0` | Seconds                                         |

#### Response

`ToolRunResult` dict on success.

#### Error cases

| Trigger                         | Response                                                 |
|---------------------------------|----------------------------------------------------------|
| Tier 0 disabled                 | `{"error": "Tier 0 is disabled in the active config."}`  |
| Output path already exists      | `{"error": "runner_error: <detail>"}`                    |
| Image missing / not a file      | `{"error": "runner_error: <detail>"}`                    |

---

### 3.39 `run_yara_scan`

- **Tier:** 0
- **Purpose:** Scan a file or directory against a YARA ruleset.
  Read-only on the target. `print_strings=False` by default to keep
  audit payloads small.
- **SIFT tool wrapped:** `yara` CLI.

#### Request

```json
{
  "rules_path": "/opt/yara-rules/combined.yar",
  "target": "/cases/incident-42/samples/",
  "recursive": true,
  "print_meta": true,
  "print_tags": true,
  "print_strings": false,
  "timeout_per_rule": 10,
  "fast_mode": true,
  "timeout": 1800.0
}
```

| Field              | Type        | Required | Default  | Notes                                      |
|--------------------|-------------|----------|----------|--------------------------------------------|
| `rules_path`       | string      | yes      | —        | Existing `.yar` / `.yara` file             |
| `target`           | string      | yes      | —        | Existing file or directory                 |
| `recursive`        | bool        | no       | `false`  | Recurse into subdirectories                |
| `print_meta`       | bool        | no       | `true`   | Include YARA rule metadata                 |
| `print_tags`       | bool        | no       | `true`   | Include YARA rule tags                     |
| `print_strings`    | bool        | no       | `false`  | Include matching strings                   |
| `timeout_per_rule` | int / null  | no       | `null`   | Per-rule timeout passed to `yara`          |
| `fast_mode`        | bool        | no       | `true`   | Enable `-f` fast mode                      |
| `timeout`          | number      | no       | `1800.0` | Seconds                                    |

#### Response

`ToolRunResult` dict on success.

#### Error cases

| Trigger                         | Response                                                 |
|---------------------------------|----------------------------------------------------------|
| Tier 0 disabled                 | `{"error": "Tier 0 is disabled in the active config."}`  |
| Policy violation (rules/target) | `{"error": "yara_policy: <detail>"}`                     |
| Runner failure                  | `{"error": "runner_error: <detail>"}`                    |

---

### 3.40 `list_hayabusa_output_formats`

- **Tier:** 0 (inventory, not tier-gated)
- **Purpose:** Return the allow-list of Hayabusa timeline output
  formats (`csv` / `json`) and their subcommands.

#### Request

No parameters.

#### Response

Dict mapping format name to short description.

---

### 3.41 `run_hayabusa_timeline`

- **Tier:** 0
- **Purpose:** Produce a Sigma-driven timeline of Windows EVTX events
  via Hayabusa. Read-only on the evtx source. `min_level` filters by
  severity.
- **SIFT tool wrapped:** `hayabusa`.

#### Request

```json
{
  "evtx_source": "/cases/incident-42/evtx/",
  "output_path": "/cases/incident-42/hayabusa/timeline.csv",
  "output_format": "csv",
  "min_level": "medium",
  "profile": null,
  "quiet": true,
  "timeout": 3600.0
}
```

| Field           | Type        | Required | Default  | Notes                                            |
|-----------------|-------------|----------|----------|--------------------------------------------------|
| `evtx_source`   | string      | yes      | —        | Existing evtx file or directory                  |
| `output_path`   | string      | yes      | —        | Target path                                      |
| `output_format` | string      | no       | `"csv"`  | `"csv"` or `"json"` (allow-listed)               |
| `min_level`     | string      | no       | `"medium"` | `informational\|low\|medium\|high\|critical` |
| `profile`       | string/null | no       | `null`   | Hayabusa profile name                            |
| `quiet`         | bool        | no       | `true`   | Suppress banner                                  |
| `timeout`       | number      | no       | `3600.0` | Seconds                                          |

#### Response

`ToolRunResult` dict on success.

#### Error cases

| Trigger                  | Response                                                 |
|--------------------------|----------------------------------------------------------|
| Tier 0 disabled          | `{"error": "Tier 0 is disabled in the active config."}`  |
| Output format not allowed| `{"error": "hayabusa_policy: <detail>"}`                 |
| Runner failure           | `{"error": "runner_error: <detail>"}`                    |

---

### 3.42 `run_hayabusa_logon_summary`

- **Tier:** 0
- **Purpose:** Summarise logon events from Windows EVTX using
  Hayabusa's `logon-summary` subcommand. Read-only on the evtx source.
- **SIFT tool wrapped:** `hayabusa logon-summary`.

#### Request

```json
{
  "evtx_source": "/cases/incident-42/evtx/",
  "output_path": "/cases/incident-42/hayabusa/logons.csv",
  "timeout": 1800.0
}
```

| Field         | Type        | Required | Default  | Notes                                |
|---------------|-------------|----------|----------|--------------------------------------|
| `evtx_source` | string      | yes      | —        | Existing evtx file or directory      |
| `output_path` | string/null | no       | `null`   | Target file for CSV output           |
| `timeout`     | number      | no       | `1800.0` | Seconds                              |

#### Response

`ToolRunResult` dict on success.

#### Error cases

| Trigger          | Response                                                 |
|------------------|----------------------------------------------------------|
| Tier 0 disabled  | `{"error": "Tier 0 is disabled in the active config."}`  |
| Runner failure   | `{"error": "runner_error: <detail>"}`                    |

---

### 3.43 `intel_lookup`

- **Tier:** 1 (network-touching, read-only lookup).
- **Purpose:** Look up one IOC across the configured external
  threat-intel providers and return an aggregated `IOCVerdict`.
  Opt-in — refuses when Tier 1 is off.
- **SIFT tool wrapped:** none (HTTP via `core.intel` providers).

#### Request

```json
{
  "value": "203.0.113.7",
  "ioc_type": "ipv4"
}
```

| Field      | Type   | Required | Notes                                                                        |
|------------|--------|----------|------------------------------------------------------------------------------|
| `value`    | string | yes      | The indicator value                                                          |
| `ioc_type` | string | yes      | One of `ipv4`, `ipv6`, `domain`, `url`, `sha256`, `sha1`, `md5`, `email`     |

#### Response

An `IOCVerdict` dict (`core.types.IOCVerdict`):

```json
{
  "value": "203.0.113.7",
  "ioc_type": "ipv4",
  "verdict": "malicious",
  "confidence": 0.92,
  "first_seen": null,
  "last_seen": null,
  "sources": [
    {"name": "dshield", "verdict": "malicious", "score": 0.92, "raw": {}}
  ],
  "attributions": [],
  "notes": null
}
```

- `verdict` is one of `malicious`, `suspicious`, `benign`, `unknown`.
  Precedence: any `malicious` wins, then `suspicious`; ties break on the
  highest score (`core.intel.aggregator`).
- `confidence` is the max score among providers matching the winning
  verdict; `null` if no provider scored.
- `sources` preserves each provider's `IOCProviderResult` in
  registration order so the caller can reason about disagreement.

#### Key-degraded behaviour

`build_aggregator` (in `core.intel.providers`) registers a provider
only when its config section is `enabled` — and, for the keyed
providers (VirusTotal, AbuseIPDB, OTX, Censys), only when the env var
named by `api_key_env` is actually set. Missing keys silently shrink
the roster; with zero active providers every lookup returns
`verdict: "unknown"` with empty `sources`. `unknown` is a legitimate
terminal state, never an error. Per-provider failures (timeouts, HTTP
errors) count as abstention and are swallowed, not surfaced.

#### Error cases

| Trigger                | Response                                                              |
|------------------------|-----------------------------------------------------------------------|
| Tier 1 disabled        | `{"error": "Tier 1 is disabled in the active config."}`               |
| `ioc_type` not allowed | `{"error": "invalid ioc_type: '<value>'; expected one of [...]"}`     |

---

### 3.44 `enrich_ip`

- **Tier:** 1 (network-touching, read-only lookup).
- **Purpose:** Aggregate every configured provider's verdict for one IP
  address. Convenience wrapper over the same aggregator as
  `intel_lookup`; the IOC type is inferred (`ipv6` when the value
  contains `:`, else `ipv4`).
- **SIFT tool wrapped:** none.

#### Request

```json
{"value": "203.0.113.7"}
```

| Field   | Type   | Required | Notes                                  |
|---------|--------|----------|----------------------------------------|
| `value` | string | yes      | IPv4 or IPv6 address (auto-detected)   |

#### Response

An `IOCVerdict` dict (shape in section 3.43). Same key-degraded
behaviour: no enabled/keyed providers means `verdict: "unknown"`.

#### Error cases

| Trigger         | Response                                                 |
|-----------------|----------------------------------------------------------|
| Tier 1 disabled | `{"error": "Tier 1 is disabled in the active config."}`  |

---

### 3.45 `enrich_domain`

- **Tier:** 1 (network-touching, read-only lookup).
- **Purpose:** Aggregate every configured provider's verdict for one
  domain (`ioc_type` fixed to `domain`).
- **SIFT tool wrapped:** none.

#### Request

```json
{"value": "evil.example.net"}
```

| Field   | Type   | Required | Notes        |
|---------|--------|----------|--------------|
| `value` | string | yes      | Domain name  |

#### Response

An `IOCVerdict` dict (shape in section 3.43). Same key-degraded
behaviour as `intel_lookup`.

#### Error cases

| Trigger         | Response                                                 |
|-----------------|----------------------------------------------------------|
| Tier 1 disabled | `{"error": "Tier 1 is disabled in the active config."}`  |

---

### 3.46 `enrich_hash`

- **Tier:** 1 (network-touching, read-only lookup).
- **Purpose:** Aggregate provider verdicts for one file hash. The hash
  kind is inferred from the stripped value's length: 32 hex chars is
  `md5`, 40 is `sha1`, 64 is `sha256`. The value is lower-cased before
  lookup.
- **SIFT tool wrapped:** none.

#### Request

```json
{"value": "d41d8cd98f00b204e9800998ecf8427e"}
```

| Field   | Type   | Required | Notes                                     |
|---------|--------|----------|-------------------------------------------|
| `value` | string | yes      | md5, sha1, or sha256 hex digest           |

#### Response

An `IOCVerdict` dict (shape in section 3.43). Same key-degraded
behaviour as `intel_lookup` — and note that the hash-capable providers
are predominantly keyed (VirusTotal, OTX), so hash enrichment without
API keys usually yields `unknown`.

#### Error cases

| Trigger                  | Response                                                            |
|--------------------------|----------------------------------------------------------------------|
| Tier 1 disabled          | `{"error": "Tier 1 is disabled in the active config."}`             |
| Length not 32/40/64      | `{"error": "unrecognized hash length; expected md5/sha1/sha256"}`   |

---

### 3.47 `feed_threatfox`

- **Tier:** 1 (network-touching, read-only feed search).
- **Purpose:** Search abuse.ch ThreatFox (`search_ioc` API) for an IOC
  — IP, domain, URL, or hash. A *search* verb, not a per-IOC verdict
  provider: it returns matching feed entries, outside the aggregator
  model (`core.intel.feeds.search_threatfox`).
- **SIFT tool wrapped:** none.

#### Request

```json
{"query": "203.0.113.7"}
```

| Field   | Type   | Required | Notes                          |
|---------|--------|----------|--------------------------------|
| `query` | string | yes      | IOC search term for ThreatFox  |

#### Response

```json
{
  "provider": "threatfox",
  "query": "203.0.113.7",
  "matched": true,
  "ioc_count": 2,
  "iocs": [{"...": "raw ThreatFox match objects"}]
}
```

#### Key-degraded behaviour

The API key is optional. The tool reads the env var named by
`cfg.intel.threatfox.api_key_env` (default `ABUSECH_API_KEY`) and, when
set, sends it as the `Auth-Key` header. Without a key the search still
runs against the public endpoint, subject to abuse.ch's anonymous
limits.

#### Error cases

| Trigger              | Response                                                                  |
|----------------------|----------------------------------------------------------------------------|
| Tier 1 disabled      | `{"error": "Tier 1 is disabled in the active config."}`                   |
| Network / parse fail | `{"provider": "threatfox", "query": "<query>", "error": "<detail>"}`      |

Note the network-failure shape carries `provider` and `query` next to
`error` — it is the one place the single-key error envelope rule of
section 1 is relaxed. Callers should still key off the presence of
`error`.

---

### 3.48 `feed_tweetfeed`

- **Tier:** 1 (network-touching, read-only feed search).
- **Purpose:** Fetch today's TweetFeed indicators
  (`api.tweetfeed.live/v1/today`), optionally filtered by exact value
  and/or tag (`core.intel.feeds.search_tweetfeed`). No API key exists
  for this feed.
- **SIFT tool wrapped:** none.

#### Request

```json
{"value": null, "tag": "phishing"}
```

| Field   | Type        | Required | Default | Notes                                        |
|---------|-------------|----------|---------|----------------------------------------------|
| `value` | string/null | no       | `null`  | Exact-match filter on the entry's `value`    |
| `tag`   | string/null | no       | `null`  | Keep entries whose `tags` list contains it   |

With neither filter, all of today's entries are returned.

#### Response

```json
{
  "provider": "tweetfeed",
  "count": 14,
  "entries": [{"...": "raw TweetFeed entry objects"}]
}
```

#### Error cases

| Trigger              | Response                                                 |
|----------------------|----------------------------------------------------------|
| Tier 1 disabled      | `{"error": "Tier 1 is disabled in the active config."}`  |
| Network / parse fail | `{"provider": "tweetfeed", "error": "<detail>"}`         |

---

### 3.49 `admin_version`

- **Tier:** server metadata (no tier gate; never touches the network).
- **Purpose:** Return the APTWatcher version plus the static Tier 1
  provider and feed roster. Unlike `admin_providers_status`, the roster
  here is hardcoded — it lists what the build *knows about*, not what
  is currently enabled or keyed.
- **SIFT tool wrapped:** none.

#### Request

```json
{}
```

#### Response

```json
{
  "aptwatcher": "0.1.0a0",
  "intel_providers": [
    "apt_watch", "dshield", "shodan_internetdb", "firehol", "ipsum",
    "stevenblack", "virustotal", "abuseipdb", "otx", "censys"
  ],
  "feeds": ["threatfox", "tweetfeed"]
}
```

#### Error cases

None. Callable even when Tier 1 is off.

---

### 3.50 `admin_health`

- **Tier:** server metadata (no tier gate; never touches the network).
- **Purpose:** MCP-side readiness probe: reports the Tier 1 flag and
  the count of providers that would actually be active right now. It
  builds (and immediately closes) a real aggregator, so the count
  honours both the `enabled` flags and the presence of API-key env
  vars.
- **SIFT tool wrapped:** none.

#### Request

```json
{}
```

#### Response

```json
{
  "status": "ok",
  "tier_1": true,
  "active_providers": 6
}
```

- `status` is `"ok"` when Tier 1 is on, `"tier_1_disabled"` otherwise.
- When Tier 1 is off, `build_aggregator` returns an empty aggregator,
  so `active_providers` is `0`.

#### Error cases

None — Tier 1 off is reported in `status`, not as an `error` envelope.

---

### 3.51 `admin_providers_status`

- **Tier:** server metadata (no tier gate; never touches the network).
- **Purpose:** Per-provider enabled/keyed/key-present status. Keyless
  providers report `enabled` + `keyed: false`; keyed providers
  additionally report whether their API-key env var is set
  (`key_present`) and the derived `active` bit
  (`enabled AND key_present`). Env var *names* only — key values are
  never read into the response.
- **SIFT tool wrapped:** none.

#### Request

```json
{}
```

#### Response

```json
{
  "tier_1": true,
  "providers": {
    "dshield": {"enabled": true, "keyed": false},
    "virustotal": {"enabled": true, "keyed": true, "key_present": false, "active": false}
  }
}
```

Keyless entries: `apt_watch`, `dshield`, `shodan_internetdb`,
`firehol`, `ipsum`, `stevenblack`. Keyed entries: `virustotal`
(`VIRUSTOTAL_API_KEY`), `abuseipdb` (`ABUSEIPDB_API_KEY`), `otx`
(`OTX_API_KEY`), `censys` (`CENSYS_API_TOKEN`) — each overridable via
the section's `api_key_env`.

#### Error cases

None. Callable even when Tier 1 is off.

---

## 4. Unregistered placeholders (Tier 1 remainder, Tier 2-4)

**The Tier 1 intel lookup family is no longer a placeholder.** Nine
Tier 1 tools are registered on the MCP wire and documented in sections
3.43-3.51: `intel_lookup`, `enrich_ip`, `enrich_domain`, `enrich_hash`,
`feed_threatfox`, `feed_tweetfeed`, `admin_version`, `admin_health`,
`admin_providers_status`. The earlier `check_ioc` planning name is
superseded by `intel_lookup` (same `core/intel/` aggregator underneath).

The tools below remain **planned** and referenced in `ARCHITECTURE.md`
/ `tier-gating.md` but are **not** registered on the MCP wire at the
time of writing. Where a shared-brain module exists in `src/core/`,
nothing calls `@mcp.tool` on it yet. Enabling the corresponding tier
flag in config will **not** make them appear.

| Tool                              | Tier | Status                                                                 |
|-----------------------------------|------|------------------------------------------------------------------------|
| `extract_iocs`                    | 1    | Planned; no code. Not registered.                                      |
| `correlate_host_against_intel`    | 1    | Planned; no code. Not registered.                                      |
| `glpi_resolve_ticket`             | 2    | GLPI MCP subprocess resolver exists in `core/integrations/glpi.py`; no tool. |
| `glpi_write_followup`             | 2    | Planned; no code. Not registered.                                      |
| `containment_kill_process`        | 3    | cnc_disruptor scaffold; `--enable-containment` flag not parsed.        |
| `containment_reset_tcp`           | 3    | Planned; no code. Not registered.                                      |
| `offensive_disrupt_c2`            | 4    | cnc_disruptor scaffold; `--enable-offensive` flag not parsed.          |

Note on naming: `sift_update` appears in some planning docs under
"Tier 1+" language; it is in fact registered and lives at Tier 0 with
an additional consent gate. See section 3.13.

---

## 5. Audit correlation

Every tool that invokes a SIFT binary (`run_volatility`,
`run_log2timeline`, `run_psort`, `run_bulk_extractor`, `sift_update`)
emits a **paired** `tool_call` audit event through
`core.sift.runner.run_tool`. Both events share the same
`correlation_id` — a 32-char hex UUID generated inside `run_tool`.

### Start event

```json
{
  "event_type": "tool_call",
  "correlation_id": "7a1f3c9e2b6d4a08a3d2e4f590c11a77",
  "timestamp": "2026-04-19T15:28:41.512034+00:00",
  "payload": {"phase": "start", "tool": "volatility3", "argv": [...], "cwd": null}
}
```

### End event

```json
{
  "event_type": "tool_call",
  "correlation_id": "7a1f3c9e2b6d4a08a3d2e4f590c11a77",
  "timestamp": "2026-04-19T15:28:53.925112+00:00",
  "payload": {"phase": "end", "tool": "volatility3", "returncode": 0, "duration_seconds": 12.413, "timed_out": false}
}
```

(`incident_id` envelope field omitted for brevity; always present.)

The `correlation_id` field on the returned `ToolRunResult` is the same
value — clients can record it alongside any `Finding.evidence.tool_call_id`
that cites this invocation, closing the loop between report and log.

### Consent-event pairing (sift_update and run_timesketch_upload)

Two Tier 0 tools write a dedicated consent event **before** the
`phase=start` `tool_call`:

* `sift_update` -> `sift_update_consent`
* `run_timesketch_upload` -> `timesketch_upload_consent`

In both cases the consent event is followed by the standard
`tool_call` start/end pair, so a single `jq` filter can pull the full
consent-to-completion story when the consent event and the start
event share the same `correlation_id`:

```bash
jq 'select(.correlation_id == "7a1f3c9e2b6d4a08a3d2e4f590c11a77")' audit.jsonl
```

The consent events never contain the raw `consent_token`; only
`consent_token_present: true` and `consent_token_length: <int>` plus
operation-specific metadata (`packages` / `dry_run` for
`sift_update_consent`; `sketch_id` / `timeline_name` / `host` /
`source` for `timesketch_upload_consent`).

### Non-SIFT tools

`preflight`, `list_profiles`, `knowledge_search`, `knowledge_get`, and
the various `list_*` inventory tools do **not** emit `tool_call`
pairs. `preflight` has its own dedicated `preflight` audit event
(recorded by the agent loop, not the MCP wrapper). Inventory tools are
pure reads of in-process constants.

The nine Tier 1 intel tools (sections 3.43-3.51) do **not** emit
`tool_call` pairs either. They never go through
`core.sift.runner.run_tool` — `intel_lookup` and the `enrich_*` tools
call the `core.intel` aggregator directly, the `feed_*` tools call
`core.intel.feeds`, and nothing in `core/intel/` writes audit events
today. Their responses carry no `correlation_id`, and provider-side
failures are swallowed as abstention rather than logged. Outbound
HTTP from these tools is therefore **unaudited at the MCP layer**;
operators who need an evidentiary record of intel lookups must capture
it in the agent loop. This is a known gap, not a documented guarantee.

### Cross-reference

- Audit envelope and full event catalog: [`../design/audit-log-format.md`](../design/audit-log-format.md)
- Rationale for append-only JSONL: [`../architecture/audit-logging.md`](../architecture/audit-logging.md)
- Correlation-ID allocation: `core.sift.runner.run_tool` (see
  `uuid.uuid4().hex` at the top of the function).

---

## 6. Source map

| Artifact                                       | Source of truth                                        |
|------------------------------------------------|--------------------------------------------------------|
| Tool registrations (`@mcp.tool`)               | `src/mcp_server/server.py`                             |
| `ToolRunResult` shape                          | `src/core/sift/runner.py`                              |
| Request/response models                        | `src/core/types.py`                                    |
| Tier flags                                     | `src/core/config.py` (`TierConfig`, `APTWatcherConfig`)|
| Allow-lists (plugins, parsers, scanners, pkgs) | `src/core/sift/` (per-runner modules)                  |
| Audit logger and envelope                      | `src/core/audit.py`, `src/core/types.py`               |
| Tier 1 provider factory / aggregator / feeds   | `src/core/intel/` (`providers.py`, `aggregator.py`, `feeds.py`) |

---

## 7. Known discrepancies

- **Server file truncation: resolved.** Earlier revisions of
  `src/mcp_server/server.py` carried a duplicated, unreachable content
  block after line 423. The file is clean today — registrations run
  uninterrupted through `admin_providers_status` and the module ends at
  `main()`. This page documents all 51 legitimately registered tools
  (sections 3.1-3.51).
- **Stale `FastMCP` instructions string.** The `instructions=` argument
  in `build_server` still tells MCP clients "Tier 0 tools only in this
  build", and the `build_server` docstring still says "only Tier 0
  tools are registered". Both predate the Tier 1 intel drop and are
  wrong on the wire; the registrations themselves (sections 3.43-3.51)
  are authoritative.
- **Tier 1 intel tools emit no audit events.** See section 5,
  "Non-SIFT tools": network-touching lookups produce no `tool_call`
  pair and no `correlation_id`.
- **Planned tools referenced but not wired.** `ARCHITECTURE.md` and
  `tier-gating.md` describe Tier 1-4 tool families; the Tier 1 intel
  lookup family is now registered (sections 3.43-3.51), while the
  remaining Tier 1 planning names and all of Tier 2-4 are not. Section
  4 above enumerates the remaining gap.
