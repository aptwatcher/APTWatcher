# Tier 0 — SIFT Lifecycle & Pre-flight

> Core tier bootstrap. Runs before the agent accepts any triage task.

---

## Goals

1. **Ensure SIFT tooling is present and current** before triage starts.
2. **Refuse to triage** if critical tools are missing or broken — fail loud,
   not silent (hallucination risk).
3. **Record the tool inventory** in the audit log so every finding is
   traceable to a known tool version.

---

## Pre-flight checks

### 1. Environment probe

```python
# Pseudocode, to be implemented in src/mcp_server/preflight.py
def preflight() -> PreflightReport:
    return PreflightReport(
        os_name=..., os_version=...,
        sift_version=..., sift_last_update=...,
        protocol_sift_version=...,
        tools={
            "volatility3":   probe_version("vol.py --version"),
            "log2timeline":  probe_version("log2timeline.py --version"),
            "plaso":         probe_version("psort.py --version"),
            "bulk_extractor": probe_version("bulk_extractor -V"),
            "yara":          probe_version("yara --version"),
            "sleuthkit":     probe_version("fls -V"),
            # ...
        },
        python_packages={
            "volatility3": __version__,
            "pycryptodomex": ...,
        },
        missing_critical=[],
        outdated_warnings=[],
    )
```

### 2. SIFT update (optional, user-triggered)

An MCP tool `sift_update()` that:
- Runs `sudo apt update && sudo apt upgrade` for SIFT-maintained packages
- Runs `sudo saltstack-update` if SIFT uses salt-based config
- Updates `volatility3` plugin repo
- Updates YARA rule sources

**Explicitly NOT automatic.** The agent suggests running update if preflight
detects staleness, but requires the user/operator to consent — updating
dependencies mid-incident is its own evidence-integrity risk.

### 3. Plugin/rule freshness

- Volatility3 symbol tables for the target OS present?
- YARA rule sets loaded and deduplicated?
- Timezone set correctly on SIFT host?

---

## Failure modes

| Condition | Behavior |
|---|---|
| Critical tool missing (e.g., volatility3) | Refuse tasks requiring it, suggest install |
| Tool present but version very old | Warn, proceed, log version in audit |
| Symbol table missing for target OS | Refuse memory analysis tasks, suggest download |
| SIFT > 90 days since last update | Warn in preflight report |
| YARA rules > 30 days old | Warn, list age in audit |

---

## Use-case profiles

Different triage scenarios need different tool subsets. Defining profiles
lets preflight check only what's needed for the requested use case:

- **`windows-host-triage`**: volatility3 (win symbols), log2timeline (win
  plugins), bulk_extractor, yara, sleuthkit
- **`linux-host-triage`**: volatility3 (linux symbols), log2timeline (linux
  plugins), chkrootkit patterns, yara
- **`memory-only`**: volatility3, yara, bulk_extractor
- **`timeline-only`**: log2timeline, plaso, regripper
- **`network-artifact`**: zeek, suricata, tshark

The agent declares its target profile at the start of a session; preflight
checks just that profile.

---

## Audit contract

Every triage session starts with a preflight record pinned in the audit log:

```json
{
  "event": "preflight",
  "session_id": "apts-2026-04-19-abc123",
  "timestamp": "2026-04-19T14:22:01Z",
  "profile": "windows-host-triage",
  "sift_version": "2025.11",
  "tools": { "volatility3": "2.7.0", "log2timeline": "20250812", ... },
  "warnings": [],
  "pass": true
}
```

Without a passing preflight entry, the agent's findings downstream in the
audit log are flagged as unverified. This is a structural guardrail:
**no preflight → no authority**.
