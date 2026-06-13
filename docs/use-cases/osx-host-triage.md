# Use case: macOS host triage (experimental)

> Experimental profile. APFS / unified-log tooling on SIFT is partial — the
> agent surfaces gaps explicitly rather than hiding them.

## When to use

- A macOS endpoint (Intel or Apple Silicon) is suspected of compromise.
- You have a logical acquisition (full filesystem via the MAS acquisition
  workflow or a sparse image), a unified-log archive (`log collect`), or
  a KAPE/`mac_apt`-style triage bundle.
- Common triggers: suspicious TCC prompts, unexplained launch agents,
  XProtect/MRT hits, an unsigned binary running on login, or an HR-driven
  executive device review.

## Profile declaration

```yaml
profile: osx-host-triage
required_tools:
  - log2timeline.py >= 20240504
  - yara
  - mac_apt
optional_tools:
  - UnifiedLogReader
  - plutil
  - APOLLO
  - spctl
artifact_categories:
  required:
    - unified_logs (logarchive or log show --style ndjson export)
    - launchd_plists (/Library/Launch{Daemons,Agents}, ~/Library/LaunchAgents)
    - fsevents (/.fseventsd/ fragments)
    - bash_or_zsh_history (per user)
  optional:
    - knowledgec_db (~/Library/Application Support/Knowledge/knowledgeC.db)
    - quarantine_events_v2 (~/Library/Preferences/.../QuarantineEventsV2)
    - spotlight_store (/.Spotlight-V100/Store-V2/.../store.db)
    - amfi_logs (AMFI kernel messages in unified log)
tier_prerequisites:
  tier_1: optional
  tier_2: optional
  tier_3: gated_by_flag
```

## What the agent does under this profile

1. **Preflight** confirms `log2timeline.py` and `yara` are present and
   records the macOS version captured in the bundle (provenance).
2. **Launchd persistence sweep.** Lists `.plist` files in the four standard
   locations, decodes each via `plutil -p`, checks `ProgramArguments[0]`
   against signed-binary expectations and flags `Label`/path anomalies.
   See `knowledge/macos/launchd-plist.md`.
3. **Unified-log review.** Extracts the subset relevant to persistence and
   execution (`com.apple.xpc.launchd`, `com.apple.TCC`, `com.apple.amfi`).
4. **KnowledgeC.db and Quarantine Events.** Application-use context and the
   provenance of downloaded files (which is the macOS equivalent of
   Windows' Mark-of-the-Web).
5. **FSEvents review** for post-compromise file activity in user home
   directories that bash/zsh history does not cover.
6. **Timeline** via plaso — plaso does parse several macOS sources;
   gaps (native APFS timeline fidelity in particular) are flagged.
7. **Report** with MITRE mapping.

## macOS-specific anti-patterns

- **Trusting `launchctl list` output on a compromised host.** The agent
  prefers on-disk `.plist` inventory plus unified-log spawn events for
  corroboration.
- **Assuming SIP blocks persistence.** System Integrity Protection prevents
  modifications in `/System` but leaves `/Library` and `~/Library` open.
  Most attacker persistence lives outside SIP's scope.
- **Ignoring TCC changes.** `Transparency, Consent, and Control` database
  changes (via `sqlite3` attack on `TCC.db`) can widen an attacker's reach
  silently.

## What it cannot do

- **Full APFS snapshot forensics**. SIFT's APFS tooling is partial; the
  agent reports the limitation instead of fabricating reconstruction.
- **iOS artifacts**. Those belong in `mobile-host-triage`.
- **Kernel-extension-based rootkit confirmation**. Modern macOS rootkits
  that run as DriverKit or System Extensions require Apple-signed
  developer tooling beyond what SIFT provides.

## Failure modes

- **No unified-log archive**: the logarchive is the single most valuable
  macOS source. Absent it, the profile runs with reduced confidence caps
  on every finding rather than aborting.
- **Binary plist failed to decode** (`plutil` refuses): the agent records
  the file path + SHA-256 and defers to manual review.
- **SIP-altered system plist drift**: flagged but not treated as a
  finding on its own — Apple ships OS updates that legitimately modify
  these.

## Related

- [Linux host triage](linux-host-triage.md)
- [Mobile host triage](mobile-host-triage.md)
- [Reference — SIFT tools](../reference/sift-tools.md)
- KB entry: `knowledge/macos/launchd-plist.md` (clean-room entry, loaded by the KB loader, not served by mkdocs)
