# Use case: Mobile (iOS / Android) host triage (experimental)

> Experimental profile. Physical / chip-off acquisitions are out of scope;
> the agent refuses to participate in those steps. Logical and filesystem
> acquisitions (iTunes-style backups, Android `adb backup`, MDM-generated
> bundles, ALEAPP / iLEAPP inputs) are in scope.

## When to use

- A phone or tablet has been imaged into a SIFT-reachable bundle and you
  want a first-pass triage against common compromise patterns (stalkerware,
  smishing-delivered payloads, MDM misconfiguration, IM exfil).
- The acquisition is logical or filesystem-level. If you only have a
  backup `.ab` (Android) or a `Manifest.plist` + `Manifest.db` (iOS), the
  agent adapts to what's present and flags missing categories.
- Common triggers: executive-protection handoff, suspected spyware
  (Pegasus-like behaviour), IM compromise review, lost-device response.

## Profile declaration

```yaml
profile: mobile-host-triage
required_tools:
  - yara
optional_tools:
  - ALEAPP           # Android Logs Events And Protobuf Parser
  - iLEAPP           # iOS Logs Events And Protobuf Parser
  - sqlite3
  - plutil
  - adb
artifact_categories:
  required:
    - mobile_acquisition_manifest (Manifest.plist/db OR adb backup header)
    - app_databases (WhatsApp / Signal / Telegram / iMessage chat.db)
  optional:
    - ios_biome (/private/var/mobile/Library/Biome/...)
    - android_logcat (dumpsys + logcat exports)
    - keychain_backup (iOS encrypted keychain in the backup)
    - whatsapp_sqlite (ChatStorage.sqlite / msgstore.db)
tier_prerequisites:
  tier_1: optional
  tier_2: optional
  tier_3: not_applicable   # no containment path for mobile yet
```

## What the agent does under this profile

1. **Preflight** confirms `yara` is present and inspects the acquisition
   manifest to decide which sub-parser (ALEAPP or iLEAPP) applies.
2. **Inventory.** Lists installed packages / apps from the acquisition,
   flags out-of-store sideloaded packages (Android `adb install`
   artifacts, iOS enterprise / developer-profile signatures).
3. **App-database review.** For the top IM apps present, extracts message
   counts and attachment inventories (without decrypting content) and
   flags abnormally large attachment caches.
4. **Persistence-equivalent surfaces.**
   - iOS: configuration profiles (`/private/var/preferences/Logging/`,
     `ManagedConfiguration`), background refresh abuse patterns.
   - Android: accessibility services enabled, device admins enabled, app
     ops granting `SYSTEM_ALERT_WINDOW` / `BIND_NOTIFICATION_LISTENER_SERVICE`.
5. **Known-stalkerware YARA sweep** over app filenames and package names.
6. **Report** with MITRE Mobile ATT&CK mapping.

## Mobile-specific anti-patterns

- **Treating a logical backup as a full forensic image.** Encrypted
  containers, sandboxed app state, and device-only secrets (Secure Enclave,
  Keystore) are not in a logical backup. The agent notes the gap.
- **Trusting app package names.** Stalkerware frequently ships under names
  that mimic system packages. The agent compares against signatures, not
  just names.
- **Confusing MDM surveillance with a compromise.** Enterprise-managed
  devices legitimately carry configuration profiles and device-admin
  enrolments that would look alarming outside that context.

## What it cannot do

- **Decrypt encrypted IM content.** The agent enumerates database
  structure and message counts, not content.
- **Physical or chip-off acquisition.** Out of scope; the agent refuses
  to participate.
- **Jailbreak / root-attestation verification** beyond flagging obvious
  artefacts (`Cydia.app`, `Sileo`, `/su` binaries, Magisk modules).
- **Carrier-network / SS7 investigation.** Completely out of scope.

## Failure modes

- **No acquisition manifest**: aborts. Without a manifest we cannot
  attest to the acquisition's scope and cannot honour evidence integrity.
- **Unsupported backup format**: reports the format and defers to
  manual analysis rather than guessing.
- **Full-disk-encryption key absent** (expected): the agent skips
  encrypted regions, records the skip, and continues.

## Related

- [macOS host triage](osx-host-triage.md)
- [Reference — SIFT tools](../reference/sift-tools.md)
