# S04 — Offline to online bundle handoff

> The cross-boundary demo. An air-gapped triage workstation produces a
> signed incident bundle, a courier carries it over the air gap, and an
> online workstation verifies the signature and fans the triage data
> out to three publication targets. Phase 3.7 lands the bundle
> primitives; S04 is how we show the primitives working end-to-end.

## Story

Wednesday 09:14 local. A finance-sector incident response team is
brought in on a suspected intrusion at a regulated client whose
segmented network forbids any outbound traffic from the analysis LAN.
Evidence from the affected host (`FIN-WS-101`) is carried into the
air-gapped SIFT VM by offline media. Triage runs entirely offline.
Three findings crystallise: an EVTX Sigma hit on an unusual logon, a
YARA memory hit on a packed loader, and a bulk_extractor pull of a
suspicious domain.

At 11:02, the operator signs the incident bundle with an Ed25519 key
that never leaves their smartcard. The bundle is copied to a one-way
file drop at 11:05. The online workstation picks it up at 11:07,
verifies the signature against the known operator public key, and —
without ever reopening the original evidence — pushes the triage data
to three downstream consumers: a takedown provider stand-in, a
threat-sharing community stand-in, and a ticketing stand-in. The demo
uses the stub publication adapter for all three so no live credentials
are required.

The narrative arc is *evidence stays offline, conclusions travel
online*. No disk image, no memory capture, no raw artifact crosses
the air gap — only a signed summary.

## Environment

- **Offline host**: `SIFT-5.13` VM on an isolated hypervisor. Python
  3.11, APTWatcher `core.bundle` at Phase 3.7, Ed25519 private key
  material under `~/.aptwatcher/keys/` (abstracted from a smartcard).
- **Online host**: an ordinary analyst workstation. Same APTWatcher
  install; only the adapter configuration differs.
- **Transport**: one-way file drop. The scenario does not prescribe a
  transport; the bundle carries its own integrity proof.
- **Keys**: private seed at `/tmp/s04/keys/operator.ed25519` on the
  offline VM; public key hex pinned into the online verify call.

## Findings and IOCs (synthetic triage output)

Three synthetic findings and five IOCs, hand crafted to exercise each
carrier in the bundle schema at least once.

### Findings

| id | summary | source tool | MITRE | confidence |
|----|---------|-------------|-------|------------|
| `f-001` | Sigma rule `Suspicious_PSExec_Service_Install` fires against Security EVTX on `FIN-WS-101` during off-hours. | Hayabusa + Sigma | T1021.002 | 0.80 |
| `f-002` | YARA rule `Packed_Loader_XorStub_v2` hits a memory region in `svchost.exe` pid 2148. | volatility3 + YARA | T1055 | 0.72 |
| `f-003` | bulk_extractor surfaces the domain `cdn-metrics-update.biz` in pagefile.sys with a nearby referer string matching a known phishing kit template. | bulk_extractor | T1071.001 | 0.65 |

Every finding carries at least one `FindingCitation` back to the
offline audit log. No finding's confidence is 1.0 — the scenario is a
triage handoff, not a conviction.

### IOCs

| value | type | source finding | notes |
|-------|------|----------------|-------|
| `cdn-metrics-update.biz` | `domain` | `f-003` | Takedown-provider stand-in. |
| `185.234.247.12` | `ipv4` | `f-001` | Logon origin on the Sigma hit. |
| `10.8.14.77` | `ipv4` | `f-001` | Jump host first seen in the same EVTX. |
| `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `sha256` | `f-002` | Packed loader binary hash. |
| `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08` | `sha256` | `f-002` | Decoded stub hash after YARA follow-up. |

Mix is deliberate: two IPs, one domain, two hashes. Mirrors the shape
of a real host-triage pass.

## Offline leg — triage to signed bundle

### 1. Stage the triage input

The scenario assumes an earlier `aptwatcher run` produced a normalised
findings-plus-IOCs JSON at `/tmp/s04/triage/input.json`. The shape is
`{"findings": [...], "iocs": [...]}` as loaded by
`_load_input_bundle()` in `src/agent_extension/analyze.py`.

### 2. Generate the operator keypair (one-time)

```bash
python -c "
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization as s
priv = ed25519.Ed25519PrivateKey.generate()
Path('/tmp/s04/keys/operator.ed25519').write_bytes(priv.private_bytes(
    encoding=s.Encoding.Raw, format=s.PrivateFormat.Raw,
    encryption_algorithm=s.NoEncryption()))
Path('/tmp/s04/keys/operator.pub.hex').write_text(
    priv.public_key().public_bytes(
        encoding=s.Encoding.Raw, format=s.PublicFormat.Raw).hex())
"
```

The 32-byte raw seed is what `export_bundle(private_key_bytes=...)`
expects. The public hex is what the online leg pins.

### 3. Run `aptwatcher analyze` with signing enabled

```bash
aptwatcher analyze \
    --input /tmp/s04/triage/input.json \
    --output-dir /tmp/s04/bundle \
    --campaign-tag S04-HANDOFF \
    --incident-id INC-20260420-S04001 \
    --operator "ir-analyst-01" \
    --language en \
    --sign \
    --private-key-path /tmp/s04/keys/operator.ed25519 \
    --sift-workstation "sift-5.13-airgap-a"
```

What the analyze command does here:

- Loads the three findings and five IOCs from `--input`.
- Fans out YARA, Suricata, and Sigma rule artifacts under
  `/tmp/s04/bundle/rules/`.
- Writes STIX, community YAML, and per-type IOC text files under
  `/tmp/s04/bundle/iocs/`.
- Renders the English analyst report and the TTP assessment under
  `/tmp/s04/bundle/reports/`.
- Because `--sign` is set, calls `export_bundle(...)` from
  `core.bundle.exporter` against `/tmp/s04/bundle/incident-bundle/`,
  writing the canonical four payload files plus `signature.json`.

Expected console tail:

```
analyze: incident_id=INC-20260420-S04001
analyze: findings=3 iocs=5
analyze: outputs under /tmp/s04/bundle
analyze: manifest=/tmp/s04/bundle/generation_report.json
```

### 4. Expected audit events on the offline side

| Step | Event name | Notes |
|------|------------|-------|
| Triage load | `input_loaded` | Records the input-file sha256. |
| Rules fan-out | `rules_generated` | Per-carrier count. |
| IOC fan-out | `iocs_exported` | Per-type count. |
| Reports fan-out | `report_rendered` | Per-language path. |
| Bundle write | `bundle_exported` | Records concatenated payload sha256 that was signed. |
| Signing | `bundle_signed` | Records signer public-key fingerprint (never the private key). |

Every event is append-only. The bundle's
`manifest.file_digests["audit.jsonl"]` fixes the exact bytes of the
embedded audit slice, so any post-signing edit breaks verification.

## Transport leg — across the air gap

Narratively, the operator:

1. Copies the whole `/tmp/s04/bundle/incident-bundle/` directory (five
   files: `manifest.json`, `findings.json`, `iocs.json`,
   `audit.jsonl`, `signature.json`) onto a signed, write-once medium.
2. Physically carries it to the online workstation.
3. Drops it at `/tmp/s04/inbox/incident-bundle/`.

The transport is untrusted by design. The signature is what makes the
bundle trustworthy; the wire does not have to.

## Online leg — verify and publish

### 5. Verify the bundle

```bash
python -c "
from pathlib import Path
from core.bundle.importer import import_bundle
pubkey_hex = Path('/tmp/s04/keys/operator.pub.hex').read_text().strip()
bundle = import_bundle(
    bundle_dir=Path('/tmp/s04/inbox/incident-bundle'),
    expected_public_key_hex=pubkey_hex, verify=True)
print(f'verified: incident_id={bundle.manifest.incident_id}')
print(f'findings={len(bundle.findings)} iocs={len(bundle.iocs)}')
"
```

`import_bundle` performs, in order:

- File-existence check for the four payload files and
  `signature.json`.
- Per-file sha256 vs `manifest.file_digests` (raises
  `BundleIntegrityError` on mismatch).
- Record-count cross-check against `manifest.counts`.
- sha256 over concatenated payload bytes in the fixed order
  `manifest.json | findings.json | iocs.json | audit.jsonl`.
- Ed25519 verification of `signature.json` against the recomputed
  digest and the pinned `expected_public_key_hex` (raises
  `BundleSignatureError` on failure).

A successful run returns an `IncidentBundle`. No side effects; no
network calls. This is the gate.

### 6. Stage for publish

The publish leg consumes sibling JSON files (`findings.json` /
`iocs.json` / `manifest.json`) at the top of a bundle directory. The
operator unwraps the verified bundle into a staging directory:

```bash
python -c "
import json
from pathlib import Path
from core.bundle.importer import import_bundle
b = import_bundle(
    bundle_dir=Path('/tmp/s04/inbox/incident-bundle'),
    expected_public_key_hex=Path('/tmp/s04/keys/operator.pub.hex').read_text().strip(),
    verify=True)
s = Path('/tmp/s04/publish-staging'); s.mkdir(parents=True, exist_ok=True)
(s/'findings.json').write_text(json.dumps(
    [f.model_dump(mode='json') for f in b.findings], indent=2, sort_keys=True)+'\n')
(s/'iocs.json').write_text(json.dumps(
    [i.model_dump(mode='json') for i in b.iocs], indent=2, sort_keys=True)+'\n')
(s/'manifest.json').write_text(json.dumps(
    {'incident_id': b.manifest.incident_id, 'campaign_tag': 'S04-HANDOFF'},
    indent=2, sort_keys=True)+'\n')
"
```

The publish loader in `src/agent_extension/publish.py` accepts both
the raw `Finding` shape and the `BundleFinding` wrapper, so the
staging step can be simplified in a later iteration.

### 7. Publish to three targets via the stub adapter

```bash
aptwatcher publish \
    --bundle-dir /tmp/s04/publish-staging \
    --adapter stub \
    --adapter stub \
    --adapter stub \
    --dry-run
```

The `stub` adapter is selected three times to stand in for the three
downstream consumers the real campaign would target (takedown
provider, community sharing, ticketing). Each invocation walks
`cmd_publish` in `src/agent_extension/publish.py`, instantiates a
fresh `StubPublicationAdapter`, and records the call.

Expected tail:

```
publish[stub]: dry-run
publish[stub]: dry-run
publish[stub]: dry-run
```

Flip to live submission (still harmless — the stub never touches the
network) with `--no-dry-run`:

```bash
aptwatcher publish \
    --bundle-dir /tmp/s04/publish-staging \
    --adapter stub \
    --adapter stub \
    --adapter stub \
    --no-dry-run
```

Expected tail:

```
publish[stub]: submitted
publish[stub]: submitted
publish[stub]: submitted
```

### 8. Expected audit events on the online side

| Step | Event name | Notes |
|------|------------|-------|
| Bundle read | `bundle_loaded` | Records inbox path and incident_id. |
| Integrity check | `bundle_integrity_ok` | Per-file sha256 match count. |
| Signature check | `bundle_signature_ok` | Records signer public-key fingerprint. |
| Stage | `publish_staged` | Records the staging directory path. |
| Adapter instantiate | `adapter_loaded` | One event per `--adapter`. |
| Publish call | `publication_submitted` | Per-adapter-call; includes counts and `dry_run` flag. |

Any verification failure emits `bundle_signature_failed` or
`bundle_integrity_failed` and halts before any `adapter_loaded` event
fires. The online audit log records *why* a bundle was rejected;
there is never a silent drop.

## Success rubric

| Score band | Meaning |
|------------|---------|
| **Pass** | Signed bundle produced offline; `import_bundle` returns cleanly with the pinned public key; all three stub publishes complete (dry-run and live); audit events match the tables above. |
| **Partial** | Bundle produced and verified, but at least one publish adapter raises. The boundary is still demonstrated; the failure is a follow-up. |
| **Fail** | Verification fails on a good bundle, or passes on a tampered bundle. Both are hard-fail. |

Two adversarial sub-cases that must also be demonstrated:

- **Tamper the bundle.** Edit one byte in `iocs.json` after signing;
  re-run `import_bundle`; expect `BundleIntegrityError` on the file
  digest check, never reaching the signature step.
- **Swap the signer.** Run `import_bundle` with an
  `expected_public_key_hex` that does not match; expect
  `BundleSignatureError` with a mismatch message.

Both cases are walked through as part of the demo so the trust
boundary is visible, not just asserted.

## Dataset strategy

S04 is **fully synthetic**. No disk image, no memory image, no real
evidence. The triage input is a hand-authored JSON that instantiates
three findings and five IOCs — enough to exercise every branch of
`export_bundle` and every adapter entry point in publish. A judge
with a vanilla Python 3.11 environment and this repository can
reproduce S04 end-to-end in five minutes.

## Related

- Design note: [`../docs/design/offline-to-online-handoff.md`](../docs/design/offline-to-online-handoff.md)
- Design note: [`../docs/design/evidence-integrity.md`](../docs/design/evidence-integrity.md)
- Procedure KB: [`../knowledge/procedures/timeline-building-workflow.md`](../knowledge/procedures/timeline-building-workflow.md)
- Procedure KB: [`../knowledge/procedures/memory-triage-live-response.md`](../knowledge/procedures/memory-triage-live-response.md)
- Source: [`../src/core/bundle/exporter.py`](../src/core/bundle/exporter.py)
- Source: [`../src/core/bundle/importer.py`](../src/core/bundle/importer.py)
- Source: [`../src/agent_extension/analyze.py`](../src/agent_extension/analyze.py)
- Source: [`../src/agent_extension/publish.py`](../src/agent_extension/publish.py)
- Scenarios index: [`README.md`](README.md)
