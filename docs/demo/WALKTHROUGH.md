# Demo walkthrough — APTWatcher end-to-end on the command line

This is a reproducible transcript, not a storyboard. Every output
block below was captured from a real run of the packaged CLI on
2026-06-12 (Python 3.12, sandboxed Linux, clean virtualenv, **no**
SIFT forensic tools installed). That last constraint is deliberate:
preflight honestly reports the missing tools instead of pretending,
and everything else in the walkthrough — knowledge base, signed
bundles, publication adapters, the accuracy harness, audit rendering —
runs to completion because none of it needs the heavy tooling. On a
SIFT workstation the same commands drive the real forensic tools.

Long outputs are trimmed with `[... trimmed ...]`; nothing is
fabricated or retouched. Where the capture session surfaced real bugs,
they are documented in section 9 rather than hidden.

The bundle leg follows scenario
`scenarios/S04-offline-to-online-handoff.md` in the repository: an
air-gapped workstation produces a signed incident bundle, the online
side verifies it, tampering is detected, and publication stays dry-run
by default.

## 1. Version and profiles

First contact with the CLI: confirm the install and list the
registered use-case profiles. Each profile is a contract — a named
tool roster the agent is allowed to plan against. The planner never
improvises a tool that is not in the active profile.

```console
$ aptwatcher version
aptwatcher 0.1.0a0
```

```console
$ aptwatcher profiles
                              Registered profiles
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Name                ┃ Required tools             ┃ Description               ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ windows-host-triage │ volatility3,               │ Full Windows triage: disk │
│                     │ log2timeline.py,           │ and/or memory plus triage │
│                     │ bulk_extractor, RegRipper, │ bundle.                   │
│                     │ yara                       │                           │
│ linux-host-triage   │ volatility3,               │ Linux triage: disk plus   │
│                     │ log2timeline.py,           │ memory, systemd/cron      │
│                     │ bulk_extractor, yara,      │ persistence sweep.        │
│                     │ chkrootkit                 │                           │
│ memory-only         │ volatility3, yara          │ Memory image only.        │
│                     │                            │ Live-response triage      │
│                     │                            │ without disk.             │
[... trimmed: timeline-only, network-artifact, osx-host-triage,
     mobile-host-triage ...]
└─────────────────────┴────────────────────────────┴───────────────────────────┘
```

## 2. Preflight — an honest failure

Preflight probes the workstation for the active profile's required
tools before any triage is planned. In this capture environment none
of the SIFT tools exist, and the command says so and exits non-zero.
This matters for evidence integrity: the agent refuses to start a run
it cannot execute, rather than silently degrading or hallucinating
tool output. On a stock SIFT workstation the same command reports
`Preflight OK` and exits 0.

```console
$ aptwatcher preflight --profile windows-host-triage
─────────────── Preflight NOT OK -- profile: windows-host-triage ───────────────
Missing required tools: volatility3, log2timeline.py, bulk_extractor, RegRipper,
yara
Missing optional tools: evtx_dump, prefetch-parser, shellbag_parser
$ echo $?
1
```

## 3. Knowledge base search

The agent's planner is grounded in 32 clean-room knowledge base
entries under `knowledge/`. Before writing novel logic, every role
asks the KB first. The search is offline keyword retrieval — no
network, no external corpus — and every entry carries MITRE ATT&CK
technique IDs that flow through to findings and reports.

```console
$ aptwatcher knowledge-search "lateral movement smb"
                    Top 5 KB hits for 'lateral movement smb'
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┓
┃ ID                ┃ Title              ┃ Source          ┃ MITRE             ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━┩
│ kb-net-smb-rpc-l… │ SMB and RPC        │ author-original │ T1021.002,        │
│                   │ lateral movement   │                 │ T1569.002,        │
│                   │                    │                 │ T1053.002,        │
│                   │                    │                 │ T1053.005,        │
│                   │                    │                 │ T1003.006, T1047  │
│ kb-win-lat-smb-a… │ SMB admin share    │ author-original │ T1021.002, T1570, │
│                   │ abuse — lateral    │                 │ T1569.002         │
│                   │ movement via       │                 │                   │
│                   │ ADMIN$, C$, IPC$   │                 │                   │
│ kb-proc-lateral-… │ Lateral movement — │ author-original │ T1021, T1021.001, │
│                   │ detection,         │                 │ T1021.002,        │
│                   │ scoping, rapid     │                 │ T1021.006, T1570, │
│                   │ containment        │                 │ T1563, T1047      │
[... trimmed: 2 more hits (EVTX logon anomalies, Linux SSH lateral
     movement) ...]
└───────────────────┴────────────────────┴─────────────────┴───────────────────┘
```

## 4. Offline leg — keypair and triage input (scenario S04)

The S04 story: triage happens on an air-gapped workstation; only a
signed summary crosses the air gap. We generate an Ed25519 operator
keypair with the repository's own helper
(`src/core/bundle/signer.py::generate_keypair`) and hand-author the
triage input — three findings, five IOCs — exactly as scripted in the
scenario. The input shape is the same `{"findings": [...], "iocs":
[...]}` JSON that `aptwatcher run` produces.

```console
$ python - <<'EOF'
from pathlib import Path
from core.bundle.signer import generate_keypair
priv, pub = generate_keypair()
Path("/tmp/s04/keys/operator.ed25519").write_bytes(priv)
Path("/tmp/s04/keys/operator.pub.hex").write_text(pub.hex() + "\n")
print(f"private key: 32 bytes -> /tmp/s04/keys/operator.ed25519")
print(f"public key : {pub.hex()}")
EOF
private key: 32 bytes -> /tmp/s04/keys/operator.ed25519
public key : fe1a7c0851d840e69d42b1399686fb3f2e77c8d8d8c287fd5802df0c0e9680c9
```

The triage input (`/tmp/s04/triage/input.json`, trimmed to one finding
and one IOC here; the full file has three and five):

```json
{
  "findings": [
    {
      "finding_id": "f-001",
      "summary": "Sigma rule Suspicious_PSExec_Service_Install fires against Security EVTX on FIN-WS-101 during off-hours.",
      "mitre": ["T1021.002"],
      "confidence": 0.80,
      "evidence": [
        {"source": "Security.evtx", "locator": "event_id=7045 record=88412", "tool_call_id": "c-101"}
      ],
      "reasoning": null
    }
  ],
  "iocs": [
    {"value": "185.234.247.12", "ioc_type": "ipv4", "verdict": "malicious",
     "confidence": 0.80, "sources": [], "attributions": [],
     "notes": "Logon origin on the Sigma hit."}
  ]
}
```

## 5. `aptwatcher analyze --sign` — fan-out plus signed bundle

One command turns the triage JSON into the full analysis surface:
YARA and Suricata rules, STIX and per-type IOC exports, the analyst
report, a MITRE TTP assessment, and — because `--sign` is set — a
canonical five-file incident bundle signed with the operator key. The
private key never appears in any output; only its public point is
recorded.

```console
$ aptwatcher analyze \
    --input /tmp/s04/triage/input.json \
    --output-dir /tmp/s04/bundle \
    --campaign-tag S04-HANDOFF \
    --incident-id INC-20260612-S04001 \
    --operator ir-analyst-01 \
    --language en \
    --sign \
    --private-key-path /tmp/s04/keys/operator.ed25519 \
    --sift-workstation sift-airgap-a
analyze: incident_id=INC-20260612-S04001
analyze: findings=3 iocs=5
analyze: outputs under /tmp/s04/bundle
analyze: manifest=/tmp/s04/bundle/generation_report.json
```

The output tree:

```console
$ find bundle -type f | sort
bundle/findings.json
bundle/generation_report.json
bundle/incident-bundle/audit.jsonl
bundle/incident-bundle/findings.json
bundle/incident-bundle/iocs.json
bundle/incident-bundle/manifest.json
bundle/incident-bundle/signature.json
bundle/iocs.json
bundle/iocs/bundle.stix.json
bundle/iocs/community-submission.yml
bundle/iocs/domain.txt
bundle/iocs/ipv4.txt
bundle/iocs/sha256.txt
bundle/manifest.json
bundle/reports/ANALYSIS-INC-20260612-S04001.md
bundle/reports/Campaign_Report_INC-20260612-S04001.docx
bundle/reports/TTP_INC-20260612-S04001.md
bundle/rules/s04-handoff.suricata.rules
bundle/rules/s04-handoff.yar
```

A sample of the generated detection content — real Suricata rules
derived from the IOCs, with campaign-tagged messages and a managed SID
range:

```console
$ head -3 bundle/rules/s04-handoff.suricata.rules
alert dns any any -> any any (msg:"S04-HANDOFF - suspicious DNS lookup cdn-metrics-update.biz"; dns.query; content:"cdn-metrics-update.biz"; nocase; sid:3000000; rev:1;)
alert ip any any -> 185.234.247.12 any (msg:"S04-HANDOFF - outbound to 185.234.247.12"; sid:3000001; rev:1;)
alert ip any any -> 10.8.14.77 any (msg:"S04-HANDOFF - outbound to 10.8.14.77"; sid:3000002; rev:1;)
```

And the detached signature over the bundle payload digest:

```console
$ cat bundle/incident-bundle/signature.json
{
  "algo": "ed25519",
  "public_key_hex": "fe1a7c0851d840e69d42b1399686fb3f2e77c8d8d8c287fd5802df0c0e9680c9",
  "signature_hex": "e4a45cedbe96e6403e3e0daa06a5cc2f0a20be22e33252de5dc38aa176fa60b4f7444cbd9decf3c9f5cd9b52c0eea6ccb20055ee9e39845ed6eb8e6cf4ec7e03",
  "signed_digest_hex": "bb2aa4353e0d2f57fa393b20602af1d80c598cb357ca719c6e6f81f9f8629502"
}
```

## 6. Online leg — verify the bundle

The bundle is copied to the online side's inbox (in S04, by hand
across an air gap — the transport is untrusted by design). The
importer re-derives every digest, cross-checks record counts, and
verifies the Ed25519 signature against the pinned operator public key
before returning a single object. No network, no side effects.

```console
$ python - <<'EOF'
from pathlib import Path
from core.bundle.importer import import_bundle
pubkey_hex = Path("/tmp/s04/keys/operator.pub.hex").read_text().strip()
bundle = import_bundle(
    bundle_dir=Path("/tmp/s04/inbox/incident-bundle"),
    expected_public_key_hex=pubkey_hex,
    verify=True,
)
print(f"verified: incident_id={bundle.manifest.incident_id}")
print(f"findings={len(bundle.findings)} iocs={len(bundle.iocs)}")
EOF
verified: incident_id=INC-20260612-S04001
findings=3 iocs=5
```

## 7. Tamper detection — the trust boundary, demonstrated

S04 requires two adversarial sub-cases, and both must hard-fail.
First, edit a single character inside the signed payload — one digit
of an IOC value, so the JSON stays syntactically valid and only the
content changes (`185.234.247.12` becomes `185.234.247.13`). The
per-file digest check catches it and names the exact file and both
digests:

```console
$ python verify_inbox.py   # same import_bundle call as above
REJECTED -- BundleIntegrityError: sha256 mismatch for iocs.json: expected sha256:51bd9d0732964cd98cb5ec1f0a690d989c442cd5c1808d4d9f869ee2a72862d6, got sha256:d009e846111715911535f226e967de954ad80d20f7b72e34f9fb8ee12fcaecfc
```

Second, restore the file and present the wrong signer: verify against
a freshly generated public key that is not the operator's. The
signature gate rejects it before trusting a single record:

```console
$ python verify_inbox.py --expected-key <other-key-hex>
REJECTED -- BundleSignatureError: bundle public key does not match expected public key
```

One honest capture note: our first tamper attempt flipped a random
byte, which broke JSON syntax, and the importer failed on the JSON
parse (a `JSONDecodeError`) before reaching the digest comparison. A
corrupted bundle is still loudly rejected either way — nothing
verifies, nothing is silently accepted — but the content-preserving
edit above is the better demonstration because it exercises the
cryptographic gate itself, the way a real adversary editing an IOC
would.

## 8. Publish — dry-run by default

The online side fans the verified bundle out through publication
adapters. Three guardrails are visible here: `--dry-run` is the
default (overriding it is an explicit act), the `stub` adapter lets
the whole path run with zero credentials and zero network, and one
adapter invocation per downstream consumer keeps the blast radius
explicit. S04 uses the stub three times to stand in for a takedown
provider, a sharing community, and a ticketing system.

```console
$ aptwatcher publish --bundle-dir /tmp/s04/inbox/incident-bundle \
    --adapter stub --adapter stub --adapter stub
publish[stub]: dry-run
publish[stub]: dry-run
publish[stub]: dry-run
```

Flipping to live submission requires saying so out loud (the stub
still touches no network):

```console
$ aptwatcher publish --bundle-dir /tmp/s04/inbox/incident-bundle \
    --adapter stub --no-dry-run
publish[stub]: submitted
```

## 9. Self-correction and guardrails

The submission rubric asks for visible self-correction. This capture
session produced real examples at three levels.

**CLI guardrails refuse half-specified danger.** Signing without an
operator identity is rejected before any work happens — an unsigned
or anonymously signed bundle would be worthless downstream:

```console
$ aptwatcher analyze --input /tmp/s04/triage/input.json \
    --output-dir /tmp/s04/oops --sign \
    --private-key-path /tmp/s04/keys/operator.ed25519
error: --sign requires --operator <name>
$ echo $?
1
```

**The capture surfaced two real bugs, which were fixed, not hidden.**
The very first `analyze --sign` run in this session failed with
`error: analysis pipeline failed: render_ttp_assessment() got an
unexpected keyword argument 'iocs'` — a call-site bug the unit tests
had masked by mocking the report stage — and, once that was fixed, a
second failure where the manifest writer tried to hash the
incident-bundle directory as if it were a file. Both pipeline errors
were caught by the command's own error handling (clean `error:`
message, exit code 2, no partial state presented as success). Both
fixes are in the repository; every successful output in this document
was captured after them.

**The agent loop self-corrects and logs it.** Section 11 shows a real
audit log whose verifier and self-corrector passes are first-class,
signed events — including the honest "no issues; nothing to correct"
outcome.

Beneath these sit the standing fences: all 42 registered MCP tools
start at tier 0 (read-only, no egress), tier 1+ requires a prior
`consent_granted` audit event enforced in the server rather than the
tool, and evidence is hashed on first touch and never written to. See
[Evidence integrity](../architecture/evidence-integrity.md) and
[Self-correction](../architecture/self-correction.md).

## 10. Accuracy harness

The eval command replays eight scenario fixtures through the agent
loop with a deterministic replay client and scores findings and IOCs
against ground truth. It is the regression gate for the pipeline: the
threshold is 0.60 and a miss fails the command.

```console
$ aptwatcher eval --fixtures-dir tests/accuracy/fixtures --output-dir /tmp/wt-eval
                         Accuracy report
┏━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ scenario                 ┃ f1_findings ┃ f1_iocs ┃ duration_ms ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━┩
│ s_cloud_iam_escalation   │ 1.000       │ 1.000   │ 14          │
│ s_credential_dump        │ 1.000       │ 1.000   │ 4           │
│ s_dns_tunneling          │ 1.000       │ 1.000   │ 4           │
│ s_lateral_smb            │ 1.000       │ 1.000   │ 4           │
│ s_linux_persistence      │ 1.000       │ 1.000   │ 4           │
│ s_macos_persistence      │ 1.000       │ 1.000   │ 4           │
│ s_phishing_beacon        │ 1.000       │ 1.000   │ 4           │
│ s_ransomware_pre_encrypt │ 1.000       │ 1.000   │ 4           │
└──────────────────────────┴─────────────┴─────────┴─────────────┘
Mean F1: 1.000 (threshold 0.60)
Report JSON: /tmp/wt-eval/accuracy_report_20260612T145944Z.json
Report MD:   /tmp/wt-eval/accuracy_report_20260612T145944Z.md
```

## 11. Audit render — the judge-readable timeline

Each eval scenario above emitted a real per-incident audit log
(`/tmp/wt-eval/audit/<scenario>/<scenario>/audit.jsonl`). The audit
log is APTWatcher's source of truth: append-only, schema-versioned,
reconstructible into a full execution timeline. `audit-render` turns
the JSONL into something a reviewer can read in one screen. This is
the actual log from the `s_lateral_smb` eval run — note the planner,
verifier, and self-corrector passes as first-class events.

```console
$ aptwatcher audit-render --input /tmp/wt-eval/audit/s_lateral_smb/s_lateral_smb/audit.jsonl
# Agent Execution Log

| Timestamp (UTC) | Event | Actor | Summary | token_input | token_output | latency_ms |
|---|---|---|---|---:|---:|---:|
| 2026-06-12 14:59:44 | finding | agent | SMB admin$ share access from non-admin workstation |  |  |  |
| 2026-06-12 14:59:44 | finding | agent | Remote scheduled task creation via at.exe |  |  |  |
| 2026-06-12 14:59:44 | tool_call | tool | harness.seed_iocs |  |  |  |
| 2026-06-12 14:59:44 | llm_call | llm | llm_planner |  |  |  |
| 2026-06-12 14:59:44 | tool_call | tool | planner |  |  |  |
| 2026-06-12 14:59:44 | llm_call | llm | llm_verifier |  |  |  |
| 2026-06-12 14:59:44 | claim_verification | llm |  |  |  |  |
| 2026-06-12 14:59:44 | llm_call | llm | llm_self_corrector |  |  |  |
| 2026-06-12 14:59:44 | self_correction | llm | no issues; nothing to correct. |  |  |  |
| 2026-06-12 14:59:44 | report_emit | agent | s_lateral_smb |  |  |  |

## Summary

- total events: 10
- total input tokens: 0 (across 0 event(s))
- total output tokens: 0 (across 0 event(s))
- total wall clock: 0.003s
- self-corrections: 1
```

## 12. Reproduce it yourself

Everything above runs from a clean clone in a few minutes:

1. Install: run `install.sh` from the repository root (or `pip
   install -e ".[dev]"` in a Python 3.11+ virtualenv).
2. Follow [Try it out](../TRY-IT-OUT.md) for the audited
   command-by-command path; it is the authority if this document and
   the CLI ever disagree.
3. The bundle leg follows `scenarios/S04-offline-to-online-handoff.md`
   step by step; the input JSON in section 4 is all you need to type.

For the recorded version of this story, see the rehearsal script at
`demo/SCRIPT.md` and the condensed one-take plan at
`demo/SHOOTING-SCRIPT.md` in the repository.
