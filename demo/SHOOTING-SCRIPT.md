# APTWatcher DFIR — one-take shooting script

*Target: 4:30 recorded in a single take. This is the condensed
recording plan; the full minute-by-minute rehearsal version with
fallback planning lives in [`SCRIPT.md`](SCRIPT.md). Every command
below was executed and its output captured in
`docs/demo/WALKTHROUGH.md` — if a take goes wrong, the walkthrough is
the written substitute for the video.*

## Pre-flight checklist (ten minutes before recording)

- Terminal at 120x32 minimum, dark theme, font at 16pt or larger.
  Rich tables wrap badly under 100 columns — test with
  `aptwatcher profiles` before recording.
- Fresh clone, clean `git status --porcelain`, virtualenv activated,
  `pip install -e ".[dev]"` done, `aptwatcher version` prints
  `aptwatcher 0.1.0a0`.
- `ANTHROPIC_API_KEY` unset; `env | grep -i anthropic` returns nothing.
- Directories prepared off-camera:
  `mkdir -p /tmp/s04/keys /tmp/s04/triage /tmp/s04/inbox`.
- Operator keypair generated off-camera with the
  `core.bundle.signer.generate_keypair` one-liner (see
  `docs/demo/WALKTHROUGH.md` section 4); private key at
  `/tmp/s04/keys/operator.ed25519`, public hex at
  `/tmp/s04/keys/operator.pub.hex`.
- Triage input staged at `/tmp/s04/triage/input.json` (three findings,
  five IOCs — copy from the walkthrough or the S04 scenario).
- Helper scripts staged: `verify_inbox.py` (the `import_bundle` call)
  and `tamper.py` (edits one digit of one IOC in the inbox copy).
- All commands pre-typed into shell history in reverse order, so
  up-arrow walks the take; `history -c` first, then seed.
- `rm -rf /tmp/s04/bundle /tmp/s04/oops /tmp/wt-eval` so no previous
  take leaks into the recording.
- One dry run of the full sequence completed today, green.

## Minute-by-minute

Each narration line is written to be spoken naturally in roughly 15
to 20 seconds while the command runs or its output sits on screen.

| Time | Command to type | Narration to speak |
|------|-----------------|--------------------|
| 0:00 | `aptwatcher version && aptwatcher profiles` | "This is APTWatcher, an autonomous defensive incident response agent built for the hackathon. Everything you'll see is one pip-installable CLI. These are its use-case profiles — each one is a contract listing exactly which forensic tools the agent may plan against. The planner never improvises a tool that isn't on this list." |
| 0:25 | `aptwatcher preflight --profile windows-host-triage` | "Before any triage, preflight probes the workstation for the profile's required tools. This recording box deliberately has none of them installed — and the agent says so and refuses to start, exit code one. No pretending, no hallucinated tool output. On a real SIFT workstation this same command comes back green." |
| 0:50 | `aptwatcher knowledge-search "lateral movement smb"` | "The agent grounds its planning in a clean-room knowledge base — thirty-two original entries, searched offline. Here, lateral movement over SMB comes back with five hits, each tagged with MITRE ATT&CK techniques that flow all the way through to the final report." |
| 1:15 | `aptwatcher analyze --input /tmp/s04/triage/input.json --output-dir /tmp/s04/bundle --campaign-tag S04-HANDOFF --incident-id INC-20260612-S04001 --sign --private-key-path /tmp/s04/keys/operator.ed25519` *(deliberately missing `--operator`)* | "Now the air-gap scenario. Triage produced three findings and five IOCs offline, and I'm asking the agent to fan them out into rules, reports, and a signed incident bundle. And — it refuses. I asked it to sign without saying who the operator is. An anonymously signed bundle is worthless downstream, so the guardrail stops me before any work happens. Let me correct that." |
| 1:50 | Up-arrow, add `--operator ir-analyst-01 --language en`, re-run | "Same command, with the operator named. Three findings, five IOCs, and the full output tree: YARA and Suricata rules, STIX and per-type IOC exports, the analyst report — and a five-file incident bundle signed with the operator's Ed25519 key. The private key never leaves the offline side; only conclusions cross the air gap." |
| 2:20 | `cp -r /tmp/s04/bundle/incident-bundle /tmp/s04/inbox/ && python verify_inbox.py` | "We're on the online workstation now. The importer re-derives every file digest, cross-checks the record counts, and verifies the signature against the pinned operator public key. Verified — three findings, five IOCs, and not one byte of raw evidence made the trip." |
| 2:45 | `python tamper.py && python verify_inbox.py` | "Now let's earn that trust. I change a single digit of one IOC inside the signed payload — dot-twelve becomes dot-thirteen, the JSON stays perfectly valid. And the importer rejects it: sha-256 mismatch on iocs-dot-json, expected digest, actual digest, named explicitly. One character, caught." |
| 3:15 | `cp /tmp/s04/bundle/incident-bundle/iocs.json /tmp/s04/inbox/incident-bundle/ && python verify_inbox.py --wrong-key` | "Restore the file, and try the other attack: present a bundle signed by somebody else. The signature gate rejects the mismatched public key before trusting a single record. Both failure modes are loud, specific, and audited — there is no silent drop." |
| 3:40 | `aptwatcher publish --bundle-dir /tmp/s04/inbox/incident-bundle --adapter stub --adapter stub --adapter stub` | "Publication is where mistakes become public, so it's dry-run by default — these three adapter calls stand in for a takedown provider, a sharing community, and a ticketing system, and none of them transmit anything. Going live requires an explicit no-dry-run flag plus a verified bundle. Safe is the default; loud is the override." |
| 4:05 | `aptwatcher eval --fixtures-dir tests/accuracy/fixtures --output-dir /tmp/wt-eval` | "Finally, the accuracy harness: eight scenarios replayed deterministically through the agent loop and scored against ground truth. Mean F1 of one point zero across findings and IOCs — and every run you just watched emitted a signed, append-only audit log that renders into a judge-readable timeline with one command. Read-only by default, consent-gated above that, and every claim backed by an event ID. That's APTWatcher." |
| 4:30 | *(cut)* | |

## Timing budget per beat

If a beat runs over, steal time from the next narration line, not
from the command output — viewers need to see the output land.

- 0:00–0:25 — version + profiles. The profiles table is tall; start
  speaking as it renders.
- 0:25–0:50 — preflight failure. Pause one beat on the red banner.
- 0:50–1:15 — knowledge search. Do not read the table aloud; gesture
  at the MITRE column.
- 1:15–1:50 — the failed analyze. Let the error sit on screen a full
  two seconds before speaking the correction line.
- 1:50–2:20 — corrected analyze + output tree. If `find` output
  scrolls, scroll back up to the incident-bundle files.
- 2:20–2:45 — verification pass.
- 2:45–3:15 — tamper rejection. This is the money shot; slow down.
- 3:15–3:40 — wrong-key rejection.
- 3:40–4:05 — publish, dry-run default.
- 4:05–4:30 — eval table + closing line over the Mean F1 row.

## If something breaks mid-take

- Preflight prints something other than the expected missing-tools
  banner: a SIFT tool snuck onto the recording box. Stop, do not
  improvise — the narration depends on the honest failure.
- The corrected analyze run fails: the staged input JSON is malformed
  or `/tmp/s04/bundle` was not cleaned. Abort the take, run the
  pre-flight checklist again from the top.
- `verify_inbox.py` fails on the good bundle: the inbox copy is stale
  from a previous take. `rm -rf /tmp/s04/inbox/incident-bundle` and
  re-copy.
- Eval prints anything below 1.000: do not record. Fix first. The
  baseline was green in the pre-flight checklist; a regression on
  camera means the working tree is dirty.
- Total disaster: `docs/demo/WALKTHROUGH.md` contains the captured
  output of every command in this script and ships with the
  submission as the written substitute.

## The self-correction beat

The rubric requires visible self-correction. It happens at 1:15: the
`analyze --sign` call is typed without `--operator`, the CLI rejects
it with a clean one-line error and exit code 1, and the very next
action corrects the flag and succeeds. This is real CLI behavior, not
staged output — the exact error text is `error: --sign requires
--operator <name>`, captured in `docs/demo/WALKTHROUGH.md` section 9.
The tamper rejection at 2:45 is the second, deeper instance of the
same story: the system catching a problem and saying exactly what is
wrong instead of carrying on.

If the take runs long, the cut priority is: trim the knowledge-search
narration first, then shorten the publish beat. Never cut the
missing-operator correction or the tamper rejection — those two are
the spine of the demo.
