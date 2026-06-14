# APTWatcher DFIR — announcement templates (post-submission)

> Templates for the post-submission announcement (checklist §7).
> Fill the bracketed placeholders before posting. Keep claims aligned
> with the verified numbers in `README.md`.

## Short post (X / Mastodon / Bluesky, ≤280 chars)

> We just shipped APTWatcher to the FIND EVIL! hackathon: an autonomous
> defensive IR agent for the SIFT workstation. Read-only by default,
> Ed25519-signed incident bundles, 51 MCP tools, 746 tests.
> Code (MIT): [REPO_URL] — demo: [VIDEO_URL]

## LinkedIn / blog post (longer form)

**Title:** APTWatcher — an autonomous, evidence-safe IR agent on the SIFT workstation

Attackers now operate at machine speed; defenders still triage by hand.
APTWatcher is our answer for the FIND EVIL! hackathon: an AI agent that
triages compromised hosts, correlates forensic artifacts with live threat
intelligence, and produces analyst-grade incident reports — without
hallucinating and without touching the evidence.

Highlights:

- Strict read-only evidence mode by default; every state-changing action
  is consent-gated and audit-logged with pre/post hashes.
- Offline → online handoff: the air-gapped analysis ends in a signed,
  portable IncidentBundle (Ed25519) that a live-side agent can verify and
  act on — tamper detection included.
- 51 MCP tools over 10 SIFT forensic suites, 3 deployment modes, a
  clean-room knowledge base, and an accuracy harness with golden fixtures.
- 746 passing tests, lint- and type-clean, MIT licensed.

Try it: [REPO_URL] (one-line install) — 5-minute demo: [VIDEO_URL]
Devpost: [DEVPOST_URL]

Thanks to the organizers and sponsors of FIND EVIL! for a sharp, rubric-
driven competition, and to everyone who reviewed the design along the way.

## Thank-you note to sponsors (email / DM)

Subject: Thank you — FIND EVIL! submission (APTWatcher)

Hello [NAME],

Thank you for sponsoring the FIND EVIL! hackathon. Building APTWatcher —
an autonomous, evidence-safe IR agent for the SIFT workstation — pushed
us to take agent guardrails seriously: read-only defaults, consent
gating, signed audit logs and signed incident bundles.

The project is public under MIT at [REPO_URL]; the 5-minute demo is at
[VIDEO_URL]. Feedback is welcome — the issue tracker is open.

Best regards,
[AUTHOR]
