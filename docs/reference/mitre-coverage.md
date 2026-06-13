# Reference: MITRE ATT&CK coverage

> Full technique matrix across the three scenarios. This page is the
> authoritative answer to "which techniques does APTWatcher demonstrate
> detection for?"

Coverage here means: *the scenario's ground truth contains artifacts that
exercise the technique, and the rubric requires the agent to surface
them with the correct MITRE mapping*. It does not mean APTWatcher can
detect every instance of the technique in the wild — no finite scenario
set can.

## Coverage matrix

Rows are techniques. Columns are the three scenarios.

| Tactic              | Technique                                          | ID         | S01 | S02 | S03 |
|---------------------|----------------------------------------------------|------------|-----|-----|-----|
| Initial Access      | Phishing: Spearphishing Link                       | T1566.002  | ✓   |     |     |
| Initial Access      | Valid Accounts: Domain Accounts                    | T1078.002  |     | ✓   |     |
| Initial Access      | External Remote Services                           | T1133      |     |     | (back-story) |
| Execution           | Windows Management Instrumentation                 | T1047      |     | ✓   |     |
| Execution           | User Execution: Malicious File                     | T1204.002  |     | ✓   |     |
| Persistence         | Scheduled Task/Job: Scheduled Task                 | T1053.005  | ✓   | ✓   |     |
| Persistence         | Boot or Logon Autostart Execution                  | T1547      |     |     | ✓*  |
| Privilege Escalation| Access Token Manipulation                          | T1134      |     |     | ✓   |
| Defense Evasion     | Masquerading: Match Legitimate Name or Location    | T1036.005  | ✓   |     | ✓   |
| Defense Evasion     | Process Injection: PE Injection                    | T1055.002  |     |     | ✓   |
| Defense Evasion     | Indicator Removal: Clear Windows Event Logs        | T1070.001  |     |     | (optional) |
| Credential Access   | OS Credential Dumping: LSASS Memory                | T1003.001  | ✓   | ✓   |     |
| Credential Access   | OS Credential Dumping: DCSync                      | T1003.006  |     | ✓   |     |
| Credential Access   | Steal or Forge Kerberos Tickets: Kerberoasting     | T1558.003  |     | ✓   |     |
| Discovery           | System Information Discovery                       | T1082      |     |     | ✓   |
| Discovery           | File and Directory Discovery                       | T1083      |     |     | ✓   |
| Lateral Movement    | Remote Services: Remote Desktop Protocol           | T1021.001  | ✓   |     |     |
| Lateral Movement    | Remote Services: SMB/Windows Admin Shares          | T1021.002  |     | ✓   |     |
| Lateral Movement    | Remote Services: DCOM                              | T1021.003  |     |     | ✓   |
| Collection          | Data from Network Shared Drive                     | T1039      |     | ✓   |     |
| Collection          | Data Staged: Local Data Staging                    | T1074.001  | ✓   | ✓   |     |
| Command and Control | Application Layer Protocol: Web Protocols          | T1071.001  |     |     | ✓   |
| Impact              | Inhibit System Recovery                            | T1490      |     |     | ✓   |
| Impact              | Data Encrypted for Impact                          | T1486      |     |     | ✓   |

`*` = surfaced as secondary evidence, not the primary finding.
`(back-story)` = part of the scenario's narrative but not scored by the
rubric (the initial access vector is outside the evidence window).

## Tactic coverage summary

| Tactic               | Techniques covered |
|----------------------|-------------------:|
| Initial Access       | 3                  |
| Execution            | 2                  |
| Persistence          | 2                  |
| Privilege Escalation | 1                  |
| Defense Evasion      | 3                  |
| Credential Access    | 3                  |
| Discovery            | 2                  |
| Lateral Movement     | 3                  |
| Collection           | 2                  |
| Command and Control  | 1                  |
| Impact               | 2                  |

Total distinct techniques: **24** across the three scenarios.

## What "demonstrated" means for the rubric

For each ✓ entry, the scenario's rubric requires that the agent:

1. Surface the artifact that evidences the technique.
2. Map it to the correct MITRE technique ID.
3. Phrase the mapping as *"consistent with T1003.006 (DCSync)"* rather
   than as a categorical causation claim.

A wrong-technique mapping costs the scenario an item even if the
artifact was correctly surfaced. A correct mapping with a hallucinated
artifact is a hard fail (see [self-correction](../architecture/self-correction.md)).

## Gaps — deliberate

MITRE ATT&CK Enterprise v15 has ~200 techniques. Three scenarios cover
24 — ~12%. The selection is deliberate:

- Every selected technique is well-evidenced in standard SIFT triage
  output. If the technique requires an artifact SIFT does not surface,
  it is not a fair rubric item for the MVP.
- Every selected technique has a well-known detection signal. The demo
  is not a research contribution; it shows the agent doing the
  known-good thing reliably.
- Coverage spans the attack lifecycle (initial access through impact).
  No tactic is entirely missing — the demo cannot leave a gap that makes
  APTWatcher look narrow.

## Gaps — future work

Techniques that would enrich the matrix but that the MVP does not cover:

- `T1105` — Ingress Tool Transfer (PowerShell-based downloaders)
- `T1562.001` — Disable Security Tools
- `T1136.001` — Create Account: Local Account
- `T1098.004` — Account Manipulation: SSH Authorized Keys (Linux)

These are candidates for a post-hackathon scenario set.

## Related

- [Scenarios](../scenarios/README.md) — scenario-level MITRE breakdowns
- [Knowledge index](knowledge-index.md) — which `knowledge/` entries
  ground each technique's detection signal
- [MCP tools](mcp-tools.md) — which tools surface each technique's
  artifact
