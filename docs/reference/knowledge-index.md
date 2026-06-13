# Reference: Knowledge index

> Index of the `knowledge/` clean-room knowledge base. Entries are grouped
> by domain and tagged with their `source_type` for provenance. See
> [`knowledge/README.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/README.md) for the full
> licensing policy.

The knowledge base is APTWatcher's grounding surface. When the agent needs
context — *"what does a DCSync event look like in Security.evtx?"*, *"what
scheduled-task names are commonly used for masquerading?"* —
`knowledge_search()` is what it calls. Every entry is author-attributable,
every source type is declared, and nothing from proprietary sources is
present. See [clean-room policy](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/README.md) for the
absolute rules.

This index is generated from the committed corpus: **32 entries**, all
`source_type: author-original` (`attribution: "APTWatcher team (clean-room)"`).
The schema permits other source types (see `knowledge/README.md`), but none
are currently in use.

## Source-type legend

| Source type       | License / status                                |
|-------------------|-------------------------------------------------|
| `author-original` | MIT, written from scratch for this project      |

## Entries by domain

### Windows (6)

| Entry | Source type | MITRE techniques |
|-------|-------------|------------------|
| [`windows/dcsync.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/windows/dcsync.md) | `author-original` | T1003.006 |
| [`windows/kerberoasting.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/windows/kerberoasting.md) | `author-original` | T1558.003 |
| [`windows/masquerading-names.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/windows/masquerading-names.md) | `author-original` | T1036.005 |
| [`windows/scheduled-tasks.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/windows/scheduled-tasks.md) | `author-original` | T1053.005, T1036.005 |
| [`windows/smb-admin-share.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/windows/smb-admin-share.md) | `author-original` | T1021.002, T1570, T1569.002 |
| [`windows/vssadmin-shadows.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/windows/vssadmin-shadows.md) | `author-original` | T1490 |

### Linux (5)

| Entry | Source type | MITRE techniques |
|-------|-------------|------------------|
| [`linux/auth-log-triage.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/linux/auth-log-triage.md) | `author-original` | T1110, T1078.003, T1021.004, T1556.003 |
| [`linux/ssh-key-lateral.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/linux/ssh-key-lateral.md) | `author-original` | T1021.004, T1098.004, T1552.004, T1563.001 |
| [`linux/suid-abuse.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/linux/suid-abuse.md) | `author-original` | T1548.001, T1068 |
| [`linux/systemd-cron.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/linux/systemd-cron.md) | `author-original` | T1053.003, T1053.006, T1543.002 |
| [`linux/webshell-execution.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/linux/webshell-execution.md) | `author-original` | T1505.003, T1059.004, T1190, T1036.005 |

### macOS (2)

| Entry | Source type | MITRE techniques |
|-------|-------------|------------------|
| [`macos/launchagent-persistence.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/macos/launchagent-persistence.md) | `author-original` | T1543.001 |
| [`macos/launchd-plist.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/macos/launchd-plist.md) | `author-original` | T1543.001, T1547.011 |

### Memory (3)

| Entry | Source type | MITRE techniques |
|-------|-------------|------------------|
| [`memory/kernel-module.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/memory/kernel-module.md) | `author-original` | T1014, T1547.006, T1562.001 |
| [`memory/process-hollowing.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/memory/process-hollowing.md) | `author-original` | T1055.012, T1055.002, T1055 |
| [`memory/reflective-dll-injection.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/memory/reflective-dll-injection.md) | `author-original` | T1055.001 |

### Network (4)

| Entry | Source type | MITRE techniques |
|-------|-------------|------------------|
| [`network/beacon-jitter-dns-tunneling.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/network/beacon-jitter-dns-tunneling.md) | `author-original` | T1071.004, T1572 |
| [`network/beaconing-dns-tunneling.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/network/beaconing-dns-tunneling.md) | `author-original` | T1071.004, T1572, T1090, T1573 |
| [`network/c2-http-patterns.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/network/c2-http-patterns.md) | `author-original` | T1071.001, T1573.002, T1090.004, T1568.002 |
| [`network/lateral-smb-rpc.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/network/lateral-smb-rpc.md) | `author-original` | T1021.002, T1569.002, T1053.002, T1053.005, T1003.006, T1047 |

### Timeline (2)

| Entry | Source type | MITRE techniques |
|-------|-------------|------------------|
| [`timeline/evtx-logon-anomalies.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/timeline/evtx-logon-anomalies.md) | `author-original` | T1078, T1021, T1110, T1558 |
| [`timeline/mft-timestomping.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/timeline/mft-timestomping.md) | `author-original` | T1070.006 |

### Cloud (1)

| Entry | Source type | MITRE techniques |
|-------|-------------|------------------|
| [`cloud/aws-cloudtrail-iam-escalation.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/cloud/aws-cloudtrail-iam-escalation.md) | `author-original` | T1098, T1078.004 |

### Mobile (2)

| Entry | Source type | MITRE techniques |
|-------|-------------|------------------|
| [`mobile/imessage-artifacts.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/mobile/imessage-artifacts.md) | `author-original` | T1636.004, T1430, T1533 |
| [`mobile/ios-sysdiagnose.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/mobile/ios-sysdiagnose.md) | `author-original` | — |

### Procedures (operator playbooks) (7)

| Entry | Source type | MITRE techniques |
|-------|-------------|------------------|
| [`procedures/c2-beacon-identification.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/procedures/c2-beacon-identification.md) | `author-original` | T1071, T1071.001, T1071.004, T1573, T1572, T1568, T1090 |
| [`procedures/credential-theft-response.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/procedures/credential-theft-response.md) | `author-original` | T1003, T1003.001, T1003.006, T1552, T1558, T1078 |
| [`procedures/lateral-movement-containment.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/procedures/lateral-movement-containment.md) | `author-original` | T1021, T1021.001, T1021.002, T1021.006, T1570, T1563, T1047 |
| [`procedures/memory-triage-live-response.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/procedures/memory-triage-live-response.md) | `author-original` | T1055, T1055.002, T1055.012, T1003.001, T1620, T1027, T1140 |
| [`procedures/persistence-removal-windows.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/procedures/persistence-removal-windows.md) | `author-original` | T1547, T1547.001, T1053, T1053.005, T1543, T1543.003, T1546, T1574 |
| [`procedures/ransomware-initial-triage.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/procedures/ransomware-initial-triage.md) | `author-original` | T1486, T1489, T1490, T1491.001 |
| [`procedures/timeline-building-workflow.md`](https://github.com/aptwatcher/APTWatcher/blob/main/knowledge/procedures/timeline-building-workflow.md) | `author-original` | T1070, T1070.006, T1078, T1059, T1569 |

