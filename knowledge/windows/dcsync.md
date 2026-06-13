---
id: kb-win-cred-dcsync-001
title: "DCSync — replicating Directory secrets from a non-DC account"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1003.006
artifact_types:
  - event_logs
  - network_traffic
tools:
  - evtx_dump
  - chainsaw
  - zeek
last_updated: "2026-04-19"
---

## What DCSync is

DCSync is an abuse of the directory-replication API: a principal that
has been granted `Replicating Directory Changes` / `Replicating Directory
Changes All` / `Replicating Directory Changes In Filtered Set` rights
can ask a domain controller to send the `NTDS.dit` secrets for any
user — including `krbtgt`. The DC responds as if another DC is
replicating, because from its perspective that is exactly what is
happening.

The primitive is valuable to attackers because:

- It requires no code execution on the DC itself.
- It leaves no disk-image evidence on the DC under normal flags.
- The rights can be delegated via AD ACEs and sometimes end up granted
  to groups that shouldn't have them.

## How to detect it

The canonical signal is Security event 4662 on a DC with the replication
GUIDs in `Properties`:

| GUID                                         | Right                                                |
|----------------------------------------------|------------------------------------------------------|
| `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}`     | Replicating Directory Changes                        |
| `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}`     | Replicating Directory Changes All                    |
| `{89e95b76-444d-4c62-991a-0facbeda640c}`     | Replicating Directory Changes In Filtered Set        |

A 4662 on a DC in which `Subject Account Name` is **not** another DC,
**and** the `Properties` field contains these GUIDs, is very strongly
consistent with DCSync.

Event 4742 (*Computer account changed*) or a large cluster of 4769
(Kerberos service ticket) right after a 4662 can suggest post-DCSync
ticket forging (Golden/Silver).

Network-side indicators (captured in pcap or Zeek):

- `DRSUAPI` RPC traffic (`e3514235-4b06-11d1-ab04-00c04fc2dcd2`) to a DC
  from a non-DC peer.
- SMB named-pipe `\PIPE\lsass` invoked by a non-DC host immediately
  before the DRSUAPI call.

## What APTWatcher records

A DCSync finding cites:

1. The 4662 event on the DC with the Replicating GUIDs in Properties
   (source=`Security.evtx` on DC, locator=`event_id=4662 record=<n>`).
2. The subject account name and host; if that host is not a DC, the
   finding is "confirmed by" rather than "consistent with".
3. If network evidence is present, the DRSUAPI session that preceded or
   accompanied the event (source=`zeek:dce_rpc.log`,
   locator=`uid=<connection id>`).
4. Any subsequent `krbtgt` password-change event (4781) would increase
   confidence further — attackers sometimes rotate after DCSync, but
   defenders doing post-compromise reset also trigger it, so use with
   care.

## Why this entry is careful about confidence

DCSync is not cryptographically provable from the DC's point of view —
the DC genuinely replicated. Confidence depends on whether the
replicating principal had a legitimate reason to do so. A plain 4662
with the right GUIDs on a known DC-to-DC sync is normal. The same
event from a workstation's service account is an incident.

APTWatcher caps a DCSync finding at `confidence=0.7` on a single 4662
unless network evidence or post-event Kerberos anomalies corroborate.
