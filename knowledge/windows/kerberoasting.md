---
id: kb-win-cred-kerberoast-001
title: "Kerberoasting — offline cracking of service account credentials"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1558.003
artifact_types:
  - event_logs
  - network_traffic
tools:
  - evtx_dump
  - chainsaw
  - hayabusa
  - zeek
last_updated: "2026-04-19"
---

## What Kerberoasting is

A principal requests a Kerberos service ticket (TGS) for a service that
has a Service Principal Name (SPN) registered under a user account
(i.e., not a computer account). The KDC returns the TGS encrypted with
the service account's NTLM-derived key. The attacker takes the TGS
offline and attempts to recover the account password by brute-force or
dictionary attack.

The attack is valuable because:

- Any authenticated domain user can request tickets for any SPN —
  requesting is normal traffic.
- Service accounts with weak passwords (still common) fall in seconds
  to `hashcat -m 13100`.
- Once cracked, the attacker has the account's cleartext password and
  can authenticate anywhere that account has rights.

## How to detect it

The signal is Security event 4769 (TGS request) with specific features:

- `Ticket Options` includes encryption flag `0x0` or `0x1` indicating
  `RC4-HMAC` (older DES/RC4) rather than AES-256. Attacker tools often
  request RC4 to keep cracking fast.
- `Service Name` points at a user account (i.e., the SPN is registered
  on a user, not a computer).
- A single user account requesting an abnormally high number of SPNs in
  a short window — a scripted enumeration signature.

Useful variants:

| Event ID | Log             | Meaning                                 |
|----------|-----------------|-----------------------------------------|
| 4768     | Security.evtx   | TGT request                             |
| 4769     | Security.evtx   | TGS request (Kerberoasting signal)      |
| 4770     | Security.evtx   | TGS renewed                             |
| 4776     | Security.evtx   | NTLM fallback — often paired with RC4   |

Network-side, a spike of Kerberos `AS-REP`/`TGS-REP` traffic (port 88)
from one client in a short window is the same signal seen from the
wire.

## What APTWatcher records

A Kerberoasting finding cites:

1. The cluster of 4769 events from the same principal in a short
   window (source=`Security.evtx` on the KDC, locator=`event_id=4769
   account=<name> count=<n>`).
2. The encryption type returned (RC4-HMAC → higher confidence).
3. The service accounts whose SPNs were queried (evidence of
   reconnaissance, independent of whether cracking succeeded).
4. If present, subsequent 4624 logons as one of the queried service
   accounts from an unusual source — consistent with a crack having
   succeeded.

## Confidence calibration

- Request pattern only, no follow-on logons: `confidence <= 0.5` —
  Kerberoasting *intent* is likely but cracking success is not proven.
- Request pattern + follow-on logon from unusual source as the service
  account: `confidence <= 0.8` — consistent with a successful crack.
- Request pattern + follow-on logon + clear impact (lateral movement
  using that account): can go higher, but only with each step cited
  independently.

## Common pitfalls

- **Legitimate scanners generate the same pattern.** A PowerShell or
  BloodHound run by the blue team looks identical. Correlate with
  ticketing / change management before raising confidence.
- **AES-only environments hide the signal.** If the domain enforces
  AES and the account is AES-enabled, the RC4 flag is missing. The
  request-volume heuristic still applies.
