---
id: kb-cloud-aws-cloudtrail-iam-escalation-001
title: "AWS CloudTrail triage for IAM privilege escalation"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1098
  - T1078.004
artifact_types:
  - cloudtrail_logs
tools:
  - aws cloudtrail lookup-events
  - athena
  - jq
last_updated: "2026-04-20"
---

## What CloudTrail captures and why it matters

CloudTrail is the authoritative record of control-plane API activity
in an AWS account: every `iam:*`, `sts:*`, and `organizations:*` call,
the identity that issued it, the source IP and user-agent, and the
request and response payloads for most events. For IAM privilege
escalation the log is often the only ground truth — IAM itself stores
the current state of users, roles, and policies, but not the sequence
of changes that produced that state.

The events that matter most for escalation triage are the ones that
either mint new credentials or expand existing ones:

- `CreateAccessKey` — mints a long-lived access key for a user.
  Pairs with an immediate key-based API call from an unfamiliar
  source IP.
- `AttachUserPolicy`, `AttachRolePolicy`, `AttachGroupPolicy` —
  attaches a managed policy (often `AdministratorAccess`) to an
  identity.
- `PutUserPolicy`, `PutRolePolicy` — writes an inline policy,
  frequently used to bypass policy boundaries that guard managed
  policies.
- `UpdateAssumeRolePolicy` — rewrites a role's trust policy. A trust
  policy that suddenly accepts an external account, a wildcarded
  principal, or the attacker's own user is the canonical backdoor.
- `PassRole`, surfaced as `iam:PassRole` in the authorization context
  of events like `RunInstances`, `CreateFunction`, or `StartBuild` —
  pre-condition for handing a higher-privilege role to a compute
  resource the attacker controls.
- `AssumeRole` from an identity that has never assumed that role
  before, especially when chained with a just-modified trust policy.

## Query patterns

Short lookups run against `aws cloudtrail lookup-events`, which is
bounded to the last 90 days and is rate-limited; it is adequate for
quick pivots but not for bulk analysis. For bulk work, query the
CloudTrail S3 bucket through Athena.

An Athena baseline partition layout exposes the trail as a table with
columns including `eventtime`, `eventname`, `eventsource`,
`useridentity.arn`, `sourceipaddress`, `useragent`, `requestparameters`,
and `responseelements`. A useful time-windowed pattern:

```sql
SELECT eventtime, eventname, useridentity.arn AS actor,
       sourceipaddress, useragent, requestparameters
  FROM cloudtrail
 WHERE eventtime BETWEEN '<start>' AND '<end>'
   AND eventname IN (
        'CreateAccessKey', 'AttachUserPolicy', 'AttachRolePolicy',
        'PutUserPolicy', 'PutRolePolicy', 'UpdateAssumeRolePolicy',
        'PassRole'
   )
 ORDER BY eventtime;
```

Join the result by `sourceipaddress` and `useragent` to cluster
activity that shares an operator workstation or an automation tool.
Pipe JSON output through `jq` to pull `requestparameters.policyName`
and `requestparameters.userName` without a second query round-trip.

## Signals beyond the event name

`eventSource` occasionally disagrees with `eventName` in ways that
expose automated tooling. Console-originated actions normally show
`signin.amazonaws.com` in adjacent login events and a browser
user-agent; when the same actor emits console-attributed IAM changes
from a CLI user-agent (`aws-cli/2.x` or an SDK signature) within the
same session window, treat the session as assumed-compromised and
pivot on the credentials in use.

Chain analysis is more informative than single events. The classic
escalation path is:

1. Attacker compromises a low-privilege identity.
2. `PassRole` is granted or discovered on a higher-privilege role.
3. The attacker runs a service (`RunInstances`, `CreateFunction`)
   that takes that role.
4. The service calls `AssumeRole` and now holds the higher
   privileges.

Treat co-occurrence of `PassRole` authorization and a subsequent
`AssumeRole` by the spawned resource as a single finding, not two.

## Retention and hygiene

Default CloudTrail event history in the console covers 90 days only.
For IR work, configure a dedicated trail delivering to an S3 bucket
with at least 365 days of retention, log-file validation enabled, and
MFA-delete on the bucket. Parallel delivery to a SIEM is recommended
but does not replace the S3-of-record.
