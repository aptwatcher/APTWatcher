---
id: kb-mobile-ios-imessage-001
title: "iOS iMessage artifacts — sms.db / chat.db structure review for mobile triage"
source_type: author-original
attribution: "APTWatcher team (clean-room)"
mitre_techniques:
  - T1636.004
  - T1430
  - T1533
artifact_types:
  - sqlite
  - imessage_db
  - attachments
  - manifest_plist
tools:
  - sqlite3
  - iLEAPP
  - plutil
last_updated: "2026-04-19"
---

## What iMessage stores on an iOS device

On-device, SMS and iMessage history lives in a single SQLite database
at `~/Library/SMS/sms.db` (referred to as `chat.db` on some build
variants and in older tooling — the schema is the same). The key
tables a triage reviewer cares about are:

- `message` — one row per SMS or iMessage, with `ROWID`, `guid`,
  `handle_id`, `text`, `service` (`iMessage` or `SMS`), `is_from_me`,
  `date`, `date_read`.
- `chat` — one row per conversation (1:1 or group), with `guid`,
  `chat_identifier`, `display_name`, `service_name`, `room_name`.
- `chat_message_join` — many-to-many link between `chat.ROWID` and
  `message.ROWID`.
- `attachment` — one row per attached file: `ROWID`, `guid`,
  `filename`, `mime_type`, `transfer_name`, `total_bytes`.
- `message_attachment_join` — link between `message.ROWID` and
  `attachment.ROWID`.
- `handle` — contact identifiers, one row per phone number or email
  address the device has ever exchanged messages with.

Attachment payloads live under
`~/Library/SMS/Attachments/<xx>/<yy>/<GUID>/<filename>`, where `xx`
and `yy` are two-character hex shards derived from the GUID. In an
iTunes-style logical backup, this tree is flattened into hashed
filenames on disk. The mapping is kept in `Manifest.db` (SQLite,
table `Files`), where `fileID` is the SHA-1-derived hash used as the
on-disk filename and `relativePath` gives the logical path the file
had on the device; `domain` is usually `HomeDomain` for SMS
artifacts. Encrypted backups encrypt `Manifest.db` itself, so the
password is required before any query.

## How to review it on an acquisition

Start with `Manifest.db`, not with the hashed blobs:

```sql
SELECT fileID, relativePath FROM Files
 WHERE relativePath = 'Library/SMS/sms.db'
    OR relativePath LIKE 'Library/SMS/sms.db-%'
    OR relativePath LIKE 'Library/SMS/Attachments/%';
```

Copy the resolved `sms.db`, plus any `-wal` and `-shm` companions,
into an evidence staging area and open read-only with
`sqlite3 -readonly sms.db`.

Useful structural queries (no message text is read):

- Message counts per `handle_id` bucketed by month, to surface
  activity bursts aligned with the suspected compromise window.
- Attachment count and cumulative `total_bytes` per `handle.id`,
  joined via `message_attachment_join` and `chat_message_join`.
- Attachment distribution by `mime_type` (images, video, PDFs,
  vcards, archives, unknown).
- Orphan rows: entries in `message_attachment_join` whose
  `message_id` no longer resolves to a row in `message`, or rows in
  `attachment` with no matching join — both are deletion markers.
- Inbound messages with `is_from_me = 0` and `service = 'iMessage'`
  from a `handle_id` not present in the device address book.
- Messages carrying URL previews (`balloon_bundle_id` set) pointing
  at domains that do not match normal contacts or vendor domains.

For each attachment GUID, resolve its expected hashed filename via
`Manifest.db` and confirm the blob is present on disk. A referenced
GUID with no corresponding file is itself a triage signal.

## What APTWatcher records

The agent does not decrypt or read message text. The mobile-host
triage profile explicitly refuses to dump `message.text`,
`attributedBody`, or any `payload_data` content. What it records,
per finding, is structural:

1. Absolute path of `Manifest.db` and `sms.db` inside the backup
   tree, plus SHA-256 of each file.
2. Row counts for `message`, `chat`, `attachment`, `handle`,
   `chat_message_join`, `message_attachment_join`.
3. Top-20 `handle.id` values by message volume, each with inbound
   count, outbound count, attachment count, and cumulative bytes.
4. Attachment inventory: `mime_type` counts and cumulative bytes,
   plus top-10 attachments by size (GUID and MIME type only).
5. Orphan-row count across both join tables, flagged as suggestive
   of remote deletion.
6. Count of referenced attachment GUIDs whose hashed blob is
   missing from the backup tree.
7. Presence of Business Chat and Apple Pay message types, since
   both legitimately inflate attachment and balloon counts.
8. For encrypted backups without the password: SHA-256 of the
   encrypted `Manifest.db` and `sms.db`, and a deferred note.

Handle identifiers are phone numbers or email addresses and are treated as PII — included verbatim only in the sealed evidence bundle, redacted in summary output.

## Confidence calibration and pitfalls

iMessage traffic is bi-directional, so a foreign handle is not on
its own a compromise signal — the user may have received a wrong
number, a marketing iMessage, or a Business Chat reply. Tier up only
when foreign-handle activity clusters with other findings (unexpected
configuration profile, MDM change, Safari history anomalies).

Orphan attachment rows are real but ambiguous: legitimate deletion
clears `message` rows while join entries can linger briefly, and
iCloud Messages sync can remove content locally after a server-side
delete. Treat a non-zero count as suggestive, not conclusive.

Group chats produce many-to-many joins through `chat_message_join`
and will inflate per-handle counts if aggregated naively — aggregate
per `chat.guid` first, then per handle, to avoid double-counting.
Business Chat and Apple Pay conversations produce high attachment
and balloon-bundle counts as a matter of normal operation; exclude
them before computing the top-20 handle table, or annotate which
rows are business endpoints.

Encrypted backups cannot be queried without the backup password —
`Manifest.db` itself is encrypted. The agent records file hashes,
notes the encrypted-backup state, and defers structural review until
the password is provided through a separate channel. It does not
attempt to crack the password.
