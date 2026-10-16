# Explicit task archives and quotas (v0.31)

The signed simulation executor has an active area and an archive in the **same
private SQLite database**. Explicitly archiving a completed, failed or cancelled
task moves its entire original row atomically. Its ID, caller, signed input,
terminal status and byte-identical signed receipt remain available for authorized
reads and duplicate submissions after restart. Archiving never runs a task.

This frees active admission slots. It does **not** delete input/output, reduce
disk usage, export data, erase backups or authorize replay. There is no automatic
archive, age-based selection or eviction. Pending, queued, running and uncertain
tasks cannot be archived. Uncertain work stays visible in the active area even
after a caller adds an advisory review. Never delete either table or reset a task
to bypass a quota; doing so invalidates durable deduplication.

## Preview and confirm one original task

Use the original keys/group/grant, source, audience, executor public pin, TLS CA
and caller state described in [durable tasks](durable-tasks.md#caller-commands).
First download the original terminal receipt with `refresh` if needed. The local
preview neither contacts the executor nor changes task state:

```bash
task_client archive-preview --task-id "$TASK_ID"

# Copy the original request_hash and receipt_hash printed by the preview.
task_client archive --task-id "$TASK_ID" \
  --request-hash "$REQUEST_HASH" --receipt-hash "$RECEIPT_HASH" \
  --confirm-task-id "$TASK_ID"
```

Preview reports `eligible`, `observed_state`, `payload_retained: true` and
`remote_state_checked: false`; it does not establish current remote placement or
authorization. Confirmation repeats the exact ID and both hashes. The archive
request sends the original signed input, so it is not a local privacy action.
Both caller and executor still require current approved `task.echo` credentials,
policy/revocation checks and a fresh archive-bound possession proof. A discovery
candidate, read token, metadata probe or another group member cannot archive it.

The response contains the unchanged signed terminal receipt and `archived: true`.
The placement flag is authenticated transport metadata, not a separate signed
archival attestation. Caller verification checks the original executor/context,
request hash and immutable saved terminal receipt before accepting it. CLI output
also states `payload_retained: true`. The caller does not persist an archive flag;
its original result, terminal state and cancellation barrier remain intact.

`get`, `submit` and `cancel` response schemas are unchanged. `show`, `refresh` and
local lists still show the original outcome, without a new task state. Repeating
the same archive request is safe even after a lost response, failed local receipt
commit or restart. SQL insertion/removal is one transaction under the directory
lock: failures leave the record in its original area. A post-commit authorization
denial may leave it archived without an ACK; query/retry the original task after
human-controlled authorization recovery. No error authorizes a new task ID.

## Configure bounded admission

Add these options to the existing explicit `--tasks` service invocation:

```bash
  --task-capacity 256 \
  --task-history-capacity 10000 \
  --task-caller-capacity 64 \
  --task-caller-history-capacity 1000
```

| Limit | What counts | Default | Allowed |
|---|---|---|---|
| `--task-capacity` | All active rows, including terminal/uncertain rows and cancellation tombstones | 256 | 1..10000 |
| `--task-history-capacity` | All active + archived rows | 10000 | 1..100000 |
| `--task-caller-capacity` | Active rows for this caller public-key identity | min(64, active limit) | 1..10000 |
| `--task-caller-history-capacity` | Active + archived rows for this caller identity | min(1000, history limit) | 1..100000 |

All four limits apply before accepting a **new ID**, whether submit or an absent
intent cancellation tombstone. Existing reads, original duplicate submissions,
queued cancellation and eligible archival still work at/above quota. Archiving
frees global/caller active slots, while both history counts remain unchanged. A
full history quota therefore continues returning 429 for new IDs after archival.
The limits are independent; a smaller history limit may bind before an active
limit. The existing bounded request/receipt sizes remain in force.

These executor options are row-count admission quotas, not rate limits, byte/disk quotas, worker
concurrency limits or caller-outbox/review quotas. One caller may still exhaust a
shared global limit. Same-host callers with different approved keys have separate
caller quotas; hostname/IP/Tailscale device never identifies the subject. Separate
executors have separate databases/archives/limits. Archival issues no membership,
credentials or machine-wide permissions.

Quotas are validated startup/library configuration, not persisted policy. Keep
them in service startup configuration; omitting an option restores its default.
An operator may explicitly change bounds within the allowed ranges on restart
with the original state. Lowering below existing occupancy preserves all rows and
denies new IDs until applicable limits permit them. No restart silently evicts or
archives history. Protect capacity from disk exhaustion using operational storage
monitoring; other directory tables and SQLite overhead are outside these quotas.

## Upgrade, backup and compatibility

Before starting v0.31, back up the complete executor SQLite using its backup API,
and protect original key/grant references and caller state. Opening the executor
performs a **one-way executor-state migration**, even without archival: its bound
adapter/storage field changes from `echo-v1` to `echo-v1/task-history-v1`. The Echo
adapter and advertised contract remain `echo-v1`. The marker prevents older
executors, which only inspect the active table, from starting and missing archived
IDs. Unknown formats, conflicting identity/audience and overlapping/corrupt archive
history fail closed. Do not remove the marker or restore old state to replay work.

The caller retains the v0.30 `task-operations-v1` format and its existing
[one-way migration](task-operations.md#upgrade-and-recovery). v0.30 callers can
still submit/query/cancel against the new service; archival commands require the
new caller. Older services reject archive operations without changing task state.
Keep all active/archive tables together with directory policy/revocation history.
No migration generates keys/groups, selects a different executor or executes work.

## Validation and remaining scope

Tests exercise actual HTTP/TLS and service/client CLIs, same-host caller/executor
isolation, four admission limits, signed receipt preservation, late submissions,
cancelled tombstones, lost ACK/local commit failures, archive transaction rollback,
concurrent reads/retries, current authorization and format/integrity recovery.

Payload deletion/compaction, archive export/import, automatic retention, executor
byte/disk quotas, scheduling/rate limiting, running-task cancellation, verified
uncertain outcome resolution, external Human sessions, HA, real product adapters and
physical LAN/Tailscale trials remain unimplemented. Trusted history and consistent
backups are still required; rollback, disk loss and cloned-key recovery are not solved.

v0.32 exposes the same preview/confirmed archive through a separate fixed
[signed-task MCP caller](task-mcp.md). Placement remains authenticated response
metadata; no payload deletion, new authority or result state is introduced.

The v0.33 [Human task UI](task-ui.md) separately exposes explicit signed Echo
operations with actor-bound preview/confirmation and original-intent recovery.
It never dispatches simulated chat or converts MCP arguments into Human consent.

The separate v0.34 [local task budgets](task-storage.md) bound caller/review and
Human consent admission with recovery reservations. Executor archive/row quotas
remain unchanged; caller archival does not free retained caller payload charge.
