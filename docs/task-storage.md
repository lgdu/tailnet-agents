# Local task storage admission (v0.34)

Signed Echo callers and Human UI consent history now have local admission budgets.
They stop accepting new records without deleting existing history, changing keys/
groups, selecting another executor or replaying uncertain work. These are logical
payload budgets with recovery reservations, **not physical SQLite/disk quotas**.
The executor's existing [four row quotas](task-history.md#configure-bounded-admission)
remain separate and unchanged. Legacy bearer tasks are outside these budgets.

## Caller configuration

Use these startup options before the existing `tailnet-tasks` subcommand:

```bash
tailnet-tasks [original identity/group/source/state options] \
  --capacity 256 --history-capacity 10000 \
  --byte-capacity 268435456 --review-capacity 10000 storage
```

The bracketed words above stand for the existing required caller arguments; retain
their original values. Library users pass `capacity`, `history_capacity`,
`byte_capacity`, `review_capacity` as `TaskClient` keyword arguments. Signed MCP
and the Human UI's caller configuration accept an optional exact integer object:

```json
"storage_limits": {
  "capacity": 256,
  "history_capacity": 10000,
  "byte_capacity": 268435456,
  "review_capacity": 10000
}
```

Add this object to the existing private [caller configuration](task-mcp.md#configure-the-original-identity-and-fixed-executor).
Omitted fields use defaults. Unknown keys, booleans, floats and numeric strings
fail before caller state is opened; tool/browser arguments cannot change limits.

| Limit | Default | What counts |
|---|---|---|
| `capacity` | 256 | Unresolved original tasks: pending, queued, running, uncertain, including unresolved cancellation barriers |
| `history_capacity` | 10000 | Every original caller task, including completed/failed/cancelled and executor-archived results |
| `byte_capacity` | 268435456 (256 MiB) | Charged original intent bytes, receipt/cancellation recovery reservations and retained review bytes |
| `review_capacity` | 10000 | All caller-signed local advisory review records |

Count limits accept 1..100000; byte limits accept 1..1073741824. They are independent:
a history/byte budget can bind before the unresolved-task count. A tiny valid byte
budget can admit no task. `uncertain` keeps an unresolved slot because it does not
prove absence of a side effect; no quota decision authorizes a replacement intent.
Completed/failed/cancelled receipts release only the unresolved slot. Remote
archival keeps caller history, byte charge and the original receipt intact.

## Charged bytes and recovery

For each caller task, charge the UTF-8 byte length of its signed original token
plus **16640 bytes**: a 16384-byte receipt reservation (the existing signed-token
verification bound) and 256 bytes for task/cancellation metadata. The reservation
stays charged after a receipt/cancellation is saved; it is not returned for reuse.
Each review charges its exact signed-token bytes plus 64 bytes for its two IDs.
Legacy receipts larger than the reservation contribute their excess to reported
usage, without being deleted; signature verification still governs actual reads.

Admission checks and insertion share one SQLite transaction under the existing
caller/file lock. Distinct concurrent new IDs cannot over-admit. Same-ID/input
queue recovery happens before admission, and changed reuse conflicts. Review
retries retain the original signature before checking new-review admission.
Existing reads, submit/retry/refresh, cancellation barriers, receipt persistence
and eligible archival do not require another admission slot, even if startup
limits are lowered below occupancy. SQL or real disk failures can still prevent
commit: retain the original intent/barrier and retry explicitly after recovery.

`tailnet-tasks storage` reports `limits`, `usage` (`tasks`, `active`, `reviews`,
`charged_bytes`), `receipt_reserve_per_task` and `physical_disk_limit: false`.
The older `status` count schema is unchanged. Signed MCP's existing
`signed_task_status` adds a `storage` object; its tool schemas/catalog stay fixed.
MCP reports a sanitized capacity error for rejected new records. No query sends
pending work or contacts an executor.

## Human UI consent budgets

Configure the existing explicit Human task gateway with:

```bash
  --task-bindings-file /absolute/private/task-bindings.json \
  --task-consent-capacity 10000 \
  --task-consent-byte-capacity 67108864
```

These apply separately to each configured `(binding ID, Human ID)`; they are not
machine/IP/device quotas. All retained preview/started/done/expired rows count.
The same count/byte ranges above apply. Each consent charges its exact stored
payload/preview UTF-8 bytes plus **33280 bytes**: 32768 for the bounded Echo result
and 512 for metadata. Saved results larger than the reservation add their excess
to reported legacy usage. Results produced by this version must fit the reserved
Echo result bound; an oversized response leaves the original started consent for
inspection/recovery rather than saving an unbounded result.

New-preview admission and insertion are atomic. An identical saved preview ID
recovers before admission, and existing confirmation/retry/result commits remain
available at/above quota. New records return HTTP **429**. Preview expiry, task
completion and archival never delete a consent or release its history charge.

**A new cancellation/refresh/archive preview is also a new consent record.** At a
full UI history budget it is denied; the gateway never bypasses Human confirmation
to perform it. Read history and retry an already saved confirmation, or explicitly
increase configured limits and restart with the original bindings. If a new
cancellation is needed without admitting a UI preview, stop the UI, then use the
existing Human-operated CLI cancellation with the same caller key/group/outbox.
Caller cancellation remains available above its admission budgets. Do not clear
history, switch identities/executors or allocate another task to recover capacity.

The task panel's **读取本地容量** explicitly reads both caller and consent limits/
usage. Its `POST /api/task-read` operation is `storage`, with only original
`group_id`, `binding_id`, `operation`. Existing Human role/group/binding checks
apply. This local read does not create a preview, grant rights or contact an
executor. Same-host Agent bindings retain independent caller and consent budgets.

## Restart, compatibility and limits

Limits are validated startup configuration, not persisted membership policy or
identity bindings. Preserve overrides in service/config files: omitting them
restores defaults. Raising/lowering limits retains original data and contexts;
usage is recomputed from saved rows. No new caller/executor marker, database schema
or task wire format is introduced, and earlier one-way migrations still apply.
Older versions do not enforce these new local budgets; do not use them as a
quota bypass. Older MCP config readers reject the new optional configuration key.

Keep complete consistent UI/caller/executor backups and original keys, grants,
pins, CA and policy/revocation history. No history pruning, payload compaction,
automatic retention, rollback/disk-loss repair or key-clone reconciliation is
provided. Directory/chat tables, indexes, free pages, WAL/journals, backups and
other processes are outside the charged budget; operational disk monitoring and
filesystem capacity remain necessary. A full real disk can still block recovery.

This uses simulated Echo identities with actual loopback HTTP/TLS/stdio and
browser tests. It adds no real Agent adapter, group enrollment, discovery-based
permission, automatic execution, running stop, verified uncertain resolution,
external Human session, HA or physical LAN/Tailscale validation.

In v0.35, Human UI uncertainty reviews use these same caller review/byte and UI
consent budgets. The exact saved Human consent ID is the review request ID. A
started review whose caller write committed before the UI acknowledgment recovers
the original signature above quota; a genuinely new note still needs admission.
No review frees the unresolved task slot or changes the original signed receipt.
