# Explicit task cancellation and uncertainty notes (v0.30)

These operations use existing simulated caller/executor identities, original group,
configured LAN/Tailscale origin and private state. They never create a group, grant,
Agent identity or replacement task. Real products remain unavailable. Actual
network operations still require both principals' current approved `task.echo`
grants, fresh policy, learned revocation checks and an operation-bound proof.
Directory read credentials, discovery and adapter metadata confer no task rights.

## Preview and confirm cancellation

Use the `task_client` shell helper from [durable tasks](durable-tasks.md#caller-commands),
or the installed `tailnet-tasks` command with the same existing pins/keys/state:

```bash
# Local read: inspect the exact original task, executor and request hash.
task_client cancel-preview --task-id "$TASK_ID"

# Copy request_hash from that preview; confirm the original ID explicitly.
task_client cancel --task-id "$TASK_ID" \
  --request-hash "$REQUEST_HASH" --confirm-task-id "$TASK_ID"

task_client status
task_client show --task-id "$TASK_ID"
```

Preview neither contacts the service nor changes a task. It reports local observed
state, eligibility, request hash, executor and `sends_original_task: true`.
`pending` means no receipt is saved locally, not proof the service never received
or started work. Confirmation sends the **original signed intent, including its
input**, to that original trusted executor. This is not merely a local delete.
It creates no new task ID or intent and cannot choose a different executor.

The caller commits `task_cancellations` **before** network I/O. Once saved, `flush`
will not submit this intent, including after transport/authorization/storage errors,
a refresh reporting queued, or process restart. Show/list/receipt views retain
`cancellation_requested: true`; `status` counts nonterminal such tasks as
`cancel_pending`. That local view means a cancellation request is unresolved, not
that execution stopped. `refresh` only queries, and never clears the barrier.
There is no resume/clear-barrier operation in this release.

The executor serializes cancellation with the durable running marker:

| Original executor state | Result of cancel |
|---|---|
| Absent | Commit a signed `cancelled` tombstone for the original intent |
| `queued` | Commit `cancelled` before any invocation |
| `cancelled`, same original intent | Return the exact stored cancellation receipt |
| `running`, `completed`, `failed`, `uncertain` | 409 conflict; do not stop/relabel work |
| Same ID with different caller/intent | Conflict/authorization denial; no replacement |

A committed cancellation receipt binds the original task hash/caller/executor and
has `status: cancelled`, `output: null`, `error: execution_cancelled`. Late original
submissions and retries return it without calling the adapter. If cancellation wins
before the running marker, a concurrent submit observes that receipt too. If the
running marker wins, cancellation cannot claim that work stopped. A full executor
can cancel an existing queued row but cannot create another tombstone beyond its
capacity. v0.31 can explicitly archive a cancelled row, retaining its complete
tombstone/receipt and total-history usage while releasing an active slot. See
[task history](task-history.md); deletion/pruning is not implemented.

Lost responses or failed local receipt commits retain the caller barrier. Retry
the same confirmed `cancel` or query the original ID; never generate another task
to bypass an unknown outcome. A locally saved cancelled receipt can be read/retried
without network I/O; this is its historical acknowledgment. Remote duplicate
operations still require current authorization. Cancellation guarantees depend on
retaining the original durable executor history; database rollback/deletion and
cloned keys are not safe recovery methods and cannot prove no earlier side effect.

## Record an uncertainty review

`uncertain` is an immutable signed executor outcome. Human evidence can explain it
without manufacturing a successful/failed/cancelled receipt or authorizing replay.
With an already downloaded and locally verified uncertain receipt:

```bash
task_client review-preview --task-id "$TASK_ID"

# Write evidence in a local UTF-8 file. Use a stable new 32-lowercase-hex ID
# for this note; reuse it unchanged if the response/output was lost.
task_client review --task-id "$TASK_ID" \
  --receipt-hash "$RECEIPT_HASH" --decision unresolved \
  --note-file state/evidence.txt --request-id "$REVIEW_ID" \
  --confirm-task-id "$TASK_ID"

task_client reviews --task-id "$TASK_ID" --after 0 --limit 20
task_client show --task-id "$TASK_ID"
```

Preview reports original executor, request/receipt hashes, receipt issue time and
available decisions: `effect_observed`, `no_effect_observed`, `unresolved`. The note
is nonempty UTF-8 text of at most 2048 bytes. Confirmation rechecks original ID and
receipt hash, then signs an advisory record with the **caller's existing key**.
It binds owner/group/audience, both identities, task/request/receipt hashes, decision,
exact note, stable request ID and issue time. It explicitly states
`task_status: uncertain` and `effect: advisory_local_record_only`.

These are caller statements entered through a human-operated CLI. They do not
independently authenticate a Human UI principal or verify real-world effects.
`no_effect_observed` does not change the original outcome, reset execution state,
create a new intent, grant permissions, or permit automatic retry/migration.
New evidence appends a new note; there is no edit/delete/requeue operation.

Identical request-ID retries return the same signed record without signing again;
changed reuse, including another task, conflicts. Notes and signatures commit
atomically. Read pages use returned `next_after` and `has_more`; each record's
signature, context and database request-ID binding is verified before display.
New notes reject clocks earlier than the original receipt. A committed identical
retry still recovers the original record after clock rollback.

All review/preview/history actions are local and require no network I/O. They
remain available after grant expiry or group dissolution using the original key,
public pins, grant and private state. Their authority is only to write this caller's
local record; remote result access remains governed by current authorization.
Notes may contain private evidence: protect the SQLite file and consistent backups.
They are not an independently witnessed, deletion/rollback-proof log. No note is
sent to other Agents, a directory, the Human UI or MCP.

## Upgrade and recovery

Upgrade caller and executor to v0.30 before using cancellation. The task operation
schema adds `cancel` and receipts add terminal `cancelled`; older verifiers reject
that state. Older services reject cancel instead of returning a false stop ACK.
The new caller retains its barrier after such a rejection.

Caller startup preserves its original owner/group/caller/executor/source/audience/
CA bindings and original intents, adding `task-operations-v1` to the persisted
context. It creates cancellation/review tables and checks saved cancellation hashes.
This is a **one-way caller-state migration**, including when opening the new CLI
for a read. A v0.29 caller refuses that format before it can ignore a cancellation
barrier. Do not strip the marker, replace state, or downgrade an old backup to
resubmit work. Back up consistently before upgrading. Existing executor rows and
`echo-v1` context remain; cancellation tombstones must be retained.

Same-host callers use separate keys/state files, and same-host executors use
separate keys/databases/listeners. Cancelling one identity's task cannot cancel
another member's intent or confer machine-wide permission. Restart always reloads
the original identity/group; failed cancellation never creates replacements.

## Verification and remaining scope

Thirty new cases cover actual HTTP/TLS, task/proof/context binding, cancellation
versus running races, late submissions, immutable receipts, both-end retry/restart,
capacity, same-host isolation, transaction/signature failures, authorization expiry,
durable caller barriers, one-way format migration, local review integrity/dedup/
pagination and real CLI calls. A separate check used the actual v0.29 caller source
to verify downgrade rejection and restoration of the original cancellation barrier.

Stopping running/external work, independently verified outcome resolution, note
sharing, safe requeue, payload pruning, running-adapter timeouts, Human UI task
integration, real product adapters and physical LAN/Tailscale trials remain open.
The reference Echo adapter and its metadata contract are unchanged; inspecting
metadata never cancels, reviews or executes anything.

The separate v0.32 [signed-task MCP caller](task-mcp.md) exposes local cancellation
preview, confirmed cancel and advisory-note reads using this same state. It cannot
create reviews or authenticate Human consent. Its stable queue/single-task submit
preserve the cancellation barrier; cached running/terminal results never resubmit.
