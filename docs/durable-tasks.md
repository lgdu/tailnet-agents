# Signed durable Echo tasks (v0.27)

An explicitly configured simulation executor accepts signed `echo` tasks for an
existing human-created group. Executor and caller state survive restart. The
critical guarantee is conservative recovery: persist the running marker before
calling the adapter; if execution might have happened but no result was committed,
report `uncertain` and never invoke it again automatically. This is not a general
exactly-once guarantee for external side effects, database rollback or disk loss.

This path is separate from the old bearer Echo bridge, Human UI Echo chat, network
text messages and MCP delegation. Those interfaces do not silently enable these
checks or gain durable task state. No real Agent, shell, model or filesystem tool
adapter is started. Network membership alone grants no execution rights.

## Configure the original executor

Install `.[identity]`. A human must have created the group and explicitly issued
and approved `join` plus `task.echo` for both caller and executor. Retain original
keys/group and deliver a fresh signed policy and learned revocations using existing
administration. Grants with only `join`, discovery or chat scopes cannot run/query
tasks. Discovery candidates cannot select or authorize an executor.

On the simulation executor's machine, extend the existing TLS admission service:

```bash
python3 -m tailnet_agents.admission_server \
  --authority-public-key state/owner.pub --group-id "$GROUP_ID" \
  --audience executor-a --database state/executor-a.sqlite3 \
  --require-policy --policy-file state/group.policy \
  --tasks --task-agent-key state/executor.pem \
  --task-grant-file state/executor.grant \
  --host 0.0.0.0 --port 8771 \
  --tls-cert state/executor.crt --tls-key state/executor.key \
  --allow-host executor.YOUR-TAILNET.ts.net
```

The service still requires `TAILNET_VERIFIED_READ_TOKEN` for directory operations;
this token cannot run or read signed tasks. Both task routes default to 404. Task
mode requires signed policy mode and both original executor files; stray key/grant
options without explicit `--tasks` fail configuration. No missing configuration or
partition creates a group/key/grant. Startup can wait with stale credentials but
cannot execute/query tasks until authorization is fresh and valid.

This executor is a cryptographic Agent subject, never the owner key. Consistent
private SQLite state pins its subject, audience and `echo-v1` semantics/storage format, in addition
to the directory's existing owner/group pin. A POSIX file lock and in-process guard
prevent two task executors from recovering/executing the same database concurrently.
Run one service process per directory database. A second executor on the same
machine uses its own key, approved grant, database and listener port; identity is
never unique by host/IP/Tailscale device. Caller processes need no listener.

## Caller commands

Manually provision the trusted owner/executor public keys, original caller private
key, approved scoped grant, exact LAN/Tailscale origin, audience and TLS CA. Use a
private caller state file distinct from heartbeat and messaging state:

```bash
task_client() {
  python3 -m tailnet_agents.task_client \
    --url https://executor.YOUR-TAILNET.ts.net:8771 \
    --agent-key state/caller.pem --authority-public-key state/owner.pub \
    --grant-file state/caller.grant --group-id "$GROUP_ID" \
    --audience executor-a --executor-public-key state/executor.pub \
    --ca-cert state/ca.pem --state state/tasks.sqlite3 "$@"
}

# The text file is local input for an Echo simulation, not code to execute.
task_client queue --input-file state/echo.txt
task_client status
task_client list --after 0 --limit 20
task_client flush --limit 20

# Use the task_id printed by queue/flush. refresh only queries; it never executes.
task_client refresh --task-id "$TASK_ID"
task_client show --task-id "$TASK_ID"
```

If terminal output was lost, `list` pages saved IDs/status without network I/O.
Use returned `next_after` with `--after` while `has_more` is true, then query the
original ID. It omits input/output; `show` reads an already verified local receipt.

Installed entrypoint: `tailnet-tasks`. Input/output are nonempty UTF-8 strings of
at most 2048 bytes within 16 KiB signature envelopes. `queue` is an explicit new
task action with no network I/O; it commits the original signed task/ID before any
submission. Creating another queued task creates another intent, even if text is
identical. Do not queue a new ID to bypass uncertain work or a conflict.

`flush` visits at most 20 pending or confirmed-unstarted (`queued`) tasks in local
insertion order, stopping on the first request/verification/storage error. It
always uses each original envelope and fixed executor. Earlier stored receipts
remain committed if a later entry fails. It never resubmits local `running`,
`completed`, `failed`, `uncertain` or v0.30 `cancelled` entries. It also skips every
task with a persisted cancellation intent, even if a refresh still reports queued. `refresh` queries a locally known ID
with a fresh proof and commits its verified signed receipt; it never runs queued
work. Use explicit `flush` to retry a queued task. Unknown local IDs are rejected
before network I/O; retain caller state to retain the original intent/hash.

## States and crash recovery

| State | Meaning | Recovery |
|---|---|---|
| `pending` | Caller has original task but no verified receipt | Retry original task at the original executor, or query its original ID |
| `queued` | Executor committed the request; no adapter invocation started | Startup and queries do nothing; explicit freshly authorized submission may claim it |
| `running` | Running marker committed before adapter invocation | Concurrent retry/query returns status without another invocation |
| `completed` | Signed output and terminal receipt committed | Return the original receipt; never execute again |
| `failed` | Adapter failure/invalid output committed with sanitized error | Return the original failure; never execute again |
| `uncertain` | Restart found a running task without a committed outcome | Return terminal uncertainty; advisory local notes cannot change it or authorize replay |
| `cancelled` (v0.30) | Signed pre-execution cancellation tombstone at original executor | Never execute this intent; retain tombstone and return the same receipt |
| `cancel_pending` (local view, v0.30) | Caller saved cancellation intent, with no terminal outcome yet | No `flush` resubmission; retry explicit cancel or query original ID; it is not a stop acknowledgment |

If execution completes after a caller disconnects, its result is still committed.
If that response or the caller's local receipt commit is lost, retry returns the
original signed result. If the executor crashes after a simulated side effect or
its terminal-result commit fails, the running marker remains. Restart commits
`uncertain`, even if the adapter may actually have finished. A crash between the
running marker and adapter invocation also becomes uncertain: refusing a possibly
unnecessary retry is safer than inventing a no-execution fact.

Queued rows survive restart without automatic execution. Caller and executor
current grant/policy/revocation checks run on acceptance, again just before the
running marker, and before returning a newly committed result. Work already
started cannot be undone by revocation; its outcome is saved but access is denied
if authorization expired/revoked meanwhile. Result reads and duplicate submissions
also require both current authorizations. A human can separately issue/approve
replacement grants for the same keys and renew/deliver policy, then restart the
service and caller with original state. No task client signs or renews credentials.

Dissolution is terminal and blocks further network work/reads without deleting
history. Results are caller-only; other group members and directory read-token
holders have no implicit read API. Already downloaded plaintext cannot be revoked.
v0.30 [task operations](task-operations.md) can cancel absent/queued original
intents and append local advisory uncertainty notes. Running work cannot be stopped,
uncertain results cannot be rewritten/requeued, and tasks cannot move executors.
Diagnose effects using external evidence. Never edit database status to `queued`.

## Signatures and persistence

Each request uses a single-use 30-second possession challenge bound to the full
submission or exact queried task ID, current grant and fixed audience. Signed task
intent binds owner/group/audience/caller/executor, ID, `echo` kind, input and creation
time. A fresh current approved grant may submit an older queued intent. Conflicting
reuse of an ID with another signed envelope or caller is 409; no record is evicted.
v0.31 adds explicit full-record terminal archives and four row-count bounds:
256 active/10000 total globally and min(64, active)/min(1000, history) per caller
by default. At any bound, new IDs return 429 while existing retries/reads work.
Archival frees active slots and retains total-history usage and original receipts.
Both areas participate in deduplication. See [task history](task-history.md) for
CLI configuration, explicit confirmation and the one-way executor-format migration.

The executor signs receipts binding the original request hash, both identities,
context, status, output/error and timestamp. Terminal receipts are persisted and
remain byte-identical across restart/retry. Caller verifies the configured executor
key and exact intent hash before committing. It rejects running→queued rollback
and any change to a saved terminal receipt. Conflicting responses leave original
state intact; do not interpret an error as permission to dispatch a replacement.
Historical receipts do not independently prove historical grant/policy validity;
the explicitly trusted executor's signed statement is the evidence.

Client state is a 0600 owned regular SQLite file with an exclusive POSIX process
lock. It pins original owner/group/caller/executor, origin, audience and configured
CA contents. TLS validates CA/hostname on LAN/Tailscale; HTTP is loopback-only and
proxies/redirects are disabled. Original files restore the original task intent and
identity; changing executor or origin fails instead of silently migrating tasks.
Executor and caller connections explicitly use SQLite FULL synchronization.
Both databases contain plaintext input/output: trusted local/store operators can
read them. Consistently back up complete SQLite data using its backup API; preserve
executor requests/receipts and caller intents/receipts together. Database rollback,
cloned-key state, stolen backups, disk loss and key/CA migration are not solved.

## Unimplemented work

The executor only simulates Echo. No real product adapters, external side-effect
integration, A2A/MCP task bridge, Human UI task panel, asynchronous scheduling,
automatic polling/retry daemon, running-work cancellation, verified uncertain-result resolution, retention
UI, payload pruning, byte/outbox quotas, rate limiting, multi-executor migration, replication/HA or physical LAN/
Tailscale/WAN trials are implemented. Graceful shutdown drains active operations;
a future blocking adapter could delay shutdown, and forced termination deliberately
leaves uncertainty. Unit tests inject simulation callbacks only to verify crash
boundaries, not to claim production side-effect safety. Trusted clocks, private
storage and timely human-controlled policy/revocation delivery remain required.

## Reference adapter inspection (v0.29)

The default Echo implementation now has an explicit [adapter contract](adapters.md)
with the same `echo-v1` persisted identity and unchanged signed task wire format.
A read-authenticated metadata probe can inspect its signed contract without
submitting a task, advancing execution state or recovering uncertain work. Opening
a service, catalog lookup and discovery do not probe automatically. Existing
in-process Python test callbacks are not verified product adapters and cannot
advertise the reference contract. All submit/query permission and recovery rules
above remain in force; compatible metadata gives callers no execution permission.

## Explicit operation workflow (v0.30)

[Task operations](task-operations.md) adds preview/confirmed cancellation and local
uncertainty records through this same caller CLI. Cancellation signs no new task,
uses the original intent/executor and persists a no-resubmit barrier before I/O.
Caller state gains a one-way format marker; older clients reject it rather than
ignore cancellation intent. The executor task table retains signed cancellation
tombstones. Review notes never change signed task receipts or authorize retries.
