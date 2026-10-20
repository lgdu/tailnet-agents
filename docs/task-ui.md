# Human-confirmed signed Echo tasks (v0.33)

The loopback Human UI can operate explicitly configured original signed-task
callers. This is separate from simulated chat replies and both MCP processes.
Opening a view, listing history, previews, startup and restart never queue or
submit tasks. Only a separate authenticated human confirmation performs an
operation. No discovery, group creation, enrollment, grant issuance/renewal or
executor startup occurs through this bridge. Actual product Agents are unavailable.

## Explicit setup

Install `.[identity]`. First create the signed group explicitly through its human
owner's existing UI and separately provision/approve original caller and executor
keys/grants. Keep the original UI database, policy authority and configured human
ID. Start the existing simulated Echo executor separately; use HTTPS/CA for LAN or
Tailscale origins. HTTP is allowed only for loopback development.

Prepare the caller's private absolute-path configuration described in
[signed-task MCP](task-mcp.md#configure-the-original-identity-and-fixed-executor). It fixes the original Agent
key, owner pin, grant, signed group, source/audience/CA, executor pin and SQLite
outbox. This reuses the file format, not a running MCP process. Stop CLI/MCP use
of this caller state before starting the UI: the original exclusive file lock
prevents concurrent processes.

Create an owned regular mode-0600 bindings file at an absolute path, for example
`/absolute/private/task-bindings.json`:

```json
[
  {
    "id": "home-echo",
    "human": "owner",
    "config_file": "/absolute/private/original-caller.json"
  }
]
```

One to sixteen unique binding IDs are supported. Each human must be a configured
admin, that signed group's creator and the configured policy administrator. The
caller's owner pin must match the UI's original policy owner. The group must
already exist; local chat groups without a signed policy cannot be bound. Other
admins, participants and observers cannot read this caller's tasks or confirm its
consents. Binding IDs, human identity and original caller context/state path are
persisted and cannot be silently replaced/removed on restart. New bindings may
be added while retaining every existing one. Rotate credentials/configuration by
stopping and restarting with the same contexts, not by selecting another state.

Start the original UI with its existing user environment and signing arguments:

```bash
tailnet-agents-ui --database /absolute/private/chat.sqlite3 \
  --policy-owner-key /absolute/private/original-owner.pem \
  --policy-owner-public-key /absolute/private/original-owner.pub \
  --policy-admin owner \
  --task-bindings-file /absolute/private/task-bindings.json
```

The default UI remains core-only and has no task bindings. Once bindings are
saved, restarting this version without them fails. Configurations and credentials
are never accepted from a browser request or returned to it. The browser receives
only public identity/source metadata, authorized input/results and consent history.
Same-host Agents use independent keys/grants/configurations/outboxes; no hostname,
IP or Tailscale device uniqueness is imposed.

## Preview, then confirm one original operation

Select the signed group and **签名任务**, then select an existing binding. Reads
are explicit, paginated and local. There is no polling/flush or automatic chain.

| Operation | Preview and confirmed behavior |
|---|---|
| Queue | Show exact Echo input and stable task ID; confirmation only commits that original local intent, without network I/O |
| Submit | Show original verified input, request hash, executor and local eligibility; confirmation submits only that intent, respecting cancellation barriers |
| Refresh | Show original input and saved observation; confirmation queries and persists a verified remote receipt, never executes queued work |
| Cancel | Show original input/hash and observed eligibility; confirmation persists the original cancellation barrier before requesting pre-execution cancellation |
| Archive | Show original input/request/terminal receipt hashes; confirmation moves the full completed/failed/cancelled record, retaining plaintext and deduplication history |

The browser must repeat the original task ID before confirming. The server
stores a 60-second preview bound to authenticated human, binding, group, operation,
original task/input/hashes and current signed UI policy snapshot. Unknown fields,
caller/URL/key/path overrides and changed reuse of a preview ID fail. First
confirmation rejects expiry, backward time or a changed policy, and records a
durable `started` authorization **before** caller mutation/network I/O. Once an
expiry is observed by the server it remains expired after clock rollback. Trusted
wall clocks are still required; this does not detect every unobserved clock change.

Successful completion stores a `done` acknowledgment. Repeating it reads the
historical local result, without network I/O or a fresh authorization claim.
Separate remote operations still enforce both Agents' current scoped grants,
policy and revocation state through the existing proof/receipt protocol.
Uncertain/running tasks cannot be resubmitted from a new submit preview; uncertain
tasks cannot be cancelled or archived. No operation manufactures a result or
changes uncertainty into permission to replay.

## Lost output and restart

A failed operation retains its original consent/task ID. Use **显式重试同一确认**,
or reopen/reload, explicitly read confirmation history and select the original
`started` entry, then repeat its task ID to retry. Already-started operations may
be explicitly retried after the preview deadline; that recovers the original
authorized intent, not a new operation. Current human/group access and remote
authorization still apply. A dissolved group permits local history/completed
acknowledgments but blocks new previews and unfinished confirmations.

UI consent state and caller state are separate SQLite transactions. A crash can
leave `started` even when the remote operation succeeded; it is not proof of
failure or that work never ran. Queue retry uses the same ID/input, submit uses
the same signed intent, and cancellation retains the durable barrier. Preserve
original executor history and recover the same operation; never generate another
ID or choose another executor to bypass unknown results. Startup never resumes it.

Closing, switching groups/bindings and logout discard browser previews/results;
late responses cannot revive them. Starting a replacement preview immediately
clears the old display and locks confirmation input until the new response.
Preview expiry stays disabled after a browser
clock rollback. UI tokens stay in page memory, not URLs or browser storage. The
browser itself has no durable outbox; the gateway's explicit consent history is
the recovery record. Review-note creation and reads remain CLI/MCP operations as
documented in [task operations](task-operations.md).

## Trust, storage and remaining work

Human authorization comes from the separate configured UI bearer credential and
server-side role/group/binding checks. It is independent of Agent tool arguments,
but is not external identity-provider login, hardware approval or a Human digital
signature. Anyone holding that UI token can act as that human. The trusted gateway
holds Agent credentials and already holds the owner signer. Trusted OS operators
can still run CLI/MCP directly with Agent keys; this is not a global Human-consent
requirement on the task wire protocol. Do not expose the loopback UI through a
public/tailnet proxy; session/deployment security remains future work.

This adds UI-local bindings/consents only, with no new caller/executor or task-wire
format. Prior one-way [caller/executor migrations](task-history.md#upgrade-backup-and-compatibility)
still apply to older state. Back up the complete UI, caller and executor databases
consistently and preserve original keys, grants, pins and policy/revocation history.
Consents contain plaintext inputs/results and are neither independently witnessed
nor deletion/rollback-proof; no pruning or rollback/disk-loss repair is provided.
Older UIs do not understand task consent records; do not use a downgrade as a
recovery procedure.

Not implemented: real product workers/client interoperability, external Human
authentication/sessions, Human uncertainty-note creation, generic tool execution,
MCP Human-consent bridging, modern task extensions, running-task stop, scheduling,
verified external outcomes, payload pruning, executor byte/disk bounds, HA or physical
LAN/Tailscale trials. Verification uses synthetic identities and real loopback
HTTP/TLS/stdio processes plus Chromium; it does not establish production safety.

## Local consent and caller admission (v0.34)

The gateway now accepts `--task-consent-capacity` and
`--task-consent-byte-capacity` as validated startup options for each Human/binding.
Caller files may separately include `storage_limits`. The task panel explicitly
reads both budgets with **读取本地容量**; neither tool/browser fields nor discovery
can replace the configuration. See [local task storage](task-storage.md) for
limits, byte reservations, current usage and restart behavior.

Every new preview consumes retained history, even cancel/refresh/archive. Full
UI admission returns 429 without saving a partial record. Existing preview-ID
recovery and started/done confirmation retries remain available. Increase explicit
limits/restart for another preview, or stop UI and use the same original caller
CLI for cancellation; caller cancel/result persistence does not require new-task
admission. No history is deleted or Human confirmation bypassed to free capacity.
