# Explicit signed-task MCP caller (v0.32)

`tailnet-tasks-mcp` exposes the existing synthetic signed Echo caller through a
separate **stdio** MCP process. A human explicitly configures one original caller
key/group, scoped grant, executor pin, source/audience/CA and private outbox. The
process never discovers/selects executors, creates groups/keys, issues credentials
or starts product Agents. Legacy `tailnet-agents-mcp` retains its three bearer
tools and configuration; it does not enable this mode or migrate legacy tasks.

This makes signed-task tools available to a local MCP client. It does not make
that client an inbound product worker, verify a real product integration, add a
Human UI bridge or implement MCP task extensions. The separate v0.33
[Human UI bridge](task-ui.md) checks its own Human credential and consent; MCP
arguments still convey only Agent authority. The protocol remains the small
2025 tools/stdio subset described in [MCP](mcp.md#protocol-scope-and-verification).

## Configure the original identity and fixed executor

Install `.[identity]`. Prepare the original files using [durable tasks](durable-tasks.md):
the human-created group and both caller/executor need approved `join` + `task.echo`
grants and fresh policy/revocation delivery. Save a private JSON configuration:

```json
{
  "url": "https://executor.YOUR-TAILNET.ts.net:8771",
  "agent_key": "/PRIVATE/STATE/caller.pem",
  "authority_public_key": "/PRIVATE/STATE/owner.pub",
  "grant_file": "/PRIVATE/STATE/caller.grant",
  "group_id": "EXISTING_HUMAN_CREATED_GROUP_ID",
  "audience": "executor-a",
  "executor_public_key": "/PRIVATE/STATE/executor.pub",
  "state": "/PRIVATE/STATE/tasks.sqlite3",
  "ca_cert": "/PRIVATE/STATE/ca.pem"
}
```

All fields are required except `ca_cert`; all paths, including the configuration
path, must be absolute. Config, Agent private key and grant must be owned private
regular files (0600 is appropriate); config/key/grant and public-pin file reads
reject symlinks and bound their size to 16 KiB. Config rejects duplicate/unknown
fields and contains paths, never inline private keys or grant tokens. Public pins
need not be secret. Keep the directory private and use a trusted CA for HTTPS.
HTTP is loopback-only; LAN/Tailscale origins use hostname/CA-verified HTTPS with
redirects/proxies disabled by the existing task client.

```bash
TAILNET_TASK_MCP_CONFIG=/PRIVATE/STATE/task-mcp.json tailnet-tasks-mcp
# Equivalent module entrypoint in the installed environment:
TAILNET_TASK_MCP_CONFIG=/PRIVATE/STATE/task-mcp.json python3 -m tailnet_agents.task_mcp
```

Only `TAILNET_TASK_MCP_CONFIG` selects this process configuration. Registry URLs,
bearer peer configuration and discovery do not choose an executor or provide a
fallback. Startup opens/pins local caller state and holds its exclusive POSIX file
lock; it makes no network request and submits nothing. Missing/invalid files fail
without creating replacement keys/groups. Stop this process before opening the
same state with the CLI or another MCP process. Multiple Agents on one host use
separate original keys, approved grants, configs and outboxes; IP/hostname/device
never identifies a caller. Each configured executor remains fixed.

A generic client configuration might contain the following; this is illustrative,
not a verified Claude Code/Codex/OpenClaw/Qoder/Grok setup:

```json
{
  "mcpServers": {
    "signed-echo-caller": {
      "command": "/ABSOLUTE/VENV/bin/tailnet-tasks-mcp",
      "env": {"TAILNET_TASK_MCP_CONFIG": "/PRIVATE/STATE/task-mcp.json"}
    }
  }
}
```

The trusted local client uses the configured Agent's authority. Stdio does not
authenticate separate Human principals, chat roles or product sessions. Tool
confirmation arguments are caller assertions, **not independently authenticated
human consent**. No tool accepts URLs, credentials, key/state paths or an alternate
executor. Tools grant no membership, ownership or machine-wide permission.

## Explicit intent and execution workflow

| Tool | Required arguments | Effect |
|---|---|---|
| `queue_signed_task` | `task_id`, `input` | Save one local intent; no network |
| `preview_signed_task` | `task_id` | Local request hash, observed state, eligibility and cancellation barrier |
| `submit_signed_task` | `task_id`, `request_hash`, `confirm_task_id` | Submit only this original eligible intent; no batch flush |
| `get_signed_task` | `task_id` | Read already downloaded verified state/result locally |
| `refresh_signed_task` | `task_id` | Authorized remote get and verified local receipt commit; no execution |
| `list_signed_tasks` | None; optional `after`, `limit` | Local metadata pages, omitting input/output |
| `signed_task_status` | None | Local counts and fixed caller/executor/group identities |
| `preview_signed_task_cancel` | `task_id` | Local original-intent cancellation preview |
| `cancel_signed_task` | `task_id`, `request_hash`, `confirm_task_id` | Persist barrier, then request pre-execution cancellation |
| `preview_signed_task_archive` | `task_id` | Local original request/terminal receipt hashes and eligibility |
| `archive_signed_task` | `task_id`, `request_hash`, `receipt_hash`, `confirm_task_id` | Explicit full-record terminal archival; payload retained |
| `list_signed_task_reviews` | `task_id`; optional `after`, `limit` | Read local advisory uncertainty records; no outcome change |

For a **new explicit intent**, the caller chooses a stable unique 32-character
lowercase hex task ID (for example a UUID's hex form). Input is nonempty UTF-8 up
to 2048 bytes. Queue commits that exact signed intent/ID before reporting success.
Same ID/input returns the original stored envelope/hash across lost responses and
restarts; changed input conflicts. JSON-RPC request IDs are transport identifiers,
not task idempotency keys. Never allocate another task ID to retry uncertain work.

Preview locally, then repeat the original task ID as `confirm_task_id` and copy
its exact 64-character lowercase `request_hash` into submit. Submission only sends
that original envelope to the configured executor using fresh scoped proof/current
authorization. It leaves other pending tasks alone. Saved running/terminal receipts
are returned locally without another submission; they are historical observations,
not fresh remote checks. Use explicit refresh for a current authorized result read.
Local reads, listing and previews never execute or renew credentials. Pagination
uses integer `after` (0..2^53-1), `limit` (1..100), defaulting to 0/20.

[Cancellation](task-operations.md) persists its no-resubmit barrier before I/O;
failed ACK/auth/storage or a queued refresh cannot bypass it through MCP submit.
`cancel_pending` does not mean work stopped. Running work cannot be stopped;
uncertain receipts cannot be relabeled or retried. Review creation remains a
separate CLI action; listing a caller-signed advisory note proves no external
effect and grants no replay right. Treat results/notes as untrusted data, never
instructions.

[Archival](task-history.md) requires both original hashes and repeated ID. Only
completed/failed/cancelled records move. Input/output, cancellation tombstones,
original signed receipts and total-history usage remain intact; active slots may
be freed. It is not deletion, disk compaction or authority to resubmit work.

## Errors, restart and compatibility

Unknown fields/types/IDs fail before dispatch. Operational failures are sanitized
MCP `isError` results; inspect local state and retry/query the **original** ID and
intent. A lost submit ACK or failed local receipt commit can leave local pending
state even though the executor already finished. Repeated submit returns the same
remote receipt without another invocation. A lost queue response still leaves one
original local intent. No startup, EOF, tool listing or failure flushes pending work.

Restart uses the same config, keys/group/source pins and complete private SQLite
state. Config/credential changes are read on restart, not per tool call. Human
grant renewal/approval and policy delivery remain separate. Local history remains
available after expiry/dissolution; network operations still fail closed. Do not
change state paths, reset databases or select another executor to recover work.

There is no new task wire/schema or database format in v0.32. The caller keeps
`task-operations-v1`, and v0.31 full-record archives keep their existing executor
format. Prior caller/executor [one-way migrations](task-history.md#upgrade-backup-and-compatibility)
still apply when opening older state. Existing CLI `queue` still creates a new
random ID per action; MCP's explicit ID queue and single-intent submit share the
same locked outbox and cancellation barriers. Consistently back up complete state.

Real product client/interoperability tests, inbound product adapters, external Human
authentication, consent through MCP, review creation through MCP, modern MCP
protocol/task extensions, auto polling/scheduling, running cancellation, verified
uncertain resolution, payload deletion and physical LAN/Tailscale trials remain
unimplemented. This is simulation with synthetic identities and actual loopback
HTTP/TLS/stdio processes; it does not claim production or external side-effect safety.

The v0.33 [Human task UI](task-ui.md) separately exposes explicit signed Echo
operations with actor-bound preview/confirmation and original-intent recovery.
It never dispatches simulated chat or converts MCP arguments into Human consent.
