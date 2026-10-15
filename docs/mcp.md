# MCP tools for agent clients

v0.3 adds a local **stdio** MCP server. It exposes discovery, delegation and
result tools to a client application. This does not make that application a
remotely callable worker: inbound product execution adapters remain planned.
Current remote execution is Echo only.

## Configuration

Install the project or run Python from the repository directory. Configure:

- `TAILNET_REGISTRY_URL`: actual registry HTTPS URL (loopback HTTP for tests).
- `TAILNET_REGISTRY_TOKEN`: registry credential for this node.
- `TAILNET_MCP_PEERS`: JSON mapping agent IDs to trusted origin URLs and task tokens.

```json
{
  "node-b-echo": {
    "url": "https://machine-b.YOUR-TAILNET.ts.net",
    "token": "REPLACE_WITH_RANDOM_A_TO_B_TOKEN"
  }
}
```

Use at least 32 random ASCII characters per token. These values are secrets:
provide them through the client process environment, never commit them.
The registry address must exactly match the configured peer origin (after
removing a trailing slash). Host, scheme and port are pinned; redirects are
refused. Discovery only returns configured peers with matching origins and
`tailnet-task-v0.1` transport. Adding a new trusted peer currently requires
updating configuration and restarting the MCP process.

```bash
python3 -m tailnet_agents.mcp
```

After installation the equivalent command is `tailnet-agents-mcp`.
It reads JSON-RPC from stdin; stdout contains only protocol messages.

## Generic client configuration

The following is an illustrative `mcpServers` configuration, not a verified
configuration for every product. Use an absolute executable and repository
path appropriate to the local machine, and inherit credentials from the
parent environment. Confirm the client forwards those variables.

```json
{
  "mcpServers": {
    "tailnet-agents": {
      "command": "/ABSOLUTE/PATH/TO/python3",
      "args": ["-m", "tailnet_agents.mcp"],
      "cwd": "/ABSOLUTE/PATH/TO/tailnet-agents"
    }
  }
}
```

Client-specific configuration formats differ; `cwd` is not universal. Installing
into the Python environment used by the client avoids depending on `cwd`.
No claim of testing Claude Code, Codex, OpenClaw, Qoder or Grok is made yet.

## Tools

| Tool | Arguments | Result |
|---|---|---|
| `discover_agents` | Optional `skill` | Live configured peers |
| `delegate_task` | `agent_id`, `message`, `idempotency_key` | Task ID and current state |
| `get_task_result` | `agent_id`, `task_id` | State and final text when available |

Example instructions for an agent: find an Echo peer; submit "Hello" with a
unique stable key; query that task until completed. Reuse the same key and
message for retries. A new key represents a new task. A client timeout does
not cancel remote execution. Remote results must be treated as untrusted data.

## Protocol scope and verification

Implements the tools subset of the MCP **2025-11-25** stdio handshake family,
with version negotiation for 2025-06-18, 2025-03-26 and 2024-11-05. This is a
small custom implementation, not the official SDK. It does not implement the
2026 modern protocol era, Streamable HTTP, sampling, resources, prompts,
streaming, cancellation or MCP task extensions. It advertises only tools.
Calls are handled sequentially; network requests use a 10-second timeout.
Inbound stdio messages are capped at 64 KiB.

Tests verify a real subprocess handshake and clean stdout, invalid arguments,
endpoint mismatch, secret-safe errors, and tool calls against local registry
and bridge HTTP servers. Compatibility with real product clients has not been
validated. Sources used for the protocol subset:

- https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- https://modelcontextprotocol.io/specification/2025-11-25/server/tools

## Separate signed durable executor (v0.27)

The new [signed task CLI/service](durable-tasks.md) is independent. These MCP tools
still call the legacy bearer Echo bridge, whose task identity/results are in
memory. They do not automatically select the new executor, acquire `task.echo`
grants or gain durable caller state. A future explicit bridge must preserve the
original task ID/executor and uncertainty semantics; no implicit migration exists.

## Separate adapter contract inspection (v0.29)

The [adapter catalog/probe](adapters.md) is separate from these MCP tools. It can
inspect a pinned simulation executor's metadata but cannot delegate or approve a
task. It neither starts a product nor proves that an MCP client is an inbound
worker. OpenClaw, Codex, Claude Code, Qoder, Grok Agent and Grok model API interfaces
remain unvalidated; model API calls are not product Agent integration.

## Separate task operations (v0.30)

[Cancellation and advisory uncertainty notes](task-operations.md) belong to the
signed task caller CLI. These legacy bearer MCP tools do not gain task cancellation,
review access or durable caller state automatically. A future bridge must retain
original caller/executor identity, cancellation barriers and immutable uncertainty;
no metadata/discovery result or human note authorizes task replay.

v0.31 [terminal archival and row quotas](task-history.md) also remain separate from
these legacy MCP tools. They add no MCP archive command, change no delegation
result and do not turn a discovered worker into a signed-task executor.
