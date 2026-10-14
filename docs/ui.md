# Human UI v0.6: local chat simulation

The UI is a standalone local demonstration of the interaction model. It does
not integrate the mesh simulator, registry, MCP tools or real agent adapters.
It shows one fixed group and three deterministic Echo participants. It does
not claim multi-user authorization, network discovery or E2E encryption.

## Start

```bash
export TAILNET_UI_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python3 -m tailnet_agents.ui --port 8770 --database state/chat.sqlite3
```

Open `http://127.0.0.1:8770` locally. Enter the value of `TAILNET_UI_TOKEN`
from the terminal/environment; the server never inserts it into a URL or page.
After installation, the entrypoint is `tailnet-agents-ui`.

The token represents a **single demo owner**, not separate human accounts.
The UI holds it only in page memory. Reloading requires reconnecting. All
API operations require it. The service binds to loopback and checks Host and
Origin; do not expose it through Tailscale Serve, a reverse proxy or a public
port before implementing actual human sessions and deployment security.

## Behavior

- Group chat: choose named recipients, or let Moderator reply by default.
- Direct conversation: only the selected simulated agent replies. Each
  conversation has an independent history.
- Simulate offline: toggle a member in the right panel on desktop. A message
  to an offline member is saved, with explicit feedback that no reply occurred.
  There is no automatic offline delivery queue yet.
- Agent replies never trigger peer replies or execute commands.
- SQLite persists chat and request deduplication across restart. Simulated
  presence resets to online on server restart; this is not network presence.
- Each history request returns the latest 200 messages. Older messages remain
  in SQLite, but pagination is not yet implemented.
- A failed send retains its request ID for retry in the current page. Do not
  change the pending payload. Reload/logout discards that pending retry state,
  so there is no durable browser outbox yet.

Private conversations are separated in storage and UI. Because this demo has
one human owner, anyone possessing its UI token has access to every demo
conversation. These tests prove conversation routing, not privacy between
multiple human users. Storage is plaintext SQLite; it is not E2E encrypted.
Do not use this prototype for confidential conversations.

## Verification and next work

Backend HTTP tests cover authentication, Origin rejection, CSP headers,
conversation routing, offline recipients and durable deduplication. Static
assets are packaged with the Python distribution. Browser/product interop
and real mesh chat remain unvalidated.

Next milestones: real human identity/roles; authenticated group membership;
message event delivery; browser outbox and history pagination; integration with
network bridges; actual private-chat cryptography if required by the trust model.
