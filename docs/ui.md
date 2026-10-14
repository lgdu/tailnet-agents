# Human UI v0.8: role-aware local chat simulation

The UI is a standalone local demonstration of the interaction model. It does
not integrate the mesh simulator, registry, MCP tools or real agent adapters.
It shows one fixed group and three deterministic Echo participants. It implements configured local human roles and API-level private-history
isolation. It does not claim network discovery, external identity-provider
integration or E2E encryption.

## Start

```bash
export TAILNET_UI_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python3 -m tailnet_agents.ui --port 8770 --database state/chat.sqlite3
```

Open `http://127.0.0.1:8770` locally. Enter the value of `TAILNET_UI_TOKEN`
from the terminal/environment; the server never inserts it into a URL or page.
After installation, the entrypoint is `tailnet-agents-ui`.

`TAILNET_UI_TOKEN` retains the legacy single-owner configuration, with identity
`demo-owner` and admin role. For multiple humans use `TAILNET_UI_USERS` below.
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
- Initial history loads the latest 100 messages. "加载更早消息" pages backward.
  New messages are polled with an ID cursor every 2 seconds while the page is visible.
- A failed send retains its request ID for retry in the current page. Do not
  change the pending payload. Reload/logout discards that pending retry state,
  so there is no durable browser outbox yet.

Private conversations are scoped by the authenticated human ID on the backend.
Other participants and administrators cannot query another human's private
history through the API. This does not protect against server/database operators
or compromised bearer tokens. Storage remains plaintext SQLite, not E2E encryption.

## Verification and next work

Backend HTTP tests cover authentication, Origin rejection, CSP headers,
conversation routing, offline recipients and durable deduplication. Static
assets are packaged with the Python distribution. Browser/product interop
and real mesh chat remain unvalidated.

Next milestones: external human identity/session integration; authenticated group membership;
push-based message delivery; durable browser outbox; integration with
network bridges; actual private-chat cryptography if required by the trust model.

## Independent humans and roles

Set `TAILNET_UI_USERS` to a JSON object in the server environment. This takes
precedence over `TAILNET_UI_TOKEN`. Each ID is stable (1..64 ASCII letters,
digits, dots, underscores or hyphens). Each token must be unique and contain
at least 32 random ASCII characters. Below are placeholders, not usable secrets:

```json
{
  "owner": {"token": "REPLACE_WITH_RANDOM_OWNER_TOKEN", "role": "admin"},
  "alice": {"token": "REPLACE_WITH_RANDOM_ALICE_TOKEN", "role": "participant"},
  "watcher": {"token": "REPLACE_WITH_RANDOM_WATCHER_TOKEN", "role": "observer"}
}
```

| Role | Group history | Send / own private history | Simulated presence controls |
|---|---|---|---|
| admin | Yes | Yes, own history only | Yes |
| participant | Yes | Yes, own history only | No |
| observer | Yes | No | No |

Identity and role come from the server credential map, never request body fields.
The UI displays the authenticated ID and hides unavailable controls; the API
independently enforces those checks. The private scope is `(human ID, target
agent ID)`. Request deduplication is also scoped by human ID. The application
has one shared demo group; per-group memberships are not implemented.

Rotate/revoke tokens or change roles by editing the environment and restarting
the UI server. Keep IDs unchanged to retain each human's private history.
No self-service account creation, identity-provider login or expiring session
cookies are implemented. Anyone holding a token can act as that configured
human. This remains a loopback-only prototype.

## Upgrade from v0.6

Back up SQLite with its backup API before upgrading. On first open, v0.7 adds
an owner column and a per-human deduplication table. All legacy private history
and request records are assigned exclusively to `demo-owner`; new identities
do not inherit them. Legacy group history stays shared. Keep `demo-owner` in
your configuration if you want to access those old private conversations.
This is an additive migration; downgrading to v0.6 is not supported because
its reads lack human isolation. Preserve the pre-upgrade backup for rollback.

Group history and simulated member presence update by polling every 2 seconds.
There is no WebSocket/SSE push yet. Hidden tabs pause polling; visible tabs catch
up on subsequent polls. Requests time out after 10 seconds and polling retries.
Messages are deduplicated by ID. Older-page loads preserve scroll position;
new messages do not force a reader at an older scroll position to the bottom.
Login/logout and conversation switches invalidate stale UI request results.
This browser behavior has not yet been visually tested with real clients.

## Message page API

`GET /api/messages?conversation=group&limit=100` returns the newest page.
Use `before=<oldest-id>` for older history or `after=<newest-id>` for updates.
Those cursors are exclusive and mutually exclusive; limit is 1..200.
Returned messages are always ascending by ID. `has_more` refers to the selected
direction. Private scope always comes from the authenticated identity, never
query parameters. Observer restrictions apply to every page request.
