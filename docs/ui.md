# Human UI v0.21: signing and explicit policy delivery

The UI is a local demonstration of the interaction model. It does
not integrate the mesh simulator, registry, MCP tools or real agent adapters.
Humans explicitly create groups and select configured human members. Each group
uses the same three deterministic Echo participants. Those are simulated actors,
not authorized network Agent identities. It implements configured local human roles and API-level private-history
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
assets are packaged with the Python distribution. The new signing workflow has
Chromium functional coverage; broader browser/accessibility and product interop
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
agent ID)`. Request deduplication is also scoped by human ID. Each group has its own explicit human membership list. Global admin status does
not bypass membership or private-history checks. Human role is global in this
prototype; per-group roles are not implemented.

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

## Explicit group creation and access

A fresh database contains no groups. Login displays an empty state; Agent
startup/discovery does not create a group. Only a configured human with admin
role can open "创建群组", enter a name, select existing human identities and
confirm creation. The server assigns a random unique group ID and automatically
includes the creator. Nonmembers cannot list the group, read messages, send
messages or access the simulated member list. Membership persists across restart.

The group selector switches the history namespace. A pending uncertain send
blocks switching until resolved or logout. The three simulated agent identities
are common to each group, but conversations and deduplication records are scoped
by group ID; private history also includes the human identity.

API additions:

- `GET /api/groups`: groups accessible to the authenticated human.
- `GET /api/humans`: configured IDs/roles, admin-only; never returns tokens.
- `POST /api/groups`: admin-only `{ "name": "...", "humans": ["alice"], "request_id": "stable-key" }`.
- Message and presence POSTs include `group_id`; reads include it in the query.

Group creation is now idempotent by `(human creator, request_id)` across restart.
Retry identical payloads with the same key; a changed payload returns 409. The
UI retains its key while the create dialog stays open. Closing/reopening it or
reloading loses that key: check the group list before making another request.
Grant issuance remains manual. Opt-in signed policy approval/export is described
in [human policy signing](human-policy.md); explicit directory application enables
existing policy propagation.
This is application-level access control on a local server, not mesh authorization.

Upgrade preserves an existing legacy group's history as group `legacy`.
Its human membership is restricted to identities present as message owners and
`demo-owner`; previously configured silent observers are not automatically
re-authorized. The old group's creator is `demo-owner`. Fresh databases do not
create `legacy`. Database migrations are additive; keep a consistent backup and
do not downgrade to older server versions that lack group access checks.

## Membership management and dissolution

"管理群组" is available to the group's creator while that human retains the
configured admin role. Invited admins cannot manage a group they did not create.
The creator can add configured human identities or revoke their membership.
The creator cannot remove itself; use dissolution to close the group. Removing
an identity from membership denies future reads/writes. It cannot erase history
already downloaded to a browser. The UI clears the active group when its next
poll detects revoked membership.

Dissolution requires entering the complete group name. It is terminal for that
group ID. Members retain read-only access to history; sending, membership changes
and simulated presence changes are denied. Dissolution is idempotent, persists
across restart and is recorded once. It does not delete data. Creating another
group of the same display name creates a different ID through a new human action.

New APIs:

- `GET /api/group-info?group_id=...`: member-accessible metadata, human membership
  and the latest 50 lifecycle records (no private message content or credentials).
- `POST /api/group-members`: creator+admin only, `group_id`, `subject`, `operation`
  (`add` or `remove`). Subject must be a configured human.
- `POST /api/group-dissolve`: creator+admin only, `group_id`, `confirm_name`.

Message history access and write authorization are rechecked under the SQLite
lock/transaction. Revocation and terminal state are not just UI controls.
Legacy-history import is marked once so a restart cannot re-add a removed human
solely because that person's old messages remain stored.

Local human membership remains a UI ACL. For explicitly created signed groups,
dissolution also commits a signed terminal policy; Agent removal uses a separate
signed-policy action. Distribution requires explicit policy export/application
or confirmed delivery to a recipient fixed by trusted startup configuration.
No owner transfer or recovery is implemented: preserve the creator's identity,
credentials/configuration and database backup. Lifecycle records are plaintext
local audit data, not tamper-proof evidence against a database operator.

The optional [signing workflow](human-policy.md) connects this UI to existing
Agent grants and signed policies through explicit human actions. Grant creation,
Agent runtime enrollment and background directory delivery remain separate. The
optional [delivery workflow](policy-delivery.md) previews locally, requires human
confirmation of the recipient and exact snapshot, and persists point-in-time
receiver revision/age receipts. It never registers an Agent or renews policy.
Recipient configuration is off by default; grant issuance still uses manual
provisioning. Human
role configuration and local group membership use the checks documented above. See [status](status.md) for the current integration boundary.
