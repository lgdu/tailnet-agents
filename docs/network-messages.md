# Signed network messages (v0.26, unreleased)

The opt-in admission service can act as one designated conversation store for an
existing human-created group. Independent synthetic Agent clients on different
machines use LAN or Tailscale HTTPS to send signed group/direct text and catch up
after downtime. This is a custom prototype protocol, separate from local Human UI
Echo chat and the bearer task API. It starts no product Agent, executor or reply
loop. A message is text, not a task or authority to invoke tools.

## Explicit configuration

Install `.[identity]`. Retain the existing owner public key, original group ID,
Agent private keys and manually issued/approved grants. Each sender/reader needs
`join` plus `chat.group` or `chat.direct` in its grant and current signed policy.
The Human UI's separate issuance/approval workflow supports those scopes.
Discovery candidates, presence copies and directory read credentials confer no
chat access. A missing/stale policy or isolated network never creates a group.

Enable `--messages` on the existing admission service, alongside `--require-policy`
or `--policy-file` and its existing TLS configuration:

```bash
python3 -m tailnet_agents.admission_server \
  --authority-public-key state/owner.pub --group-id "$GROUP_ID" \
  --audience history-a --database state/history.sqlite3 \
  --require-policy --policy-file state/group.policy --messages \
  --host 0.0.0.0 --port 8771 \
  --tls-cert state/history.crt --tls-key state/history.key \
  --allow-host history.YOUR-TAILNET.ts.net
```

The existing service also requires `TAILNET_VERIFIED_READ_TOKEN` for directory
administration. Message clients do not need or use that token. Configure the
service origin, CA, owner, group and audience explicitly through a trusted channel.
Use a certificate matching the configured LAN DNS or tailnet name. Plain HTTP is
permitted only on loopback. Proxies and redirects are disabled. Physical LAN and
cross-region Tailscale testing is still outstanding; actual HTTP/TLS processes
with synthetic identities are exercised on loopback.

One service process owns each database. Its persisted owner/group and message
audience cannot be replaced on restart. Default startup without `--messages`
keeps both message routes disabled (404) and preserves existing history.

## Client workflow

Use a different private messaging state file for each Agent key and designated
service, separate from heartbeat state. Two Agents may share a machine, IP,
hostname, endpoint or Tailscale device. Their keys and outboxes stay independent;
no Agent listener or new port per client is necessary for this polling transport.

```bash
# Use this shell function separately on each simulated Agent's machine.
message_client() {
  python3 -m tailnet_agents.message_client \
    --url https://history.YOUR-TAILNET.ts.net:8771 \
    --agent-key state/agent.pem --authority-public-key state/owner.pub \
    --grant-file state/agent.grant --group-id "$GROUP_ID" \
    --audience history-a --ca-cert state/ca.pem \
    --state state/messages.sqlite3 "$@"
}

# Write a text file locally, then persist a group message without network I/O.
message_client queue --text-file state/message.txt
message_client status
message_client flush --limit 20

# Omit --recipient for group chat. Use an exact public-key identity for direct text.
message_client queue --text-file state/private.txt --recipient "$OTHER_AGENT_ID"
message_client flush
message_client sync --scope direct --peer "$OTHER_AGENT_ID" --limit 20
message_client history --scope direct --peer "$OTHER_AGENT_ID"

# Read group pages. Repeat sync while has_more is true.
message_client sync --scope group --limit 20
message_client history --scope group
```

Installed entrypoint: `tailnet-messages`. `queue --reply-to MESSAGE_ID` optionally
references a message already committed in the same conversation. Queuing a reply
before its pending parent is safe only when the parent is flushed first. References
to another conversation or missing messages are rejected. Direct conversations
are a deterministic unordered pair of public-key identities; group conversations
are bound to owner/group. No automatic mentions, model response or execution runs.

Text is nonblank UTF-8, at most 4096 bytes, and its signed envelope must also fit
the shared 16 KiB signature limit (escaped four-byte Unicode may hit that first).
There are no attachments, edits, deletion or implicit task submission. `history`
returns at most the newest 100 verified cached messages in conversation order.
It performs no network request. A local copy already read cannot be revoked.

## Delivery, retry and recovery

`queue` commits the original signed envelope to SQLite and reports `pending`.
It can queue while offline or awaiting manual credential renewal. `flush` requires
a currently valid scoped grant; the service independently checks current policy,
approved credential and learned revocations for every retry, including duplicates.
For direct sends, the recipient must also be in the active policy with
`chat.direct` and at least one approved grant ID not locally revoked. Policy does
not contain recipient credential expiry; the recipient must present its own valid
grant and fresh proof to read, so storing text does not prove it can read now.

Each operation uses a fresh, single-use, 30-second challenge. The proof binds the
full operation/body or read scope, peer, limit and cursor, as well as audience and
grant. The receiver verifies the sender signature and commits before returning
`stored`, the message ID, immutable envelope hash and store sequence. `stored`
means accepted by that configured store; it does not mean delivered to a person,
read, executed, or replicated to other stores. Receipts rely on authenticated TLS
and the trusted store; they are not an independently signed delivery certificate.

If a response is lost, the exact original message ID/envelope remains pending.
Restarting both ends and retrying gives the original committed receipt, without
another message. Reusing an ID with changed content, recipient or sender returns
409. A storage error returns 503 without a success acknowledgment. `flush` visits
at most 20 pending entries in local insertion order and stops on the first failure.
Earlier successful entries stay stored; later entries stay pending. It never
moves uncertain sends to another service or silently discards blocked entries.
A permanently rejected head entry currently requires operator diagnosis; automatic
retry scheduling and explicit cancellation UI are not implemented.

`sync` reads a bounded page for one authorized conversation. It verifies every
signature, owner/group/audience, participant, ordering and cursor before a single
transaction writes inbox entries and the next cursor. A bad second entry, failed
transaction or lost response cannot skip the first unread page. Each conversation
has its own persisted cursor. Removal, revoked/expired grants, stale policy or
terminal dissolution block further network sends/reads; retained history is not
deleted. Current authorized group readers can read all retained group history,
including history before they joined. A still-authorized direct participant can
read that conversation after the other participant leaves.

## Privacy and operational limits

Direct history is served only to its sender/recipient after current scoped grant
and possession checks. Other members, directory bearer readers and the owner
have no implicit message-reading API. The configured store and local database
operators hold plaintext; this is **not end-to-end encryption**. Source authentication
and authorization-at-insertion are trusted store statements; history readers verify
Agent signatures, not an independently reconstructable historical policy proof.
Do not route confidential messages through an untrusted store.

Client SQLite files are 0600, owned regular files with a POSIX exclusive process
lock; symlinks, shared permissions and concurrent use fail closed. State pins
owner/group/key, origin, audience and configured CA contents. Restart with the same
files restores the original outbox/inbox/cursors. A separately human-issued and
approved replacement grant for the same identity can resume pending sends. Changing
service/CA requires a deliberate future migration design; do not delete state to
"fix" conflicts. Consistently back up both store and client databases using SQLite
backup, including message deduplication and cursor state. Database rollback, disk
loss and cloned private-key recovery are not solved by this transport.

The prototype has no history retention/quota UI, automatic polling daemon,
push/websocket transport, multi-store replication, message-source failover,
E2E encryption, human-browser integration or real product adapters. Challenges
share the admission engine's 256 outstanding-challenge bound; per-peer rate limits
and production DoS hardening remain future operations work. Trusted clocks and
fresh signed policy/revocation delivery are required. Learned changes take effect
on subsequent operations; a member already holding plaintext cannot be made to
forget it. See [operations](operations.md#signed-message-store-and-client-state-v026-unreleased)
and [protocol](protocol.md#signed-network-messages-v026-unreleased).
