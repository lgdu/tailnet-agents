# Configured-peer policy synchronization — v0.17

Verified directory nodes can share the same human-created group policy over
HTTP/TLS. A receiver pulls a full owner-signed snapshot from one explicitly
configured source and verifies the pinned owner/group before applying it.
Periodic service pull and one-shot HTTP-to-HTTP relay are both available.

This is policy replication, not a full Agent mesh. Agent presence, directory leases, conversations and tasks stay local.
Owner-signed credential revocations now propagate alongside policies.
There is no automatic peer discovery, leader election or source failover.

## Two nodes on one machine

Prepare a human-created group and approved signed snapshot using
[group policy](group-policy.md). Both nodes must have the same trusted public-key
file and exact group ID. The owner private key remains on the administrator
machine. Use distinct databases and read tokens for the two services.

Start source A in one terminal, setting `TAILNET_VERIFIED_READ_TOKEN` to A's
32+ character ASCII read credential:

```bash
python3 -m tailnet_agents.admission_server \
  --authority-public-key state/owner.pub \
  --group-id YOUR-EXACT-GROUP-ID \
  --audience node-a \
  --port 8771 \
  --database state/node-a.sqlite3 \
  --require-policy --policy-file state/group.policy
```

In another terminal, set `TAILNET_VERIFIED_READ_TOKEN` to B's read credential and
`TAILNET_POLICY_PEER_TOKEN` to A's read credential, then start receiver B:

```bash
python3 -m tailnet_agents.admission_server \
  --authority-public-key state/owner.pub \
  --group-id YOUR-EXACT-GROUP-ID \
  --audience node-b \
  --port 8772 \
  --database state/node-b.sqlite3 \
  --require-policy \
  --policy-peer http://127.0.0.1:8771 \
  --policy-sync-interval 10
```

B attempts an immediate pull, then waits ten seconds after each completed attempt.
Until it receives a valid active policy, it rejects Agent admission. Subsequent
successful pulls apply membership changes or terminal dissolution. The same
snapshot can be received repeatedly. A peer may relay a previously accepted
snapshot to another configured receiver; a relay cannot sign or change it.

B's private-key-possession challenges still use audience `node-b`. Registering
at A does not register at B; each node requires fresh proof and maintains its own
leases. Policy is saved in B's SQLite database and is available after restart,
before contacting A. Discovery failure never creates a group or identity.

## LAN and Tailscale

Follow [TLS deployment](tls-deployment.md) for **both** service listeners.
Each non-loopback listener requires its own TLS certificate/key and explicit
allowed hostname/IP configuration. In B's command replace the source URL with
A's actual HTTPS hostname and add `--policy-peer-ca state/source-ca.pem` for a
private CA. The URL hostname must match A's certificate SAN.

Omitting the peer CA uses system trust. Source token and source URL are trusted
administrator configuration, never learned from an unauthenticated broadcast.
Redirects are not followed and ambient HTTP proxies are disabled. This setup
works independently of whether connectivity is provided by LAN or Tailscale;
actual cross-machine deployments remain to be validated.

## One-shot relay without reopening a live database

With A's token in `TAILNET_POLICY_PEER_TOKEN`, B's token in
`TAILNET_VERIFIED_READ_TOKEN`, and the pinned public key/group:

```bash
python3 -m tailnet_agents.policy_sync \
  --source-url http://127.0.0.1:8771 \
  --target-url http://127.0.0.1:8772 \
  --authority-public-key state/owner.pub \
  --group-id YOUR-EXACT-GROUP-ID
```

The installed entry point is `tailnet-policy-sync`. For private HTTPS CAs use
`--source-ca-cert` and `--target-ca-cert`. The relay verifies A's signed snapshot
locally, then submits it to B's existing read-token-and-signature protected route.
It never opens either running service's database. Empty policy source exits before relay. Invalid policy, authentication/transport
failure or rejected update exits nonzero with a generic error and no token output.
Policy or some signed revocations may already have been accepted when a later
page fails; accepted revocations are never undone. If the target acknowledgment is invalid, the command
reports failure, although the target may already have accepted the update.

## Read-protected API and status

| Route | Response |
|---|---|
| GET `/v1/policies` | `{policy: signed-JWS}` or `{policy: null}`; policy mode required |
| GET `/v1/revocations?after=0&limit=100` | Read-protected paginated signed credential-revocation records |
| POST `/v1/policies` | Apply owner-signed snapshot; exact group/revision/state acknowledgment |
| GET `/v1/policy-sync` | Synchronizer state, last attempt/success epoch timestamps, accepted revision and revocation cursor; or `{state: disabled}` |

All listed routes require the receiving service's read bearer token and existing
Host/Origin checks. Policy GET and sync status do not accept query parameters.
POST additionally requires the pinned owner signature. Grant-only mode cannot
export or accept policy snapshots. Status reveals no credentials or detailed
transport exceptions. `last_success` refers to this runtime, not persisted state.

States are `idle`, `waiting` (source has no policy snapshot), `catching_up`
(revocation scan has more pages), `synced`, `error` and
`stopped`. Receiving the same valid snapshot counts as a successful attempt; it
is not proof that no newer snapshot exists elsewhere. Status is exposed by the
service API and is not yet connected to the human UI.

## Consistency and failure limits

- Receivers enforce owner/group pins, monotonic revision/time, same-revision
  conflict rejection and permanent learned dissolution. HTTPS server identity
  and owner signature are separate checks.
- A missing snapshot, unreachable source or bad signature never clears accepted
  state. The last accepted policy continues to govern admission. There is no
  maximum policy age or fail-closed freshness lease in this version. A removed
  member can remain authorized on a disconnected receiver until the change is
  learned, subject to credential expiry and local credential revocations.
- Lower revisions and conflicting equal revisions put sync into `error`; the
  receiver keeps its accepted snapshot. Human administration must repair source
  configuration or issue a higher valid revision. A dissolved receiver cannot
  be revived by a higher active revision.
- This uses one fixed source and full snapshots, with no multi-source convergence,
  signatures from a member quorum, replay-resistant fresh-source attestation
  or task cancellation.
- Source polling is independent of HTTP request handling. Shutdown prevents late
  network responses from applying to a closed database. Network I/O can outlive
  shutdown in a daemon thread; it cannot perform further database writes.

Tests cover actual two-node HTTP/TLS propagation, removal/dissolution, read-token
checks, stale/foreign/conflicting snapshots, empty-source behavior, restart,
background recovery, stop during slow I/O, the one-shot CLI, service startup flags
and certificate CA/hostname rejection. These are loopback tests using synthetic
Agent identities, not real product adapters or WAN trials.

## Signed credential-revocation feed (v0.17)

GET `/v1/revocations?after=0&limit=100` requires the source read token. `after`
is a nonnegative integer cursor, `limit` is 1..100. The response has exactly
`generation`, `entries`, `next_cursor`, `has_more`. Entries contain `sequence`
and the separately typed owner-signed `revocation` JWS. Sequences are source-local
SQLite row IDs, not globally trusted versions. Generation is a persisted random
source database identifier, not a membership identity or signed freshness proof.

Each signed record must match the pinned owner/group and contain a valid grant
ID. Receipt inserts it idempotently into the receiver's durable revocation set;
that credential can no longer register/renew or appear in discovery even if
policy still lists it. Relays can export learned signed records without re-signing.
There is no un-revoke operation; issue and explicitly approve a new credential.

Periodic service sync processes at most ten pages per attempt. More pages give
`catching_up`, retaining the cursor for the next attempt. A completed scan restarts
from zero on the next poll, and process restart also starts from zero. Full rescans
catch records behind an earlier cursor after source backup restoration. A source
generation change during a scan resets the cursor. No deleted or missing source
record clears a receiver's learned revocation.

The one-shot relay allows up to 100 pages (10,000 entries). Its acknowledgment
includes `revocations_complete`; exhaustion reports partial progress and exits
nonzero. Use the periodic service for larger histories. A bad signature or page
never advances past the last accepted record. Partial valid updates persist on
failure, while sync reports `error`. Old v0.16 sources lack this feed and therefore
cannot produce a successful v0.17 sync; upgrade sources before receivers.

`last_success` updates only after policy verification and a completed revocation
scan. A null policy can still supply valid revocations to a periodic receiver;
one-shot relay with a null policy makes no changes. Disconnected receivers still
cannot learn new revocations immediately. Polling is full-history work, not an
optimized production replication protocol, and cancelling running tasks remains
unimplemented.
