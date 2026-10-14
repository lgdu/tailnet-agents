# Configured-peer policy synchronization — v0.16

Verified directory nodes can share the same human-created group policy over
HTTP/TLS. A receiver pulls a full owner-signed snapshot from one explicitly
configured source and verifies the pinned owner/group before applying it.
Periodic service pull and one-shot HTTP-to-HTTP relay are both available.

This is policy replication, not a full Agent mesh. Agent presence, directory
leases, conversations, tasks and per-credential revocation records stay local.
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
It never opens either running service's database. Empty source, invalid policy,
authentication/transport failure or rejected update exits nonzero with a generic
error and no token output. If the target acknowledgment is invalid, the command
reports failure, although the target may already have accepted the update.

## Read-protected API and status

| Route | Response |
|---|---|
| GET `/v1/policies` | `{policy: signed-JWS}` or `{policy: null}`; policy mode required |
| POST `/v1/policies` | Apply owner-signed snapshot; exact group/revision/state acknowledgment |
| GET `/v1/policy-sync` | Synchronizer state, last attempt/success epoch timestamps and accepted revision; or `{state: disabled}` |

All three routes require the receiving service's read bearer token and existing
Host/Origin checks. Policy GET and sync status do not accept query parameters.
POST additionally requires the pinned owner signature. Grant-only mode cannot
export or accept policy snapshots. Status reveals no credentials or detailed
transport exceptions. `last_success` refers to this runtime, not persisted state.

States are `idle`, `waiting` (source has no snapshot), `synced`, `error` and
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
  signatures from a member quorum, replay-resistant fresh-source attestation,
  per-credential revocation replication or task cancellation.
- Source polling is independent of HTTP request handling. Shutdown prevents late
  network responses from applying to a closed database. Network I/O can outlive
  shutdown in a daemon thread; it cannot perform further database writes.

Tests cover actual two-node HTTP/TLS propagation, removal/dissolution, read-token
checks, stale/foreign/conflicting snapshots, empty-source behavior, restart,
background recovery, stop during slow I/O, the one-shot CLI, service startup flags
and certificate CA/hostname rejection. These are loopback tests using synthetic
Agent identities, not real product adapters or WAN trials.
