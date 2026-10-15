# Configured-peer policy synchronization — v0.18

Verified directory nodes can share the same human-created group policy over
HTTP/TLS. A receiver pulls a full owner-signed snapshot from explicitly configured
sources in priority order and verifies the pinned owner/group before applying it.
Periodic service pull and one-shot HTTP-to-HTTP relay are both available.

This is policy replication, not a full Agent mesh. Agent presence, directory leases, conversations and tasks stay local.
Owner-signed credential revocations now propagate alongside policies.
There is no automatic policy-source trust, leader election or quorum consensus.
Separate [candidate discovery](discovery.md) can locate signed peer endpoints;
those results never populate this trusted source configuration automatically.
The discovery CLI reads this receiver's existing database in read-only mode so
learned signed revocations and its persisted policy age bound also constrain
self-signed candidates; keep this local receiver synchronized.

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
  --policy-max-age 300 \
  --policy-sync-interval 10
```

B attempts an immediate pull, then waits ten seconds after each completed attempt.
Until it receives a valid active policy, it rejects Agent admission. Subsequent
successful pulls apply membership changes or terminal dissolution. The same
snapshot can be received repeatedly. A peer may relay a previously accepted
snapshot to another configured receiver; a relay cannot sign or change it.
An active snapshot stops authorizing 300 seconds after its signed issuance in
this example, even if A keeps serving it successfully. Renew through the existing
human-controlled authority before that deadline, as described below.

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

## Ordered sources and failover

Keep `--policy-peer`/`TAILNET_POLICY_PEER_TOKEN` for one source. For independent
primary/backup credentials, use `--policy-sources-file state/policy-sources.json`
instead. It is mutually exclusive with `--policy-peer`; `--policy-peer-ca` belongs
only to the single-source option. The JSON file contains 1..8 entries and no
credential values:

```json
[
  {
    "url": "https://directory.lan.example:8771",
    "token_env": "TAILNET_LAN_POLICY_TOKEN",
    "ca_cert": "lan-ca.pem"
  },
  {
    "url": "https://backup.YOUR-TAILNET.ts.net:8771",
    "token_env": "TAILNET_BACKUP_POLICY_TOKEN"
  }
]
```

Set both named token variables securely before startup; each needs 32+ ASCII
characters and must authenticate its own source. CA paths are relative to the
JSON file; omission uses system trust. Duplicate URLs, inline tokens, unknown
fields, missing credentials and non-loopback HTTP are rejected. All source
configuration is trusted administrator input; never populate it from discovery.

Each poll tries the primary, then backups on transport/authentication/signature
failure, missing/expired policy, rejected revision/conflict or incomplete
revocation scan. Every source has a separate cursor and generation tracking.
The poll stops after the first source completes its scan with a usable policy
(including terminal dissolution). The next poll starts with the primary again.
This is priority failover, not selecting the newest policy from all peers.

All sources must supply the same pinned owner and original group. A backup cannot
roll back a learned revision, remove a learned revocation or revive a dissolved
group. Verified partial updates persist through failure. Each attempt allows ten
pages per source with a ten-second per-request timeout; slow or backlogged sources
can delay a poll. No directory lock is held during network I/O.

## Signed policy age and renewal

In policy mode, active snapshots authorize only while
`now < issued_at + policy_max_age`. The default is 300 seconds; configure
`--policy-max-age SECONDS` (integer 1..86400) at initial setup. The bound persists:
omitting the flag on restart reuses it, tightening is allowed, increasing it is
rejected. Choose a bound comfortably above polling/renewal intervals and the
minimum ten-second registration lease. Grant-only mode remains unchanged.

`issued_at` is signed by the pinned authority. Duplicate delivery, successful
HTTP contact, failover, revocation scans and process restart cannot refresh it.
New revisions whose signed timestamp is still expired do not help. Before expiry,
the human-controlled authority must renew the existing group policy:

```python
# Load the latest owner-verified snapshot and existing owner key securely.
# Revise the SAME group; never call create_policy during recovery.
renewed = revise_policy(owner, current_policy, approved_members)
```

Distribute the new revision before expiry. Agents/relays never receive the owner
key or mint policy in response to timeouts. Without renewal, retain the original
identity/group and wait: registration/renewal returns 403 and discovery hides
records with stale policy. TTL is capped by policy and grant expiry; less than
ten seconds remaining denies a lease. Expired snapshots can still be stored and
exported for rollback defense and relay but cannot authorize admission. Learned
revocations and terminal dissolution persist after the deadline.

Policy timestamps more than 30 seconds in the future are rejected without changing
accepted state. A clock rollback that puts stored policy more than 30 seconds
ahead also fails closed. Expiry has no added grace. Keep synchronized trusted
wall clocks; this is not secure time or online proof that no newer policy exists.

Upgrading a v0.17 policy database adds the default age bound. Its old snapshot
may already be expired: back up SQLite and prepare a fresh owner-signed revision.
The JWS format is unchanged. v0.17 sources can relay it, but older receivers do
not enforce this bound; do not downgrade the executable to bypass the rule.

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
The one-shot tool remains single-source; failover is a periodic-service feature.
Its acknowledgment confirms copying, not fresh authorization: the target
independently enforces its age bound, including for old relayed snapshots.
Policy or some signed revocations may already have been accepted when a later
page fails; accepted revocations are never undone. If the target acknowledgment is invalid, the command
reports failure, although the target may already have accepted the update.

## Read-protected API and status

| Route | Response |
|---|---|
| GET `/v1/policies` | `{policy: signed-JWS}` or `{policy: null}`; policy mode required |
| GET `/v1/revocations?after=0&limit=100` | Read-protected paginated signed credential-revocation records |
| POST `/v1/policies` | Apply owner-signed snapshot; exact group/revision/state acknowledgment |
| GET `/v1/policy-sync` | Sync state/timestamps/revision, active source index, per-source states/cursors, current `policy` freshness; sync may be disabled |

All listed routes require the receiving service's read bearer token and existing
Host/Origin checks. Policy GET and sync status do not accept query parameters.
POST additionally requires the pinned owner signature. Grant-only mode cannot
export or accept policy snapshots. Status reveals no credentials or detailed
transport exceptions. `last_success` refers to this runtime, not persisted state.

States are `idle`, `waiting` (source has no policy snapshot), `catching_up`
(revocation scan has more pages), `stale`, `synced`, `error` and `stopped`.
`active_source` is a zero-based configured index, or null if no source completed
the latest attempt. `sources` lists each source's last state and cursor; untried
backups need not reflect current reachability. No URL, token, key or exception
detail appears. If some sources are non-error, the aggregate pending state
prefers catching_up, then stale, then waiting; all-source errors report error.

`policy` is evaluated on each status request, even if sync is disabled or has not
polled recently. It has `state`, `revision`, `issued_at`, `expires_at`, `max_age`;
states are missing, fresh, stale, future and dissolved. Grant-only mode reports
`{state: disabled}` in this field. Historical sync success cannot override current
expiry. Replaying a still-fresh policy can count as a successful poll but cannot
change `expires_at`, and is not proof that no newer snapshot exists. Status is exposed by the
service API and is not yet connected to the human UI.

## Consistency and failure limits

- Receivers enforce owner/group pins, monotonic revision/time, same-revision
  conflict rejection and permanent learned dissolution. HTTPS server identity
  and owner signature are separate checks.
- A missing snapshot, unreachable source or bad signature never clears accepted
  state. A still-fresh policy remains usable until its signed deadline, subject
  to grant expiry and learned revocations; expired state fails closed even during
  total outage. Unseen revocations remain possible within that bounded window.
- Lower/conflicting revisions reject that source and try a backup. All invalid
  sources leave sync in error, retaining accepted state. Human administration
  repairs configuration or issues a higher valid revision. Dissolution is terminal.
- This uses ordered sources and full snapshots, with no multi-source convergence,
  signatures from a member quorum, replay-resistant fresh-source attestation
  or task cancellation.
- Source polling is independent of HTTP request handling. Shutdown prevents late
  network responses from applying to a closed database. Network I/O can outlive
  shutdown in a daemon thread; it cannot perform further database writes.

Tests cover actual two-node HTTP/TLS propagation, removal/dissolution, read-token
checks, stale/foreign/conflicting snapshots, empty-source behavior, restart,
background recovery, stop during slow I/O, the one-shot CLI, service startup flags
and certificate CA/hostname rejection. Added cases cover stale/null primaries,
authentication and TLS failures, failback, independent partial cursors, retained
revocations/tombstones, shutdown before fallback, upgrade/expiry and recovery of
the original identity/group. These are loopback tests using synthetic
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

Periodic service sync processes at most ten pages per source per attempt. More pages give
`catching_up`, retaining the cursor for the next attempt. A completed scan restarts
from zero on the next poll, and process restart also starts from zero. Full rescans
catch records behind an earlier cursor after source backup restoration. A source
generation change during a scan resets the cursor. No deleted or missing source
record clears a receiver's learned revocation.

The one-shot relay allows up to 100 pages (10,000 entries). Its acknowledgment
includes `revocations_complete`; exhaustion reports partial progress and exits
nonzero. Use the periodic service for larger histories. A bad signature or page
never advances past the last accepted record. Partial valid updates persist on
failure, while that source reports `error` and another source may be tried. Old
v0.16 sources lack this feed and cannot complete current sync; upgrade sources first.

`last_success` updates only after policy verification and a completed revocation
scan. A null policy can still supply valid revocations to a periodic receiver;
one-shot relay with a null policy makes no changes. Disconnected receivers still
cannot learn new revocations immediately. Polling is full-history work, not an
optimized production replication protocol, and cancelling running tasks remains
unimplemented.

The optional v0.21 [human delivery workflow](policy-delivery.md) explicitly pushes
one selected snapshot to a recipient fixed in the human UI's startup configuration
and records signed readback and age metadata. These recipients are separate from
configured pull sources and discovery candidates. Opening or previewing the UI
does not synchronize, and no discovered endpoint is promoted to either trust list.

## Separate all-source human diagnosis (v0.28)

The gateway's [policy review](policy-review.md) explicitly compares all configured
recipients, including backups hidden by a healthy primary. It persists verified
signed conflict/terminal history and provides fixed-time human renewal consent.
Gateway recipients and directory pull sources are independently configured; there
is no discovery promotion, newest-source selection, quorum or automatic adoption.
Normal directory pulls still follow the ordered failover rules above. Renewed
policy needs separate explicit delivery/pull, and grants retain their own expiry.
