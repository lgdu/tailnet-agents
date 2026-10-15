# Configured peer presence replication — v0.25

Directories can explicitly pull signed heartbeat observations from configured
sources in the same existing human-created group. The receiver independently
checks the Agent signature, owner-signed scoped grant, local approved grant IDs,
policy age and learned revocations. Copies are attributed observations in a
separate cache, never local registration leases or new membership.

## Opt in to export and configure sources

An exporter must explicitly enable the new protected route. This exports the
scoped grant alongside each local signed heartbeat so receivers can independently
check authorization. Keep its read credential restricted to trusted replicas.
The ordinary `/v1/presence`, peer-view API and browser monitor do not export grants.

```bash
# Existing directory, existing group and original owner public pin.
tailnet-verified-directory --authority-public-key state/owner.pub \
  --group-id EXISTING-GROUP-ID --audience directory-a \
  --database state/directory-a.sqlite3 --require-policy \
  --presence-export
```

Supply the existing `TAILNET_VERIFIED_READ_TOKEN` securely. Outside loopback,
configure the documented host, certificate/key and allowed hosts; export does not
weaken [TLS deployment](tls-deployment.md). Policy must already be applied or
arrive through separately configured signed-policy synchronization. Runtime
heartbeats still require human-approved grants and fresh possession proofs.

On a receiving directory, configure a file such as `state/presence-sources.json`:

```json
[
  {
    "id": "lan-directory",
    "url": "https://directory.lan.example:8771",
    "group_id": "EXISTING-GROUP-ID",
    "token_env": "TAILNET_PRESENCE_LAN_READ",
    "ca_cert": "lan-ca.pem"
  },
  {
    "id": "tailnet-directory",
    "url": "https://node.YOUR-TAILNET.ts.net:8771",
    "group_id": "EXISTING-GROUP-ID",
    "token_env": "TAILNET_PRESENCE_TAILNET_READ"
  }
]
```

Use 1–8 unique IDs/origins; `local` is reserved for direct observations. Every
source group must match the receiver's pinned group. Credential values stay in
the named environment variables, never JSON or URLs. CA paths are relative to
the file; otherwise system trust applies. The existing recipient-format parser
caps configuration at 16 KiB. HTTPS is required for LAN and Tailscale; only
loopback allows HTTP. Proxies and redirects remain disabled.

```bash
tailnet-verified-directory --authority-public-key state/owner.pub \
  --group-id EXISTING-GROUP-ID --audience directory-b \
  --database state/directory-b.sqlite3 --require-policy \
  --presence-sources-file state/presence-sources.json \
  --presence-sync-interval 5
```

Export and import are independent opt-ins. Configuring sources does not enable
grant export. Discovery results cannot become sources; no group/key/credential
is created, approved or renewed. The receiver needs only the owner public key.
It can also explicitly export its own direct observations, but copied rows are
never exported onward. Configure each desired directed link; this is one-hop
replication, not transitive gossip or automatic peer enrollment.

## State, ordering and expiry

Each poll visits **every** configured source, including after another succeeds
or fails. Each source has its own cursor, credential and CA. A poll processes at
most ten pages of twenty subjects per source; an incomplete scan continues next
poll. A completed scan resets to the beginning for updates/new lower-sorted keys.
Restart starts scanning at the beginning while preserving cached history.
Large histories, slow sources and partitions can delay observation convergence.
The default interval is five seconds; the configurable range is 1–3600 seconds.

A page is validated before its cache/head transaction commits. Earlier valid
pages survive a later failure; malformed pages cannot partially update counters.
No directory lock is held during network I/O. Shutdown prevents a late fetch
from applying after stop; socket-operation timeouts are not a whole-poll bound.

Observed deadlines are capped at the original source lease, Agent signature,
grant and receiver policy expiry **at import time**. For the same configured source binding, repeat copies can only
shorten that deadline. Source expired/unauthorized state is not promoted by
replaying the same claim. Missing/invalid local authorization caches an
unauthorized observation; later qualification or policy renewal requires a new
higher heartbeat before that cached observation can become online. Every read also rechecks current
local policy/grant/revocation. Copies, polling and a new receipt time never renew
a lease or an owner policy. Offline is signed observation state, not removal.

Durable per-subject observation heads compare generation, boot ID, sequence and
the exact signed token. New generations supersede old ones; lower sequences
cannot restore older online claims after offline, expiry or restart. Different
boots in one generation, or contradictory tokens at one sequence, mark that
generation conflicted. A higher signed generation is required to clear it.
Deleting/reconfiguring a source hides its cached rows but does not erase learned
heads; fallback to older known observations remains suppressed.

These heads order the **merged observation view**. They do not change the direct
registration verifier's per-directory fencing, and do not provide distributed
locks or protection from a malicious holder of a cloned key choosing larger
counters. Direct APIs keep their existing local scope. Trusted synchronized wall
clocks and private, non-rolled-back SQLite state remain assumptions.

## Read the attributed view

```bash
tailnet-peer-presence --url https://directory-b.YOUR-TAILNET.ts.net:8771 \
  --authority-public-key state/owner.pub --group-id EXISTING-GROUP-ID
```

Supply the receiver's `TAILNET_VERIFIED_READ_TOKEN`; optionally set `--ca-cert`,
`--after SUBJECT` and `--limit 1..20`. The CLI checks scope, Agent signatures,
head/source consistency and deadlines. It does not follow advertised endpoints.
GET `/v1/peer-presence` returns the same protected view, grouping observations by
Agent public-key subject. Shared names, IPs, endpoints or Tailscale devices never
merge distinct keys. Each observation has its source ID/origin, observation and
receipt times, effective expiry and state. Local direct data uses source `local`.

Subject states are online, offline, expired, unauthorized, superseded or conflict.
Online means at least one matching-head observation remains authorized and
unexpired. A subject is never promoted from an older claim when the newest known
claim expires or its source disappears. Pages keep all observations for a subject
together, up to eight configured sources plus local. A 512 KiB entry budget can
return fewer than the requested subjects; continue with the returned cursor.
Pages are independent reads, not an atomic network snapshot.

GET `/v1/presence-sync` reports per-source synced/catching_up/error, cursor and
last completed-scan time, without credentials or transport exception contents.
The v0.24 human monitor still reads a selected directory's **direct** presence;
a relayed-observation UI is not implemented. Use this separate API/CLI for copies.

## Persistence and limits

Cache rows and observation heads share the existing private directory SQLite
transaction/backup boundary. Backups now contain copied scoped grants; protect
them along with WAL/journal files. Restart keeps the original owner/group and
ordering. Cached remote observations retain their original deadlines and source
attribution; they are historical observations, not restored local live leases.
Direct local leases still require a new heartbeat after directory restart.
Original source bindings must be explicitly configured again to show cached rows.
No automatic retention/pruning, rollback resistance or lost-counter repair exists.

The Agent signature and owner grant prove identity and current qualification;
the source's receipt/state remains an authenticated transport observation, not a
receiver-signed attestation or an independently exported original admission proof.
Local revocations apply immediately once learned; unseen remote revocations still
have the existing partition/freshness limits. Source failure/absence is not a
member removal or terminal offline assertion.

No copied row enters `/v1/agents`, local registration, discovery announcements,
Echo chat, task execution or group creation. No real product Agent, cross-node
messages, durable task executor, multi-hop gossip, relayed human UI, key rotation
or physical LAN/Tailscale/WAN validation is included. Those are later stages.
