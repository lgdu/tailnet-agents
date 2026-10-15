# Simulated Agent runtime and signed presence — v0.23 (unreleased)

An explicitly started simulation runtime restores one existing Agent key, scoped
grant and human-created group, then renews a directory lease with signed
heartbeats and fresh possession proofs. It starts no product Agent, tool executor,
chat transport or listener at the advertised endpoint. Online status means a
recent authorized heartbeat observed by the configured directory; it does not
establish endpoint reachability or healthy task execution.

## Prerequisites and explicit startup

Install `.[identity]` on Python 3.11+ and POSIX/Linux. The runtime uses `fcntl`
file locking and secure local state-file checks. Preserve the original owner
public pin, Agent private key and exact group ID. The owner private key stays on
the human machine; the runtime needs only the owner's public key.

First have a human [create the signed group](human-policy.md), separately
[issue/install the Agent's grant](credential-issuance.md), approve that exact
credential and [deliver the policy](policy-delivery.md). The directory must run
in persisted `--require-policy` mode with a fresh approved snapshot. Runtime
startup cannot create a group, approve a credential or renew policy/grant expiry.
An unapproved/missing/stale/dissolved policy fails closed.

Save `state/agent-a/record.json`, using your explicitly configured simulation
locator and chosen name. Keep each new record within 4096 normalized JSON bytes:

```json
{
  "name": "Agent A simulation",
  "endpoint": "https://host.lan.example:8901",
  "protocol": "simulation-runtime",
  "skills": ["echo"],
  "ttl_seconds": 30
}
```

The endpoint is HTTPS metadata, without user credentials, query or fragment.
The runtime never probes it. A path may identify an explicitly configured routing
gateway; otherwise separate listeners use distinct ports. Metadata cannot choose
the Agent ID, add permissions or change the receiver's trust configuration.

Start explicitly against one trusted directory origin:

```bash
tailnet-agent-runtime \
  --url https://directory.lan.example:8771 \
  --agent-key state/agent-a/agent.pem \
  --authority-public-key state/owner.pub \
  --grant-file state/agent-a/grant.jwt \
  --group-id YOUR-EXISTING-GROUP-ID \
  --audience YOUR-CONFIGURED-DIRECTORY-AUDIENCE \
  --state state/agent-a/runtime.sqlite3 \
  --record-file state/agent-a/record.json \
  --interval 5 \
  --ca-cert state/lan-ca.pem
```

`python3 -m tailnet_agents.agent_runtime` is equivalent. Use the existing
directory's exact audience agreed through trusted configuration. LAN and Tailscale
use the same hostname/CA-verified TLS transport; use a tailnet HTTPS origin instead
of the LAN origin when appropriate. Omitting `--ca-cert` uses system trust.
HTTP is permitted only for loopback development. Proxies and redirects remain
disabled. No discovered address becomes a trusted directory automatically.
The runtime needs no directory read bearer token.

The process emits JSON `restoring_original_group`, followed by `registered`,
`waiting`, `waiting_authorization`, `conflict`, `offline` or `stopped` observations.
No grant/private key or transport exception contents are printed. Construction
performs no network I/O; the explicitly started loop performs challenge and
registration requests. `--once` sends one heartbeat and exits without an offline
message; that lease expires normally. It exits nonzero when registration is
unconfirmed. Continuous mode waits/retries the same configured group and directory.

Requested TTL is 10–300 seconds, including a ten-second heartbeat with a real
fractional clock. Signed timestamps preserve fractional seconds; existing integer
timestamps remain valid. Interval is 1–60 seconds and must be below the requested
TTL; successful short leases tighten the next wait to at most one third of the
acknowledged lease. Online registration still requires at least ten seconds of
grant and policy validity. Transport consumes the signed heartbeat budget: the
acknowledged remaining lease is rounded down to whole seconds and can be 1–9
seconds even when requesting ten. Less than one full second remaining is rejected.
The directory uses one receipt-time snapshot to calculate that lease and its
expiry, never rounding up or exceeding any signed presence/grant/policy deadline.
Unavailable or unapproved authorization never generates a replacement group or key.

Client requests use two-second socket-operation timeouts and a 1 MiB response
cap. These are not strict whole-loop or shutdown wall-time guarantees. A stop
waits for in-flight I/O before best-effort offline; local sequence-storage failure
sends no heartbeat and waits without resetting state.

## Identity, restart and same-machine operation

Each Agent has its own private runtime SQLite file, mode 0600 or stricter, owned
by the process user. The file binds owner fingerprint, Agent subject and original
group, plus a durable generation/sequence. Replacing those identities fails
startup. The file contains no private key or grant token. A cooperative exclusive
lock prevents two runtimes from sharing that file; symlink/public state paths
are rejected. Use trusted parent directories and one local process per file.

Startup commits the next generation and creates a fresh random boot ID. Heartbeat
sequence numbers commit before network I/O, so skipped numbers after failures
are safe. Restart loads the same key/grant/group and advances generation, retaining
the stable Agent ID. No identity or logical group is generated. The directory
persists accepted generations/sequences through restart and rejects old instances
even if they send higher sequence numbers within their old generation.

Agent B on the same machine uses its own original key, grant, runtime file and
human approval. It may share IP, hostname, display name or Tailscale device with A.
Their independently signed subjects remain separate; stopping/removing one does
not change the other's membership or lease. Reusing a private key represents one
identity, regardless of how many processes hold it.

After the first successful signed heartbeat, that identity cannot fall back to
legacy unsigned-metadata registration on this directory. Retain its runtime state
and use the signed runtime/SDK thereafter. Other legacy identities keep their
existing API behavior. This per-identity migration prevents old clients from
bypassing instance ordering.

## Heartbeats, loss and shutdown

Each Agent-signed token binds owner/group/subject, normalized record hash,
generation, boot ID, sequence, online/offline state and signed issue/expiry time.
Its hash joins record metadata in the fresh proof challenge context. Signatures,
approved grant scope, current policy age, learned revocations and possession
proof must all pass before the directory commits a lease and presence record.
Lease deadline is capped by signed presence, grant and policy expiry. Copying or
replaying an old token with another nonce cannot extend it.

After a lost response, acceptance can be unknown. The next loop sends a higher
sequence with a fresh signature/challenge; it does not renew the grant/policy or
recreate identity. Stop during the challenge prevents the later online POST.
SIGINT/SIGTERM stops the loop and attempts a higher-sequence signed offline update.
If authorization/network is unavailable, this is best effort and the old lease
expires. SIGKILL/crash has no offline announcement; timeouts converge to expired.
Offline is an observation, not member removal or dissolution.

Directory restart retains policies, learned revocations and ordering state but
invalidates all old live leases. A saved signed token alone cannot restore online
status; the Agent must send a fresh heartbeat. Removal/revocation/dissolution and
policy/grant expiry immediately exclude an observation from authorized discovery
and report unauthorized when read. The runtime waits for human-controlled
qualification renewal; an expired local grant sends no network heartbeat and
requires an explicitly installed new grant/restart with the same original state.

## Read point-in-time online/offline observations

With a securely configured `TAILNET_VERIFIED_READ_TOKEN`, run:

```bash
tailnet-presence \
  --url https://directory.lan.example:8771 \
  --authority-public-key state/owner.pub \
  --group-id YOUR-EXISTING-GROUP-ID \
  --ca-cert state/lan-ca.pem \
  --limit 20
```

`python3 -m tailnet_agents.presence` is equivalent. It verifies Agent signatures,
owner/group/subject, record hashes, page ordering and deadline bounds. An observation
already expired by the reader's clock cannot display online. JSON reports
`online`, signed `offline`, lease `expired` or `unauthorized`, together with the
last signed token/record and receiver observation/deadline. The public token is
not a grant, secret or fresh possession proof usable for admission.

Each call reads one page (1–20 subjects). If `has_more` is true, pass its
`next_after` as `--after` for the next page. Pages are separate observations, not
an atomic snapshot of a whole network. Only this directory's signed-runtime
subjects appear; legacy registrations and observations at other replicas are
separate. Read operations never renew leases or contact advertised endpoints.
The local chat UI still shows its separate Echo simulations.

Membership authorization is the authenticated configured directory's current
observation, not an independently verified export of every grant or a receiver-
signed attestation. Heartbeat validity is not permanent reachability. Continue
using trusted synchronized clocks; there is no secure-clock implementation.

## Backup, conflicts and remaining work

Back up runtime state consistently with SQLite's backup API and preserve each
Agent's original key/grant and group reference. The directory has its own database
and ordering history. Stale/restored/cloned runtime state can be fenced by higher
accepted generations. Do not delete state, reset counters, downgrade registration
or create a new group to recover availability. Automated lost-state/counter repair
and strong cloned-key recovery remain future work.

Same-generation different-boot requests conflict and leave the incumbent intact;
higher authorized generations supersede it. These are per-directory ordering
checks, not distributed fencing or protection from a malicious holder of the same
private key choosing larger counters. Local file/backup operators remain trusted.
Presence is not replicated with policy/revocation synchronization. Peer presence
replication, integrated authenticated UI monitoring, candidate-to-runtime trust
handoff, real adapters, mesh chat/tasks and physical LAN/tailnet trials remain open.

Tests use real HTTP/TLS services and distinct synthetic keys, including two live
runtime processes on one host renewing independently, stopping one, restart,
directory lease invalidation, signature/proof/ordering rejection, authorization
loss, clock rollback, pagination and TLS CA/hostname checks.
