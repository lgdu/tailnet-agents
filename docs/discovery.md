# Existing-group candidate discovery — v0.19

This optional layer locates candidate directory endpoints using signed IPv4 UDP
multicast announcements and explicitly configured HTTP/TLS seeds. It uses the
identity extra and existing human-approved policy. It neither creates a group nor
registers an Agent, issues credentials, starts an executor or adds a policy source.

## Trust and disclosure boundary

A human must already have created the group, approved the simulation identity in
its signed policy and provisioned the local public-key pin and a policy-mode
directory database maintained by trusted administration or configured-source sync.
Load the existing Agent key; do not generate a replacement at startup. Keep the
owner private key exclusively with human-controlled administration.

Several independently approved Agents may share a LAN IP, hostname or Tailscale
device. Give each Agent its own persistent key and scoped grant; separate
publishers/listeners use distinct ports and state databases. Configure each
publisher with that Agent's original `--discovery-agent-key` and endpoint. Results
merge by verified subject, never by host or display name. Two keys on the same
host remain two candidates. Conflicting locators for one reused/cloned key affect
only that subject, not other Agents on the machine. Discovery of either candidate
does not register it or authorize its peers.

Publishers sign minimal metadata with the approved identity key. No bearer token,
grant, private key, member list, capability list, chat or task data is sent.
The public discovery route and LAN multicast are disabled by default. Enabling
them intentionally discloses group ID, public identity, policy fingerprint,
endpoint and audience to listeners; this prototype has no encrypted discovery.

Scanners verify the signature, exact group and local policy fingerprint, signed
age and presence of the subject in the fresh active local policy, excluding
identities whose approved grant IDs are all locally revoked. The CLI reads signed
policy, signed relevant revocations and the persisted age bound from the same
directory database. A signature
identifies the candidate; it does not prove possession of an unexpired grant,
the endpoint's TLS identity or live endpoint ownership. Results always say
`admission: not_checked`. Existing registration still requires a valid approved
grant and fresh audience/context-bound possession proof. Discovery never calls
registration or policy-update routes, follows advertised addresses, copies seed
credentials or promotes discovered URLs into the trusted policy-source list.

## Enable a seed on the verified service

Install `.[identity]` and follow [signed group policy](group-policy.md) to prepare
`state/owner.pub`, `state/group.policy` and an already approved simulation key
`state/agent.pem`. Set the service's normal `TAILNET_VERIFIED_READ_TOKEN` securely;
it still protects all existing policy, revocation and registration-list routes.
The scanner does not need or send that token.

For a local-only demonstration:

```bash
python3 -m tailnet_agents.admission_server \
  --authority-public-key state/owner.pub \
  --group-id YOUR-EXISTING-GROUP-ID \
  --audience directory-a \
  --database state/directory-a.sqlite3 \
  --require-policy --policy-file state/group.policy \
  --discovery-agent-key state/agent.pem \
  --discovery-endpoint http://127.0.0.1:8771
```

Both discovery flags are required together, and signed policy mode is required.
`GET /v1/discovery` returns `{announcement: {public_key, announcement}}` without
read authentication, retaining Host/Origin checks and rejecting query parameters.
The nested announcement is typed Ed25519 JWS. Missing/stale/dissolved policy,
an unapproved identity or revocation of all its locally approved grant IDs gives
503 and suppresses LAN broadcasts. With discovery disabled the route returns 404.
Existing protected routes retain their bearer authentication.

Policy updates and learned revocations come from the existing directory database,
including configured-source synchronization. An identity with some approved
grant IDs not locally revoked may announce candidates, but actual grant validity
is deliberately rechecked only during admission. There is no background grant
renewal, re-signing of owner policy or automatic enrollment.

## LAN multicast

For actual LAN use configure the service's [TLS listener](tls-deployment.md) and
advertise its exact HTTPS origin, not a loopback URL. Explicitly add:

```bash
--discovery-lan-interface 192.168.1.20
```

Use an address actually assigned to the selected local interface. The service
sends one signed datagram immediately, then every five seconds to
`239.255.77.77:8773`, with multicast TTL 1. It does not answer UDP queries or
reflect packets. Use `--discovery-lan-port` to select another explicit port, and
match it on scanners. There is no automatic NIC selection, broadcast to all
interfaces, multicast routing, mDNS/DNS-SD implementation or Tailscale enumeration.

On another approved node with the same current policy and owner public key,
use that node's existing, synchronized directory database:

```bash
python3 -m tailnet_agents.discovery \
  --authority-public-key state/owner.pub \
  --group-id YOUR-EXISTING-GROUP-ID \
  --directory-database state/directory-a.sqlite3 \
  --lan-interface 192.168.1.21 \
  --duration 6
```

The window is 0.1–10 seconds (default 6), with 4096 bytes per message and at most
128 verification attempts per second. Reaching that rate limit pauses verification
until the next second; it does not end the scan early. The default overlaps the five-second broadcast interval;
a shorter window may miss an existing service. Oversized, malformed, foreign,
stale and unknown-identity records are
ignored. LAN receiving requires Linux `IP_PKTINFO` and an explicit local primary
IPv4 address (secondary/alias addresses are not supported). The socket binds the
discovery multicast destination, disables `IP_MULTICAST_ALL`, and verifies each
packet's ingress interface index and multicast destination before it reaches the
verification budget. Unicast, wrong-interface, missing-metadata and truncated
packets are discarded. TTL 1 limits outbound traffic; receive filtering enforces
the input boundary. Unsupported platforms fail closed; HTTPS seeds remain usable.
Guest isolation or blocked
multicast can yield no candidates; use explicitly configured seeds instead.
Invalid interface setup fails rather than silently selecting another NIC.

## LAN and Tailscale seed configuration

Save trusted `state/discovery-seeds.json` without credentials:

```json
[
  {"url": "https://directory.lan.example:8771", "ca_cert": "lan-ca.pem"},
  {"url": "https://node.YOUR-TAILNET.ts.net:8771"}
]
```

Configure 1–8 origins, with no paths/query/user info, token or environment-variable
fields. CA paths are relative to this file; omission uses system trust. Outside
loopback HTTPS is mandatory, including on Tailscale. Certificate chain and
hostname checking remain enabled; proxies and redirects are disabled. Requests
contain no Authorization or Cookie headers, regardless of process credentials.
Each request uses a two-second socket-operation timeout and a 4096-byte body cap;
this is not a strict whole-scan wall-time deadline or a hardened HTTP client.

```bash
python3 -m tailnet_agents.discovery \
  --authority-public-key state/owner.pub \
  --group-id YOUR-EXISTING-GROUP-ID \
  --directory-database state/directory-a.sqlite3 \
  --seeds-file state/discovery-seeds.json
```

The installed equivalent is `tailnet-discover`. Add `--lan-interface` to combine
providers. Only the configured seed origins receive HTTP requests; candidate
URLs are not probed. Per-seed errors do not erase candidates from working seeds.
The CLI requires `--directory-database`; there is no static-policy-file fallback.
It opens the existing database in SQLite read-only mode without constructing a
directory service, creating a database, changing registrations or resetting leases.
The pinned owner/group and persisted policy mode must match. The persisted age
bound applies (directory default 300 seconds); optional `--policy-max-age` may only
tighten it. Relevant stored revocations are signature-checked against the owner.
The library's standalone `Candidates(...)` accepts an explicit snapshot/revoked
set; its caller is responsible for updating that state. The CLI always uses
`Candidates.from_directory(...)`.

## Results, expiry and recovery

Results contain `candidates`, `conflicts` and `seeds` (each seed's ok/error status).
Candidates merge by verified subject identity, never by IP address or display
name. The result includes locator, audience, group, signed timestamps, policy
hash, observed provider labels and `admission: not_checked`. Seeing a second
distinct locator/audience for the same key sets a sticky conflict for the entire
scan, including after either announcement expires or a third locator is dropped.
That candidate is withheld and its subject appears in `conflicts`; only a new
scan clears this state. No winner or automatic task migration is chosen. Provider
labels describe the retained announcement version only: a newer issue time resets
sources, identical claims merge sources, and older/different claims add no source.

Announcements expire in at most 30 seconds and never beyond the publisher's
policy deadline. More than five seconds of future announcement time is rejected.
Replay/duplicate delivery does not extend the signed expiry. The scanner also
checks freshness at output and drops expired or clock-future records. It re-reads
the authoritative database before output, applies newly learned revocations and
tighter age bounds, and aborts with a retry requirement if the policy changed.
The read snapshot is the output's consistency point; later updates require another
scan. Empty or
conflict-only results exit nonzero; empty discovery never creates a new group.

Restart loads the same key and group/database. Leases still require fresh proof
after restart. A scanner uses the locally synchronized directory state, never
policy or revocations sent in discovery. Keep that directory updated through
trusted administration or existing policy replication. Missing/stale policy
stops discovery and admission until human-authorized renewal, preserving state.

## Verified scope and remaining work

Tests use synthetic identities, actual local UDP multicast, HTTP/TLS services and
CLI/service subprocesses. They verify signatures/scopes, no credential leakage,
expiry/replay, conflict handling, CA/hostname and redirect rejection, bounded
flood handling, opt-in routes, original identity/group after restart, read-only
lease preservation, mid-scan state changes and revoked self-signed CLI candidates
over both LAN and seeds. No real product Agent is connected.

Physical LAN/tailnet/WAN trials, multicast across real NICs/routers/firewalls,
mDNS, tailnet peer APIs, relay-resistant channel binding, cloned-key fencing,
immediate delivery of unseen remote revocations, UI enrollment and full
mesh integration remain unimplemented or unvalidated. Announcements are locators,
not proof of remote health, global membership or permission to execute work.
Same-interface multicast floods can still congest UDP queues or consume the
verification rate; this is not comprehensive denial-of-service protection.

## Separate configured runtime handoff (v0.23, unreleased)

The [simulation runtime](agent-runtime.md) renews signed heartbeat leases only
after a human explicitly supplies a trusted directory origin/audience, original
key, scoped grant and existing group. Candidate scanning never starts it, copies
credentials to a candidate or promotes a candidate into trusted configuration.
The directory still verifies approved grants, current policy and fresh possession.
Signed candidate announcements and signed runtime presence use different message
types and cannot substitute for each other.
