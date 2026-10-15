# Discovery protocol v0.1

This custom prototype API is not an A2A standard registry API.

## Bootstrap and identity

Each bridge receives one registry HTTPS URL and an owner-specific credential.
One machine can publish multiple stable agent IDs. Tailscale machine identity
and agent identity are separate. Registering an endpoint does not authorize tasks.
All registered agents are visible to authenticated registry clients in v0.1.

## API

| Method | Path | Behavior |
|---|---|---|
| GET | `/healthz` | Unauthenticated process health |
| GET | `/v1/status` | Authenticated aggregate registered/online/stale counts |
| DELETE | `/v1/agents/{id}` | Owner-only deregistration; unknown/other-owner returns 404 |
| POST | `/v1/agents` | Register or renew owner-controlled agent |
| GET | `/v1/agents?skill=coding` | List live records, optional exact skill filter |

Both agent endpoints require `Authorization: Bearer TOKEN`.
POST JSON: `id`, optional `name`, `endpoint` (HTTPS), optional `protocol`,
optional `skills` (string array), optional `ttl_seconds` (10–300, default 60).
POST returns `id` and `ttl_seconds`. GET returns `{"agents": [...]}`.
Errors: 400 invalid metadata, 403 unauthorized or ownership conflict,
404 unknown path, 413 missing/oversized POST body.

Lease expiry excludes records from discovery; SQLite retains owner reservations
across restart. Restart invalidates old leases until renewed. Explicit owner
deregistration releases the ID. Discovery is a snapshot; clients poll in v0.1.
Credentials and model API keys never appear in registration records.

## Intended execution layer (not implemented)

Registry endpoints identify adapters; callers negotiate the advertised protocol.
A2A is the intended standard task interface. Adapters must preserve task identity,
execution provenance and product permission boundaries. Network discovery does
not imply access to another agent's memory, filesystem or user approvals.
Future bridges must bound delegation depth and deduplicate retries to prevent
agent loops and duplicate side effects.

## Custom task transport v0.1 (implemented in v0.2)

Registration declares `protocol: "tailnet-task-v0.1"` and an HTTPS origin.
This API does not claim compatibility with A2A.

| Method | Path | Behavior |
|---|---|---|
| POST | `/v1/tasks` | Submit `message` and `idempotency_key`; return 202 and task |
| GET | `/v1/tasks/{id}` | Return caller-owned task; unknown or other-owner IDs return 404 |

Both requests require a bridge-specific Bearer token. Task fields are `id`,
`status` (`queued`, `running`, `completed`, `failed`), `result` and `error`.
Repeated keys with identical messages return the same task. Changed messages
return 409. New tasks at capacity return 429. There is no cancellation endpoint.
Task IDs and deduplication keys are process-local and disappear on restart.

Bridges renew registration every TTL/3 and retry registry connection failures.
The CLI polls discovery; there is no watch/subscription API or peer cache yet.
Only the Echo adapter is implemented. A2A and product execution remain planned.

## Optional identity component (v0.11)

[Identity primitives](identity.md) implement scoped signed grants and possession
proofs offline. They do not change the registry/task API above; bearer
authentication remains in place until an explicit transport integration revision.

## Verified directory library integration (v0.12)

[VerifiedDirectory](verified-directory.md) enforces signed admission for its
in-process registration path. It does not replace or expose the HTTP endpoints
above. The separate service below supplies network admission and read authorization.

## Loopback signed admission HTTP (v0.13)

[Admission HTTP](admission-http.md) is a separate service with challenge/register/
revoke routes. It does not change the bearer registry/task APIs above.
TLS and optional signed group policy were added by the following revisions.

## Direct TLS admission transport (v0.14)

The separate verified service supports explicit TLS binding and CA-verified
clients. See [TLS deployment](tls-deployment.md). This does not change ordinary
registry/Bridge APIs or implement automatic LAN/tailnet discovery.

## Signed group policy (v0.15)

The separate verified service optionally requires a durable owner-signed member
snapshot. POST `/v1/policies` requires its read token plus an owner signature.
Registration and discovery reject unapproved grant IDs, removed members and
dissolved groups. Stale/conflicting snapshots are rejected; enforcement mode
and learned dissolution persist across restart. Existing grant-only mode stays
compatible. See [group policy](group-policy.md) for schema, migration and
partition/backup limits. No task receiver or UI signing flow is added.

## Configured-peer policy pull (v0.16)

GET `/v1/policies` on the separate verified service requires its read token and
policy mode, and returns `{policy}` with a signed snapshot or null. An explicitly
configured receiver verifies pinned owner/group, then applies its existing
revision/conflict/dissolution checks. Periodic pull and one-shot HTTP/TLS relay
are available; GET `/v1/policy-sync` exposes read-protected synchronization status.
Null/errors never create groups or clear accepted policy. This replicates policy
only, not presence, credential-revocation records, conversations or tasks.
See [policy synchronization](policy-sync.md) for deployment and freshness limits.

## Signed credential-revocation replication (v0.17)

The configured-peer synchronizer additionally pulls GET `/v1/revocations`, using
bounded pages and independent verification of each owner-signed group/jti record.
Accepted revocations persist, are relayed unchanged, and are never removed by
policy updates or missing source records. Cursor checkpoints are routing hints;
completed scans and process restart rescan from zero. See [policy sync](policy-sync.md)
for the response schema, partial-progress behavior and version compatibility.

## Signed policy age and ordered sources (v0.18)

Policy JWS and update acknowledgments retain their existing wire format. In
policy mode, active authorization requires `now < issued_at + max_age`;
default max_age is 300 seconds and the local bound persists across restart.
Increasing a persisted bound or disabling policy mode is rejected. Timestamps
over 30 seconds in the future are rejected; expired snapshots can still be stored
and relayed for monotonicity but cannot authorize registration/discovery. Leases
are capped by policy and grant expiry. Learned dissolution/revocations never expire.

GET `/v1/policy-sync` adds `policy` freshness, plus `active_source` and `sources`
when synchronization is configured. Policy status includes state, revision,
issued_at, expires_at and max_age, evaluated even with sync disabled.
Expired registration/renewal returns the existing generic 403; discovery omits
affected records. `/healthz` remains liveness, not authorization readiness.

The periodic service tries 1..8 explicitly ordered sources with independent
credentials/CA/cursors. Failure, null/stale policy, invalid revision/signature or
incomplete revocations triggers fallback. Identical owner/group, rollback,
conflict and terminal-state checks apply to each source. Partial verified records
persist; polling/failover cannot extend signed authorization. There is no new
discovery route, membership grant, quorum or real Agent adapter.

## Signed candidate locators (v0.19)

An explicitly enabled GET `/v1/discovery` returns
`{announcement: {public_key, announcement}}` with no bearer authentication, under
the verified service's existing Host/Origin checks. Disabled is 404, invalid
queries 400 and unavailable fresh approved policy 503. Other routes retain their
existing authentication. `public_key` is raw base64url Ed25519 public material;
`announcement` is JWS with type `tailnet-discovery+jwt`.

Exact signed fields: `version` (integer 1), `group_id`, `subject`, `policy_hash`
(SHA-256 of the locally trusted signed policy token), `endpoint` (canonical
HTTP/TLS origin, HTTPS except loopback), `audience`, `issued_at`, `expires_at`.
Expiry is at most 30 seconds after issue and no later than publisher policy expiry;
over five seconds of future issue time is rejected. Owner/group and active local
policy must match, and the subject must be locally approved with at least one
approved grant ID not locally revoked. No grant/token/key
secrets, policy body, membership list or capabilities are carried.

Optional IPv4 multicast sends the inner envelope to `239.255.77.77:8773`, TTL 1,
on an explicitly selected interface every five seconds. No UDP requests/replies.
The custom protocol is not mDNS, A2A or automatic tailnet peer enumeration. Scans
limit packets to 4096 bytes and 128 verification attempts per second, resuming in
the next second instead of stopping early. Linux IP_PKTINFO verifies the selected
ingress interface and multicast destination before verification. Unicast,
truncation and missing metadata are rejected. Unsupported platforms or non-primary
IPv4 interface addresses fail closed for LAN reception. Configured seeds limit responses to
4096 bytes and sources to eight. Only configured seed origins are queried, with
no Authorization/Cookie headers or ambient proxies; redirects are rejected and
TLS validation remains enabled.

Merge by signed identity; any second locator/audience sets a sticky conflict for
that scan, unaffected by expiry or discarded third locators. Sources describe
only the retained announcement version; old replays cannot add source labels.
The scanner CLI reads an existing policy-mode directory database read-only,
including signed relevant revocations and its persisted age bound. It re-reads
before output, applies new revocations/tighter bounds, and fails for retry on
policy changes. It never creates a directory or resets registration leases.
Results include `admission: not_checked`; no route makes a candidate an admitted
member, execution authority or trusted policy source. Registration still requires
the existing valid grant and fresh bound possession proof. See [discovery](discovery.md)
for configuration, synchronized policy checks, replay and validation limits.

## Human policy administration (v0.20)

These routes belong only to the loopback UI, retaining its human bearer role,
Host and Origin checks. The directory wire format and HTTP routes are unchanged.
These v0.20 routes do not accept a private key, issue a grant, select a remote
recipient or register an Agent. Signer configuration loads only from trusted startup flags.

| Route | Behavior |
|---|---|
| GET `/api/policy-config` | Authenticated enabled/can_sign flags; no key material |
| POST `/api/groups` | Optional boolean `signed_policy`; true requires configured signer admin; creates an empty signed policy with the local group's exact ID |
| GET `/api/group-policy?group_id=...` | Signer admin + creator only; signed policy, claims, owner public pin and latest 50 policy audit records |
| POST `/api/policy-preview` | `group_id`, `grant`; verifies pre-issued grant and returns subject, expiry, grant permissions, proposed complete membership scope and current revision without mutation |
| POST `/api/policy-approve` | `group_id`, `grant`, `expected_revision`, `request_id`; approve its scoped identity/grant ID |
| POST `/api/policy-remove` | `group_id`, `subject`, `expected_revision`, `request_id`; remove all that identity's approved IDs and retire them locally |
| POST `/api/policy-renew` | `group_id`, `expected_revision`, `request_id`; explicitly sign a higher revision with unchanged membership |
| POST `/api/group-dissolve` | Existing exact-name confirmation also signs terminal policy when this is a signed group |

All policy operations require the configured signer admin and group creator.
Only active groups can change or retry policy operations. Expected revision and changed retry-payload
conflicts return 409; identical committed retries return the original acknowledgment
without signing again. Invalid schema/grants return 400 and unauthorized access
returns 403. Removal retires IDs within this UI database, not a new distributed
credential-revocation proof. A new grant ID is needed for UI readmission.
Downloads carry the existing signed policy JWS and can be explicitly applied
through the directory's protected policy route or the v0.21 delivery workflow. No received/advertised URL becomes
trusted automatically. See [human policy signing](human-policy.md).

## Explicit policy delivery (v0.21)

These additional loopback UI routes require the configured signer admin and
group creator. Recipient URLs, read tokens and CA files come only from trusted
startup configuration. No route accepts an arbitrary destination or credential.
The existing directory routes and signed policy format are unchanged.

| Route | Behavior |
|---|---|
| GET `/api/policy-targets?group_id=...` | Configured recipients for this existing signed group; ID, URL, group and fingerprint, never tokens |
| GET `/api/policy-deliveries?group_id=...` | Latest 20 persisted attempts and historical receipts |
| POST `/api/policy-delivery-preview` | `group_id`, `target_id`, `expected_revision`, `policy_hash`; local consent preview with no remote request |
| POST `/api/policy-deliver` | Those fields plus `target_fingerprint`, `request_id`; explicit delivery and verified readback |

The group-policy export also includes `policy_hash`, the SHA-256 of the exact
signed token. Consent binds this hash, revision and recipient fingerprint.
Delivery verifies the recipient's current signed policy, sends only an older or
empty recipient the selected snapshot, and reads back the exact signed copy and
`/v1/policy-sync` age metadata. A receipt records target, group, revision, hash,
policy/authorization state, `max_age`, `expires_at` and `checked_at`. Success can
report an expired copy; it never renews or registers anything.

409 reports stale consent, changed retry payload or remote revision conflict.
502 reports an unknown network/protocol outcome: the copy may already have been
applied. An explicit retry reads back an identical copy before considering POST.
A completed identical request returns its original receipt without remote I/O.
Receipts are point-in-time evidence, not live receiver status. Local changes
during I/O can leave an older remote copy and require new human consent. See
[policy delivery](policy-delivery.md) for configuration and recovery.

## Human credential issuance (v0.22)

These loopback UI routes require the configured signer admin and group creator,
retaining Host/Origin and `no-store` response protection. They accept an existing
canonical raw Ed25519 public key, never an Agent/owner private key, destination
URL or machine identifier. Issuance does not change signed membership or policy
revision. The directory's wire format and proof checks are unchanged.

| Route | Behavior |
|---|---|
| POST `/api/credential-preview` | `group_id`, `public_key`, `permissions`, `lifetime`, `expected_revision`, `policy_hash`; returns subject/owner, canonical request, fixed issued/expiry time, preview deadline and `consent_hash`; no issuance or remote I/O |
| POST `/api/credential-issue` | Those request fields plus `issued_at`, `consent_hash`, `request_id`; explicit issuance or recovery of that exact existing request |
| GET `/api/credential-issuances?group_id=...` | Latest 50 public request/claim/hash/time records with local valid/expired/future/retired state; never returns complete grants |

`permissions` is a duplicate-free subset of the existing permission vocabulary
and must include `join`. `lifetime` is an integer 1..86400; the owner authority
key cannot be the Agent subject. New issuance binds current policy hash/revision
and a fixed preview timestamp, with confirmation before the earlier of preview
age 60 seconds or credential expiry. Changed consent/current policy/expired
preview returns 409. Invalid schemas, keys or expired credential recovery return
400; unauthorized/retired/dissolved access returns 403.

The consent hash binds fields for human confirmation and consistency; it is not
a signed delegation or a substitute for authenticating the human admin. The
successful response includes `grant`, verified `claims`, `grant_hash`,
`request_id`, `issued_policy_revision`, `issued_policy_hash` and
`membership_changed: false`. Persisted retry metadata contains public claims and
hash only. Identical retries reconstruct the same deterministic signature with
the original ID and absolute expiry, even after unrelated revision changes.
They do not issue a replacement, extend validity, approve or register anything.

Recovery after restart is explicit POST with the original request from history;
GET/startup never reconstructs credentials. Browser memory and download files
must be handled as credential material. See [credential issuance](credential-issuance.md)
for the separate stdin installer, transfer and remaining operational limits.

## Signed simulation-runtime presence (v0.23, unreleased)

Policy-mode directories accept optional `presence` in the existing challenge
and registration POST bodies. When omitted, legacy schemas/responses stay the
same for identities that have never opted into signed presence. A supplied value
must be a string, never JSON null. After the first successful signed heartbeat,
that subject cannot use legacy registration on this directory, including after
restart/lease expiry. This prevents bypassing durable instance ordering.

The presence token is Agent-signed typed Ed25519 JWS,
`typ: tailnet-agent-presence+jwt`. Its exact claims are:

| Field | Meaning |
|---|---|
| `version` | Integer 1 |
| `owner`, `group_id`, `subject` | Pinned owner fingerprint, original group and Agent key fingerprint; owner does not sign this token |
| `record_hash` | SHA-256 of canonical normalized metadata JSON |
| `generation`, `boot_id`, `sequence` | Positive integer generation/sequence up to 2^53−1 and 32 lowercase hex boot ID |
| `state` | `online` or `offline`; observation only |
| `issued_at`, `expires_at` | Finite nonnegative numeric seconds, preserving fractional precision (integer timestamps remain valid); 0 < lifetime <= requested TTL (10–300); issue time at most five seconds ahead; receipt before signed expiry |

New signed-runtime records accept only endpoint/name/protocol/skills/ttl_seconds,
with at most 4096 normalized JSON bytes. Endpoint remains HTTPS and excludes
credentials/query/fragment. The proof challenge context becomes SHA-256 of sorted
compact JSON containing the normalized `record` and `presence_hash` (SHA-256 of
the exact token). A valid token alone cannot register: approved scoped grant,
fresh active policy, learned revocation checks and a fresh audience/context-bound
possession proof still apply. The SDK checks the returned challenge binding before
signing its proof.

Within one directory, lower generations fail; equal generations need the same
boot ID and a strictly higher sequence. Same-generation different-boot requests
leave the incumbent intact. Higher authorized generations supersede it. Conflict
returns 409, authorization/proof/signature failure 403, malformed schema 400.
Ordering, registration/grant and presence observation commit together. Signed
registration returns the existing `id`, `ttl_seconds`, plus `presence` containing
generation/boot ID/sequence/state and effective `expires_at`. Offline acknowledges
TTL zero; its group membership remains unchanged. Online registration requires
at least ten seconds of remaining credential and policy validity. The requested
metadata TTL remains 10–300; transport consumes the signed presence budget, so
the acknowledged remaining TTL may be 1–300 whole seconds. Less than one full
second of presence validity is rejected without updating the old lease or
observation. Lease TTL is rounded down using one receipt-time snapshot shared
with the effective expiry calculation; no deadline is rounded up or extended.
For example, a ten-second heartbeat issued at `1700000000.7` expires at
`1700000010.7`: immediate receipt can grant ten seconds; receipt 0.25 seconds
later grants nine seconds. Integer signed timestamps remain accepted. Legacy
registration retains its ten-second minimum authorization gate.

GET `/v1/presence?after=...&limit=20` requires the existing directory read bearer
and Host/Origin checks. `after` is empty or an Ed25519 subject cursor; `limit` is
1–20. Unknown/repeated query parameters fail. The response contains `owner`,
`group_id`, `observed_at`, policy age status, `entries`, `has_more`, `next_after`.
Each entry has `id`, `subject`, `public_key`, original normalized `record`, signed
`presence`, receiver `observed_at`, effective `expires_at` and state:
`online`, signed `offline`, lease `expired`, or `unauthorized` after credential/
policy/revocation checks. It exports no grant or private key. Empty pages retain
the supplied cursor; pages are independent observations rather than a global
atomic snapshot. Legacy unsigned registrations do not appear in this feed.

Directory restart invalidates live leases but retains signed history/ordering.
Reads never restore online state or renew policy. The CLI validates signatures,
scope, metadata, cursor order and deadlines, conservatively expiring old online
observations. Current membership is still the configured receiver's authenticated
observation; this is not a receiver-signed grant attestation or proof of executor
health. Presence is not included in policy/revocation replication. See
[runtime operations](agent-runtime.md) for migration and recovery boundaries.
