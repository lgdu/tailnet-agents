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
| GET `/api/group-policy?group_id=...` | Signer admin + creator only; signed policy, claims, owner public pin, latest 50 policy audit records and v0.28 evidence summary |
| POST `/api/policy-preview` | `group_id`, `grant`; verifies pre-issued grant and returns subject, expiry, grant permissions, proposed complete membership scope and current revision without mutation |
| POST `/api/policy-approve` | `group_id`, `grant`, `expected_revision`, `request_id`; approve its scoped identity/grant ID |
| POST `/api/policy-remove` | `group_id`, `subject`, `expected_revision`, `request_id`; remove all that identity's approved IDs and retire them locally |
| POST `/api/policy-renew` | `group_id`, `expected_revision`, `request_id`; explicitly sign a higher revision with unchanged membership |
| POST `/api/group-dissolve` | Existing exact-name confirmation also signs terminal policy when this is a signed group |

All policy operations require the configured signer admin and group creator.
Only active groups can create new policy changes. A committed identical retry makes no new signature. Expected revision and changed retry-payload
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

## Signed simulation-runtime presence (v0.23)

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


## Human gateway runtime monitor (v0.24)

GET `/api/runtime-presence` requires existing human Bearer, loopback Host/Origin,
and the configured signing-admin/group-creator checks. Required query keys are
`group_id` and configured `target_id`; optional `after` defaults to empty and must
otherwise be an Ed25519 subject, and `limit` is an integer 1–20 (default 20).
Repeated/unknown keys and caller URLs are rejected before source I/O.

The gateway only GETs source policy, one signed presence page, then policy again.
It verifies signatures, scope, metadata/cursors, signed policy/status consistency,
deadlines and local policy agreement, then rechecks local policy/config/access
after I/O. Different signed policies make online rows `unconfirmed`; concurrent
changes return 409. Receiver authorization remains an authenticated observation.
No grants, full presence tokens or source credentials are returned to the browser.
No registry lease, local policy or membership is changed or replicated.

The result contains `target`, `group_id`, `checked_at`, `observed_at`, `policy`,
`entries`, `has_more`, `next_after`. Policy includes verified receiver status,
`matches_local` and `policy_hash`. Entries include `subject`, canonical `record`,
conservative `state`, `source_state`, effective `expires_at`, `observed_at`,
`generation`, `boot_id`, `sequence` and `issued_at`. The response is `no-store`.
States include online/offline/expired/unauthorized and monitor-only unconfirmed.

Input, access, concurrent snapshot/config changes and source verification/transport
failures return 400/403/409/502 respectively. Consumers clear previous online
state on failed/superseded reads and expire cached observations conservatively.
Pages are independent reads, not one atomic snapshot. See [monitoring](runtime-monitoring.md).


## Configured peer presence replication (v0.25)

GET `/v1/presence-export?after=&limit=20` is disabled (404) unless the source
explicitly enables `--presence-export`; enabled reads require the directory read
Bearer and existing Host/Origin checks. Policy mode is mandatory. Its exact root
fields are `owner`, `group_id`, `observed_at`, `entries`, `has_more`, `next_after`.
The subject cursor/limit semantics match signed presence (1–20). Entries are
`subject`, `public_key`, canonical `record`, Agent-signed `presence`, owner-signed
`grant`, effective `expires_at`, original `observed_at`, `state`. Only direct local
observations export, including historical offline/expired/unauthorized ordering.
No cached peer data is re-exported. Ordinary `/v1/presence` stays unchanged.

Receivers configure fixed same-group source IDs/origins, CA and credential
environment names. They verify both signatures, grant/subject/scope binding,
finite bounded deadlines, ordered cursor and current local policy/approved grant
IDs/revocations. Pages commit atomically to a separate cache and durable heads.
A repeated claim cannot extend expiry or promote a negative observation; receiver
policy deadlines are also persisted at import so renewal cannot rearm old data.
No import writes local registrations, membership, grants used for local admission
or discovery candidates. Source status/receipt is authenticated transport data,
not a receiver-signed admission attestation.

GET `/v1/peer-presence?after=&limit=20` requires the receiver read Bearer and policy
mode. Root fields are `owner`, `group_id`, `observed_at`, local `policy` status,
`entries`, `has_more`, `next_after`. Each entry groups one public-key `subject`,
merged `state`, durable `head` and up to nine `observations` (local plus eight
configured sources). Heads contain `generation`, `boot_id`, `sequence`,
`token_hash` and boolean `conflict`. Observations expose `source`, `subject`,
`public_key`, canonical `record`, `presence`, `state`, `expires_at`, `observed_at`,
`received_at`; they omit full grants and source credentials. Configured source
metadata is its ID/origin/group/fingerprint; local uses ID `local`, null origin
and null fingerprint. A subject-entry byte budget of 512 KiB can shorten a page;
all observations of a subject stay together. Continue using the returned cursor.

Merged states are online/offline/expired/unauthorized/superseded/conflict. Highest
known generation then sequence orders observations; different boots at one
generation or contradictory tokens at one sequence conflict until a higher
generation. Removal of a source does not erase high-water history. Online requires
an unexpired authorized observation matching the current nonconflicted head.
Other sources/older counters cannot restore a superseded claim. Every read
rechecks local policy and learned revocations. This does not alter local direct
admission fencing or promise endpoint/executor/global reachability.

GET `/v1/presence-sync` uses the same read/Host/Origin checks and accepts no query.
It reports source IDs, synced/catching_up/error state, cursor and last completed
scan time. Polls visit all sources with independent cursors, up to ten pages of
twenty subjects each per source per poll. Completed scans restart from the
beginning; incomplete scans continue next poll. Cached history persists through
failure/restart and keeps its original deadlines. Shutdown blocks late writes.
See [peer presence](peer-presence.md) for opt-in grant handling and limitations.

## Signed network messages (v0.26)

Separate custom text protocol on the admission service, enabled only by explicit
`--messages` with signed policy mode. Directory bearer credentials cannot read
message content. Origin/Host/Origin-header checks and HTTP/TLS transport rules
are the same as admission; default is disabled (404). No endpoint calls product
Agents, generates groups/keys/grants, enrolls members or starts an automatic reply.

POST `/v1/messages/challenges` takes `{request}`. Two exact request schemas:

```json
{"operation":"send","message":"AGENT_SIGNED_TEXT_JWS"}
```

```json
{"operation":"read","scope":"direct","peer":"ed25519:OTHER_ID_HASH","after":0,"limit":20}
```

Group reads use `scope:"group", peer:null`. Direct reads require one exact peer
identity. `after` is an integer 0..2^53−1, `limit` an integer 1..20; booleans,
extra fields, unknown scopes/operations and inconsistent peers are invalid.
The challenge returns `{nonce,context}` with a 30-second single-use nonce and
`messages-v1:` plus SHA-256 of the sorted compact JSON request. Challenges share
the bounded admission nonce pool. They do not authorize any message read/write.

POST `/v1/messages` takes exact fields
`{request,grant,public_key,proof,nonce}`. The proof uses existing possession-proof
JWS semantics: subject, grant hash, nonce, pinned service audience and context.
It binds the complete send envelope or read scope/peer/cursor/limit, so a read
proof cannot be replayed as a send or broadened to another conversation. Verify
current grant (`join` and `chat.group`/`chat.direct`), signed policy age, approved
credential ID and learned revocations on every operation, including duplicate
sends. Recipient policy approval with direct scope and an unrevoked approved ID
is required for direct sends; valid recipient credentials are checked when read.

Text JWS type `tailnet-agent-message+jwt` has exact claims:
`version:1, owner, group_id, audience, sender, recipient, message_id,
conversation_id, reply_to, kind:"text", text, created_at`. Header binds the Agent
key as in existing Ed25519 tokens. Owner/group/audience must match the existing
store, sender must match the verified key/grant, recipient is null (group) or an
Ed25519 subject, IDs/reply references are 32 lowercase hex characters, and text
is nonblank, at most 4096 UTF-8 bytes within the shared 16 KiB token bound.
Creation time is a nonnegative integer up to 2^53−1 and at send cannot exceed
receiver time +30 seconds. It has no delivery TTL: a valid current manually
renewed grant can submit its original old queued envelope. Authorization is at
acceptance, not inferred from an untrusted historical creation timestamp.

Conversation ID is SHA-256 of compact JSON `[owner,group_id,scope,parties]`;
`scope` is `group` with `parties:[]`, or `direct` with the sorted unique sender/
recipient identities. Replies must reference a stored message in the same
conversation. A successful send returns exact
`{state:"stored",message_id,sequence,message_hash}` after durable commit.
`message_hash` is SHA-256 of the original compact JWS token. An exact retry gives
the original sequence/hash. A reused ID with any different envelope returns 409.
This receipt is a trusted store/TLS statement, not proof of recipient reading.

Read result exact fields:
`{owner,group_id,audience,conversation_id,after,next_after,has_more,messages}`.
Each entry is `{sequence,message,public_key,stored_at}`; no grant or private key
is returned. Sequences are positive increasing integers, scoped by the selected
conversation with possible gaps from other conversations. `next_after` is the
last returned sequence (or original cursor for an empty page). `has_more` is
boolean and only true for a full page. No private conversations are enumerable
through group reads or directory bearer APIs. An authorized group reader sees
all retained group history; a direct reader must be one of its participants.
Sender removal does not delete a still-authorized recipient's private history.

Client validates full page context, signatures, conversation, participant,
sequences, timestamps and cursor before atomically committing inbox/cursor.
An exception cannot advance its cursor past unsaved text. Errors are sanitized:
400 malformed requests, 403 invalid authorization/signature/context/recipient/
reply, 404 disabled or unknown routes, 409 conflicting ID, 413 body size outside
1..65536 bytes and 503 unavailable storage. Failed sends retain original pending
IDs; no automatic alternate-store delivery occurs. History sender signatures are
independently verified, but authorization-at-insertion depends on the trusted
store, not attached historical policy proofs. Plaintext storage operators are
trusted. See [network messages](network-messages.md) for recovery and privacy limits.

## Signed durable Echo tasks (v0.27)

Separate custom API on admission, default disabled. Explicit `--tasks` requires
signed policy mode plus original approved executor key/grant. Legacy bridge
`/v1/tasks` and MCP tools keep their existing bearer/in-memory contract.

POST `/v1/task-challenges` takes `{request}`, where the exact operation is either
`{operation:"submit",task:"SIGNED_TASK_JWS"}` or
`{operation:"get",task_id:"32_LOWERCASE_HEX"}`. Unknown fields/kinds/operations
are invalid. It returns `{nonce,context}`; context is `tasks-v1:` plus SHA-256 of
sorted compact JSON request. The nonce is single-use, expires in 30 seconds and
shares the admission engine's bounded 256 outstanding challenge pool. A message
or admission proof cannot substitute for a task-operation proof.

POST `/v1/agent-tasks` takes exact
`{request,grant,public_key,proof,nonce}`. Existing possession proof binds caller,
nonce, current grant hash, explicit service audience and full operation context.
Both caller and executor require current approved `join`/`task.echo` grants,
fresh active policy and no locally learned revocation. Directory read tokens and
chat permission do not authorize tasks. Results are visible only to the caller;
unknown or other-caller IDs return the same 404.

Task JWS type `tailnet-agent-task+jwt` has exact claims:
`{version:1,owner,group_id,audience,caller,executor,task_id,kind:"echo",input,created_at}`.
Caller/executor are public-key identities. Context must match the pinned existing
service/group/executor; creation time is integer 0..2^53−1 and at most receiver
time +30 seconds. IDs are 32 lowercase hex, input is a nonempty UTF-8 string up
to 2048 bytes, within 16 KiB token bounds. Current authorization can submit an
older saved intent after manual grant renewal; creation time is not a historical
authorization proof. No arbitrary command, model call or product adapter kind exists.

All successful submit/get responses are HTTP 200 with exact `{receipt:"JWS"}`.
Receipt JWS type `tailnet-agent-task-result+jwt`, signed by the pinned executor,
has exact claims:
`{version:1,owner,group_id,audience,executor,caller,task_id,request_hash,status,output,error,issued_at}`.
`request_hash` is SHA-256 of the original signed task token. Statuses:

| Status | Output | Error |
|---|---|---|
| `queued` / `running` | null | null |
| `completed` | Nonempty UTF-8 string, at most 2048 bytes | null |
| `failed` | null | `execution_failed` |
| `uncertain` | null | `execution_interrupted` |

Receipt time is integer 0..2^53−1; terminal receipts are durable historical signed
statements without their own expiry. Readers still need current network authorization.
Caller independently verifies executor signature, context, both identities, original
task/hash, state/output/error schema, and refuses running→queued or any change to a
stored terminal receipt. Such failures leave original local intent/result intact.
A receipt is not an independently reconstructed historical policy proof.

Executor commits immutable queued intent before running; commits `running` before
adapter invocation outside the directory lock; commits signed terminal outcome
before returning it. Exact ID/envelope retries return original state/receipt without
another invocation. Conflicting ID reuse returns 409. Concurrent duplicates cannot
claim running work. On startup `running` without a terminal receipt becomes terminal
`uncertain`, while `queued` stays unstarted. Startup/query never executes. Only
explicit fresh authorized submission can claim queued work, rechecking both
principals immediately before the running marker. Authorization loss during work
does not erase the outcome; it is committed but not returned without valid access.

No eviction: default 256 retained tasks, then 429 for new IDs, while existing reads/
retries work. No automatic uncertain retry, cancellation, resolution or alternate
executor exists. Graceful shutdown rejects new task operations and drains active
ones. Errors are sanitized: 400 malformed request, 403 authorization/signature/
context, 404 disabled/unknown/other-caller ID, 409 conflicting ID, 413 body outside
1..65536 bytes, 429 retained capacity, 503 unavailable storage or stopping executor.
TLS, Host/Origin and proxy/redirect rules match admission. See
[durable tasks](durable-tasks.md) for actual command/recovery and current bounds.

## All-source policy review and reviewed renewal (v0.28)

Three loopback UI POST routes require the configured signing admin/group creator,
with existing Host/Origin and bearer checks. They accept no arbitrary destination,
private key, discovery candidate or new identity. Signed directory policy format
and normal ordered failover are unchanged.

| Route | Exact request fields |
|---|---|
| `/api/policy-source-check` | `group_id`, `expected_revision`, `policy_hash` |
| `/api/policy-renew-preview` | Same fields; additionally prepares fixed renewal consent if known safe |
| `/api/policy-renew-confirm` | `group_id`, `expected_revision`, `policy_hash`, `issued_at`, `preview_expires_at`, `evidence_hash`, `targets_fingerprint`, `consent_hash`, `request_id` |

Check/preview return `{report, preview}`. The report includes `group_id`, local
snapshot summary, `checked_at`, ordered per-target `sources` and `evidence`.
Each source has public target binding, `state`, `relation`, optional policy and
freshness summaries, check time and an optional fixed diagnostic. Valid signed
facts from partial/changing reads persist atomically; a local-policy/configuration
race returns 409 and discards that scan. No remote POST is performed. Missing or
failed sources do not establish complete history and are not automatically chosen.

Policy summaries contain revision, exact-token `policy_hash`, verified-claims
`semantic_hash`, `issued_at` and policy state, omitting members/full JWS/grants.
The exact-token hash remains SHA-256 of the token bytes; semantic/evidence/consent
hashes use SHA-256 of Python `json.dumps(value, sort_keys=True, separators=(',', ':'),
allow_nan=False).encode()` (default ASCII escaping). The evidence digest covers
sorted `(revision, semantic_hash)` entries, deduplicating equivalent claims.
Evidence summaries include `head_revision`, `conflicts`, `terminal_known`,
`can_renew`, `digest` and `statements`. Group-policy exports add the same summary.
See [reason codes and persistence](policy-review.md#durable-signed-evidence).

A non-null preview includes group/owner, expected revision, exact token hash,
fixed integer issue time, `preview_expires_at = issued_at + 60`, evidence hash,
ordered public-target fingerprint digest and consent hash of those fields.
Confirmation sends all preview fields except `owner`, plus one stable request ID;
owner/group are rebound from the authenticated authority/context. Target bindings
include ID, URL, group and CA fingerprint, never credential values. The server
rejects changed/expired/future consent, evidence, targets or local snapshots;
confirmation time must fall in `[issued_at, preview_expires_at)` and not precede
the current snapshot's issue time. Membership/grant IDs are unchanged. Response
is the ordinary revision/hash/state acknowledgment. No delivery occurs.

Known unsafe signed history blocks every new policy signature, including the
legacy explicit `/api/policy-renew`. Identical already committed requests return
the original acknowledgment before current-history/expiry checks; changed reuse
of a request ID conflicts across legacy and reviewed operations. Schema/expiry
errors return 400, authorization failures 403 and changed bindings/unsafe history
409. Individual source failures are attributed report rows, not whole-request 502.
This is manual diagnosis/consent, not quorum or automatic reconciliation.

## Reference adapter metadata (v0.29)

With an explicit default Echo task executor, `POST /v1/task-adapter-probe` accepts
exactly `{nonce}` where nonce is 64 lowercase hex characters. Existing Host/Origin
checks and the directory **read bearer token** protect this route; it does not
allocate admission/task challenges. The normal JSON body bound is 1..65536 bytes.
Without `--tasks` it is 404. Response is exactly `{descriptor: JWS}` with no-store
headers. Bad schema is 400, read/authorization denial 403, and unavailable/closed/
unverified callback executors return 503. No task request or policy mutation occurs.

The descriptor JWS type is `tailnet-agent-adapter-descriptor+jwt`, signed by the
original executor. Payload fields are exactly `version` (integer 1), `owner`,
`group_id`, `audience`, `executor`, canonical `source` origin, requested `nonce`,
`issued_at`, `expires_at` and `contract`. Timestamps accept finite nonnegative
JSON numbers up to 2^53-1, preserving fractions; booleans are rejected. The signed
interval is positive and at most 15 seconds, clipped to executor grant and local
policy deadlines after server-side current authorization. The verifier accepts
at most five seconds of future issue time and requires its post-response clock
strictly before expiry. Original source/context/key/nonce must match.

The strict Echo contract and canonical hash are specified in [adapter contracts](adapters.md).
Unknown versions/products/fields/types fail closed; there is no fallback to product
execution. The descriptor proves possession for this metadata response, not an
owner-signed admission chain or the caller's execution permission. It cannot be
used as a task grant, intent or operation proof. Task requests/receipts, SQLite
adapter semantics `echo-v1` and `task.echo` authorization remain unchanged.
v0.31 adds a one-way executor storage-format marker described below.

## Explicit task cancellation and local review records (v0.30)

The existing task challenge/operation routes add `{operation:"cancel",task:JWS}`.
The exact original signed intent is required, not only a task ID. Its full request
hash, including `operation`, binds a fresh `tasks-v1:` challenge/proof. Both caller
and executor retain current `task.echo`/policy/revocation checks. A submit proof
cannot cancel, and read tokens or metadata cannot authorize it.

Only absent/queued intents can become terminal `cancelled`; tombstone and receipt
commit atomically under the same directory lock as the running marker. The receipt
uses the existing result JWS fields/version, with `status:"cancelled"`, `output:null`,
`error:"execution_cancelled"`. Duplicate same-intent cancel/submit returns its exact
stored receipt, including after restart. Different intent/caller collisions fail;
running/completed/failed/uncertain cancel returns 409 without rewriting outcomes.
Invalid schemas return 400, auth failures 403, absent-tombstone capacity exhaustion
429 and storage errors 503. A post-commit auth denial can leave the tombstone saved
without an acknowledgment. No running adapter cancellation is supported.

Caller cancellation intent commits before I/O and remains a `flush` exclusion even
if cancel fails or `get` returns queued/running. `cancel_pending` is a local summary,
not a new executor receipt state. API/CLI result views add `cancellation_requested`
only for locally requested tasks. Caller state migrates to `task-operations-v1`
context while retaining original pins/intents; older callers reject it. See
[task operations](task-operations.md#upgrade-and-recovery) before upgrading.

Local uncertainty reviews have JWS type `tailnet-agent-task-review+jwt`, signed by
the caller, with exact payload `{version:1,owner,group_id,audience,caller,executor,
task_id,request_hash,receipt_hash,decision,note,request_id,issued_at,task_status,
effect}`. `task_status` is `uncertain`; `effect` is `advisory_local_record_only`.
Decision is `effect_observed`, `no_effect_observed` or `unresolved`; note is nonempty
UTF-8 text up to 2048 bytes, request ID is 32 lowercase hex, and issue time is an
integer between the original receipt issue time and 2^53-1. Context/hashes must bind
the verified original intent/uncertain receipt. Stable duplicate requests return
the same record, changed reuse conflicts. Local pages validate signatures and
persisted request-ID bindings. No HTTP review route or executor-result mutation is
introduced; a review is not a task grant, operation proof or authorization to retry.

## Explicit terminal archives and admission quotas (v0.31, unreleased)

Task challenge/operation routes add the exact request
`{operation:"archive",task:JWS,receipt_hash:SHA256}`. The hash is 64 lowercase hex
over the original terminal receipt bytes; the original intent is required. The
entire canonical request binds a fresh `tasks-v1:` possession challenge/proof.
Both principals' current `task.echo`/policy/revocation authorization remains required,
including after commit. Caller CLI additionally confirms the task ID and original
request hash against private saved state before I/O.

Only original completed/failed/cancelled records with the matching signed receipt
can move. Active and archive tables share one SQLite transaction/lock; neither the
original signed input nor receipt is changed. Unknown tasks return 404, ineligible
states/changed receipt or intent return 409, invalid schema 400, auth failure 403
and storage failure 503. A successful/repeated archive returns exactly
`{receipt:ORIGINAL_RESULT_JWS,archived:true}`. The flag is authenticated transport
metadata, not part of the original result signature or a new storage attestation.
The caller verifies the unchanged terminal receipt before accepting it. No archive
result state, unsigned output replacement or replay permission is introduced.

Ordinary get/submit/cancel response schemas stay unchanged. Lookup/deduplication
uses both tables. Archived cancelled intents still return the same cancellation
receipt on late original submit/cancel; other terminal cancel requests still
conflict. Pending/queued/running/uncertain tasks cannot be archived.

Four configured row-count limits gate only new IDs: global active, global total
active+archive, per-caller active and per-caller total. They apply equally to submit
and absent cancellation tombstones; full quotas return 429 without eviction.
Existing reads/retries/eligible archival remain available at/above quota. Caller
scope is the Agent public key, not host/IP/device. Limits/defaults, migration and
remaining bounds are specified in [task history](task-history.md).

The executor context now pins `echo-v1/task-history-v1`; an original `echo-v1`
context migrates atomically while preserving identity/group/audience/history.
Older executors fail their context check before ignoring archived IDs. The Echo
adapter contract and caller format stay unchanged. Opening a service never
archives, deletes, dispatches work, creates a group/key or repairs lost history.
