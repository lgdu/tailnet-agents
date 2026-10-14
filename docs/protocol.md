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
