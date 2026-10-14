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
