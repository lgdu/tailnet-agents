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
| POST | `/v1/agents` | Register or renew owner-controlled agent |
| GET | `/v1/agents?skill=coding` | List live records, optional exact skill filter |

Both agent endpoints require `Authorization: Bearer TOKEN`.
POST JSON: `id`, optional `name`, `endpoint` (HTTPS), optional `protocol`,
optional `skills` (string array), optional `ttl_seconds` (10–300, default 60).
POST returns `id` and `ttl_seconds`. GET returns `{"agents": [...]}`.
Errors: 400 invalid metadata, 403 unauthorized or ownership conflict,
404 unknown path, 413 missing/oversized POST body.

Lease expiry excludes records from discovery; IDs remain owner-reserved until
process restart. Discovery is a snapshot; clients poll in v0.1.
Credentials and model API keys never appear in registration records.

## Intended execution layer (not implemented)

Registry endpoints identify adapters; callers negotiate the advertised protocol.
A2A is the intended standard task interface. Adapters must preserve task identity,
execution provenance and product permission boundaries. Network discovery does
not imply access to another agent's memory, filesystem or user approvals.
Future bridges must bound delegation depth and deduplicate retries to prevent
agent loops and duplicate side effects.
