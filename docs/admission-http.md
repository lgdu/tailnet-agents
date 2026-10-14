# Verified admission HTTP/TLS — prototype (v0.19, unreleased)

This separate optional service exposes VerifiedDirectory over HTTP/TLS. Default
binding is loopback HTTP. Non-loopback binds require server certificate/key and
explicit allowed host names; clients verify CA trust and hostname. See
[TLS deployment](tls-deployment.md) for controlled LAN/tailnet trials.
It is not the ordinary bearer registry, not distributed mesh and not integrated
with the UI's signed human-created policy.

## Prepare keys and one scoped grant

Install `.[identity]`. The following creates demo authority and Agent keys;
use an existing human-approved group ID. Creation refuses to overwrite keys.
For subsequent runs use `load_identity`. State files are sensitive and ignored
by git. Authority private keys must remain with the human administrator.

```python
from pathlib import Path
from tailnet_agents.identity import generate_identity, encode, public_bytes, issue_grant

owner = generate_identity('state/owner.pem')
agent = generate_identity('state/agent.pem')
Path('state/owner.pub').write_text(encode(public_bytes(owner.public_key())))
grant = issue_grant(owner, agent.public_key(), 'YOUR-GROUP-ID', ['join', 'discover'])
path = Path('state/agent.grant')
path.write_text(grant)
path.chmod(0o600)
```

The public-key file contains base64url raw Ed25519 bytes, not a PEM public key.
Group ID/audience must be agreed through trusted setup. Grant-only mode does not
require signed group policy and never automatically trusts the UI group table.
For policy enforcement, follow [the policy guide](group-policy.md) and start with
`--require-policy` or `--policy-file state/group.policy`. Without an active
snapshot, policy mode rejects all registrations. Its enforcement flag persists
in SQLite; restarting without the flag then fails instead of weakening checks.
Policy mode also persists a maximum signed age (default 300 seconds), configurable
with `--policy-max-age`. Stale policy denies registration/renewal and hides
discovery results. Restart cannot increase a saved limit; only a fresh signed
owner revision renews authorization for the same group. [Policy sync](policy-sync.md)
documents migration and ordered primary/backup source configuration.

## Start

```bash
export TAILNET_VERIFIED_READ_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python3 -m tailnet_agents.admission_server \
  --authority-public-key state/owner.pub \
  --group-id YOUR-GROUP-ID \
  --audience receiver-identity
```

Default URL: `http://127.0.0.1:8771`. Default database:
`state/verified-directory.sqlite3`, pinned to the configured authority/group.
The read token gates discovery and the revocation submission route. It does
not grant membership or signing authority. Policy submission also requires the
authority signature and is available only in policy mode.

## Register through the client

Create `state/record.json` with metadata, no `id`:

```json
{
  "name": "Local Echo",
  "endpoint": "https://agent.YOUR-TAILNET.ts.net",
  "protocol": "tailnet-task-v0.1",
  "skills": ["echo"],
  "ttl_seconds": 60
}
```

```bash
python3 -m tailnet_agents.verified_client \
  --url http://127.0.0.1:8771 \
  --agent-key state/agent.pem \
  --grant-file state/agent.grant \
  --record-file state/record.json \
  --audience receiver-identity
```

This requests a challenge, signs its context and registers once. No actual
Agent is started by registering metadata. Renew before TTL expiry by repeating
registration; it uses a fresh proof and retains the public-key-derived ID.
There is no background renewal daemon yet. Expired grants require new human
issuance; the client does not silently mint credentials.

Programmatic `VerifiedClient` also supports discovery with the read token.
Tokens are not followed across redirects or ambient HTTP proxies. The example
endpoint is metadata and is not contacted by this service.

## HTTP API

| Method/path | Requirement | Payload/result |
|---|---|---|
| GET `/healthz` | Allowed Host/Origin | Process liveness |
| GET `/v1/discovery` | Explicit discovery opt-in, allowed Host/Origin | Credential-free signed candidate metadata; no membership grant |
| POST `/v1/challenges` | Allowed Host/Origin | `{record}` → `{nonce, context}` |
| POST `/v1/registrations` | Signed grant and subject proof | `{record, grant, public_key, proof, nonce}` → ID/TTL |
| GET `/v1/agents?skill=echo` | Read bearer token | Verified, leased, non-revoked records |
| GET `/v1/policies` | Read bearer token, policy mode enabled | `{policy}` signed snapshot or null |
| GET `/v1/policy-sync` | Read bearer token | Sync state, active source index, per-source cursors, current policy age/expiry; also available when sync is disabled |
| POST `/v1/policies` | Read token AND authority signature, policy mode enabled | `{policy}` → group ID/revision/state |
| GET `/v1/revocations?after=0&limit=100` | Read bearer token | Paged signed records, source generation, cursor and has_more |
| POST `/v1/revocations` | Read token AND authority signature | `{revocation}` → acknowledgment |

`public_key` is base64url raw Ed25519 bytes. A proof binds the exact normalized
record, grant hash, nonce, subject and audience. Grants bind issuer, subject,
group, expiry and permissions. Errors intentionally omit verifier internals.
Bodies are capped at 64 KiB. Active challenges are capped at 256 and expire
in 30 seconds; capacity returns 429. There is no per-client admission rate limiter.

Generate revocations with `issue_revocation` and persist/submit the signed token.
They are not broadcast to other directories. Revocation hides directory records
and denies renewal, but does not stop tasks already dispatched elsewhere.

## Verified scope

Tests use two local simulated subjects over actual loopback HTTP. They cover
registration, discovery, revocation, renewed stable IDs, nonce replay, foreign
groups, metadata tampering, Origin checks, read authorization and body limits.
TLS transport is now tested on loopback, including CA and hostname validation.
Actual cross-machine LAN/tailnet deployment, TLS channel binding and UI grant
issuance remain unvalidated or pending. Signed revocation replication is tested
locally; immediate partition-wide revocation is not guaranteed.
Signed group policy updates and enforcement are tested locally, including
member removal, rollback rejection and terminal dissolution.
[Policy sync](policy-sync.md) adds optional periodic pull from an explicitly
configured sources with failover; registration leases and tasks/chat are not replicated. Signed credential
revocations propagate through a paginated read-protected feed.

## Optional candidate publication

`--discovery-agent-key EXISTING-KEY.pem` and `--discovery-endpoint ORIGIN` enable
the public `/v1/discovery` route. Both flags and policy mode are required. Load an
existing approved simulation identity, never the owner private key. The route
contains no read token, grant, member list or private key, and does not register
an Agent. It returns 503 when policy/key eligibility is unavailable and 404 when
disabled. Host/Origin checks remain active; query parameters are rejected.

`--discovery-lan-interface LOCAL-IPV4` additionally enables five-second UDP multicast
on that exact interface. The optional `--discovery-lan-port` defaults to 8773.
Shutdown joins the publisher before closing the directory database. Seed scans
and multicast reception are a separate [discovery CLI](discovery.md), and produce
unadmitted candidates without changing existing registration/policy routes.
