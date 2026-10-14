# Verified admission HTTP/TLS — prototype (v0.14)

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
Group ID/audience must be agreed through trusted setup. This service does not
verify a signed group-creation policy or automatically trust the UI group table.

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
not grant membership or signing authority.

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
| GET `/healthz` | Local request | Process liveness |
| POST `/v1/challenges` | Local request | `{record}` → `{nonce, context}` |
| POST `/v1/registrations` | Signed grant and subject proof | `{record, grant, public_key, proof, nonce}` → ID/TTL |
| GET `/v1/agents?skill=echo` | Read bearer token | Verified, leased, non-revoked records |
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
Actual cross-machine LAN/tailnet deployment, TLS channel binding, signed group
policy, UI grant issuance and distributed revocation remain unvalidated or pending.
