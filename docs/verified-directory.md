# Credential-enforced directory (v0.18)

`VerifiedDirectory` connects the optional identity component to SQLite directory
registration. This module remains an **in-process API**. A separate
[loopback admission service](admission-http.md) now exposes it over HTTP. Existing
registry/Bridge/UI commands still use their previously documented bearer tokens.
Network admission, mesh replication and UI grant issuance are not wired up.

Install `.[identity]` before importing this component.

## Admission flow

1. A trusted human authority issues a grant for an agent key and exact group ID.
2. The caller prepares registration metadata (without an ID).
3. The directory creates a one-use challenge bound to normalized metadata.
4. The agent signs possession proof binding grant, audience, nonce and context.
5. In policy mode, the current signed snapshot must approve the grant first.
   Registration verifies the proof and grant before writing the metadata/credential
   association in one SQLite transaction. The ID is derived from the public key.
6. Discovery returns live leases only while their associated grants remain valid.

```python
from tailnet_agents.identity import generate_identity, issue_grant, prove_possession
from tailnet_agents.verified_directory import VerifiedDirectory, issue_revocation

owner = generate_identity('state/directory-owner.pem')
agent = generate_identity('state/directory-agent.pem')
group_id = 'YOUR-HUMAN-CREATED-GROUP-ID'
record = {
    'name': 'Example Echo',
    'endpoint': 'https://agent.YOUR-TAILNET.ts.net',
    'skills': ['echo'],
    'protocol': 'tailnet-task-v0.1',
    'ttl_seconds': 60,
}
grant = issue_grant(owner, agent.public_key(), group_id, ['join', 'discover'])
directory = VerifiedDirectory(owner.public_key(), group_id, 'receiver-identity',
                              database='state/verified-directory.sqlite3')
try:
    challenge = directory.challenge(record)
    proof = prove_possession(agent, grant, challenge['nonce'], 'receiver-identity',
                             context=challenge['context'])
    accepted = directory.register(grant, agent.public_key(), proof,
                                  challenge['nonce'], record)
    peers = directory.discover('echo')
finally:
    directory.close()
```

This example creates demo keys once; repeat runs must use `load_identity`.
The group ID must originate in a human-created policy. The API receives a pinned
owner key/group from its trusted caller; grant-only mode does not require a signed
group-creation policy. With `require_policy=True`, a persisted signed snapshot
must also approve the subject, grant ID and all grant permissions. See
[group policy](group-policy.md). It cannot be used as proof that the whole mesh is secure.

## Revocation and renewal

A revocation is a separately typed, owner-signed JWS containing exact group ID
and credential `jti`. Obtain `jti` from verified grant claims, then:

```python
signed = issue_revocation(owner, group_id, claims['jti'])
directory.revoke(signed)
```

Revocation is idempotent and persists across restart. Revoked grants cannot renew
and their entries immediately disappear from this directory's discovery results.
This does not stop an existing task or revoke a different previously issued grant.
Other directories must receive and verify the signed credential-revocation record
independently. [Policy synchronization](policy-sync.md) propagates membership
snapshots and these per-credential records; no partition-wide immediate guarantee
is provided.

The database pins owner fingerprint and group ID. Reopening with a different
owner/group fails. Restart retains identity ownership, grants and revocations,
but invalidates leases until fresh proof-based registration. New valid grants
for the same subject retain the same derived Agent ID. Grant validity caps lease
length; credentials with less than 10 seconds remaining cannot register.
Policy mode also caps leases at signed `issued_at + policy_max_age` and rejects
stale policy during registration/discovery. The maximum age defaults to 300
seconds and persists; the `policy_max_age` constructor argument may tighten it
but cannot increase it on restart. `policy_status()` reports current freshness
without changing the stored snapshot. Owner-authorized renewal preserves the
same group and subject identity. See [policy sync](policy-sync.md) for migration,
clock requirements and configured-source failover.

## Limits

- The separate loopback HTTP service/CLI is available; TLS transport is available and tested locally; TLS exporter/channel binding and
  decentralized discovery are not.
- `discover()` is a trusted-caller library method, not an authenticated remote
  discovery endpoint. Network callers need explicit read authorization.
- Proof context binds registration metadata, but production still needs a
  verified channel/audience to prevent relay and endpoint identity confusion.
- Signed grant permission `join` authorizes directory admission only. Advertised
  skills are self-descriptions, not execution privileges or attestations.
- No owner-key rotation or credential issuance UI. Optional signed policy
  enforcement integrates member removal and terminal dissolution into this
  directory; local UI lifecycle remains separate.
- SQLite stores grant and signed revocation tokens in plaintext. Protect backups.
- Construct one instance per database. Wrapper methods serialize admission;
  bypassing its private Registry/SQLite state bypasses its checks.

Tests cover valid registration, metadata tampering, nonce replay, wrong authority,
wrong-group revocation, expiry, durable revocation, authority pinning and renewal
with a new credential while retaining the subject's stable identity.
