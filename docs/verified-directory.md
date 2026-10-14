# Credential-enforced directory (v0.12)

`VerifiedDirectory` connects the optional identity component to SQLite directory
registration. It is an **in-process API**, not a new HTTP service. Existing
registry/Bridge/UI commands still use their previously documented bearer tokens.
Network admission, mesh replication and UI grant issuance are not wired up.

Install `.[identity]` before importing this component.

## Admission flow

1. A trusted human authority issues a grant for an agent key and exact group ID.
2. The caller prepares registration metadata (without an ID).
3. The directory creates a one-use challenge bound to normalized metadata.
4. The agent signs possession proof binding grant, audience, nonce and context.
5. Registration verifies the proof and grant before writing the metadata/credential
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
owner key/group from its trusted caller; it does not itself validate a signed
group-creation policy. It cannot be used as proof that the whole mesh is secure.

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
Other directories must receive and verify the signed record independently; no
propagation mechanism or partition-wide immediate guarantee is provided.

The database pins owner fingerprint and group ID. Reopening with a different
owner/group fails. Restart retains identity ownership, grants and revocations,
but invalidates leases until fresh proof-based registration. New valid grants
for the same subject retain the same derived Agent ID. Grant validity caps lease
length; credentials with less than 10 seconds remaining cannot register.

## Limits

- No HTTP route, CLI daemon, TLS/channel binding or decentralized discovery.
- `discover()` is a trusted-caller library method, not an authenticated remote
  discovery endpoint. Network callers need explicit read authorization.
- Proof context binds registration metadata, but production still needs a
  verified channel/audience to prevent relay and endpoint identity confusion.
- Signed grant permission `join` authorizes directory admission only. Advertised
  skills are self-descriptions, not execution privileges or attestations.
- No owner-key rotation, signed group policy, dissolution record integration or
  credential issuance UI. Local UI lifecycle and this directory remain separate.
- SQLite stores grant and signed revocation tokens in plaintext. Protect backups.
- Construct one instance per database. Wrapper methods serialize admission;
  bypassing its private Registry/SQLite state bypasses its checks.

Tests cover valid registration, metadata tampering, nonce replay, wrong authority,
wrong-group revocation, expiry, durable revocation, authority pinning and renewal
with a new credential while retaining the subject's stable identity.
