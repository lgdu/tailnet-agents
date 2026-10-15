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
  integrated decentralized mesh are not. Separate [candidate providers](discovery.md)
  offer opt-in locators without changing proof-based registration.
- `discover()` is a trusted-caller library method, not an authenticated remote
  discovery endpoint. Network callers need explicit read authorization.
- Proof context binds registration metadata, but production still needs a
  verified channel/audience to prevent relay and endpoint identity confusion.
- Signed grant permission `join` authorizes directory admission only. Advertised
  skills are self-descriptions, not execution privileges or attestations.
- Owner-key rotation remains unimplemented. The optional [human issuer](credential-issuance.md)
  separately issues scoped grants. Optional signed policy
  enforcement integrates member removal and terminal dissolution into this
  directory; local UI lifecycle remains separate.
- SQLite stores grant and signed revocation tokens in plaintext. Protect backups.
- Construct one instance per database. Wrapper methods serialize admission;
  bypassing its private Registry/SQLite state bypasses its checks.

Tests cover valid registration, metadata tampering, nonce replay, wrong authority,
wrong-group revocation, expiry, durable revocation, authority pinning and renewal
with a new credential while retaining the subject's stable identity.

## Signed runtime observations (v0.23)

`challenge(record, presence=None)` and `register(..., record, presence=None)`
retain legacy behavior when the token is omitted for an unconverted identity.
In policy mode, an Agent-signed token adds metadata/expiry and durable instance
ordering to fresh proof-based admission. Lease/grant/presence commit together;
`presence_status(after='', limit=20)` returns bounded historical/live observations
with current authorization rechecked. Signed-runtime identities cannot bypass
ordering through legacy registration. See [runtime operations](agent-runtime.md)
for expiry, offline, same-host concurrency, restart and fencing limits.


## Peer observation cache (v0.25)

`configure_presence_sources`, `apply_peer_presence`, `export_presence` and
`peer_presence_status` add an explicit separate observation plane. Pages validate
signatures and local authorization before atomic cache/head application; every
read rechecks current policy and learned revocations. `export_presence` contains
scoped grants and only local direct history, so HTTP exposure needs a separate
opt-in. Imports never populate `agents`/`admission_grants` or change local proof
verification. Merged ordering/conflicts persist across restart and source changes;
this is not distributed operational fencing. See [peer presence](peer-presence.md).

## Separate signed message plane (v0.26)

The opt-in HTTP handler attaches `MessageStore` to the existing directory lock,
private SQLite connection, signed policy and learned revocations. It does not
populate admission records or local leases. Every operation independently checks
chat scope and key possession; direct history is participant-only. New persistent
message tables pin the original audience and retain immutable IDs/receipts across
restart. No read bearer shortcut or owner private key is used. See
[network messages](network-messages.md).

## Separate signed task plane (v0.27, unreleased)

`TaskExecutor` reuses current signed policy, scoped grants, learned revocations,
the directory lock and SQLite connection, with a separate exclusive executor file
lock. Task identity/audience is pinned; request/running/result boundaries and
signed terminal receipts persist. Running work interrupted before result commit
becomes uncertain, not a new invocation. No task adds admission records/leases or
creates groups. See [durable tasks](durable-tasks.md).
