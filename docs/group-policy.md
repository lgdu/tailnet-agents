# Signed group policy — v0.21 (unreleased)

This optional layer connects persistent signed membership to the verified
admission directory. The optional [human UI signing gateway](human-policy.md)
now creates and updates snapshots with explicit export/manual application or
[human-confirmed recipient delivery](policy-delivery.md). Full mesh
integration remains future work. [Configured-peer policy replication](policy-sync.md) is available. A trusted administrator explicitly creates and signs snapshots;
an Agent must never call creation on startup or discovery timeout.

## Human administration example

Install `.[identity]`. Keep the owner's private key on the administrator machine.
A directory needs only its pinned public key, the group ID and signed snapshots.
Use `generate_identity` once to prepare keys; use `load_identity` on subsequent
runs. Files below are runtime state and must stay outside git.

```python
from pathlib import Path
from tailnet_agents.identity import (
    load_identity, issue_grant, verify_grant, identity_id, encode, public_bytes,
)
from tailnet_agents.group_policy import create_policy, revise_policy, POLICY_TYPE
from tailnet_agents.identity import verify

owner = load_identity('state/owner.pem')
agent = load_identity('state/agent.pem')

# Explicit human action. Creates a NEW random group ID and empty member policy.
initial = create_policy(owner, 'My approved agents', {})
# Extract the new ID from an owner-verified message, not untrusted decoded JSON.
group_id = verify(initial, owner.public_key(), POLICY_TYPE)['group_id']
grant = issue_grant(owner, agent.public_key(), group_id, ['join', 'discover'])
claims = verify_grant(grant, owner.public_key(), group_id)
members = {
    identity_id(agent.public_key()): {
        'permissions': ['join', 'discover'],
        'grant_ids': [claims['jti']],
    }
}
approved = revise_policy(owner, initial, members)
Path('state/owner.pub').write_text(encode(public_bytes(owner.public_key())))
Path('state/group.policy').write_text(approved)
Path('state/agent.grant').write_text(grant)
Path('state/agent.grant').chmod(0o600)
print(group_id)  # Use this exact ID in service configuration.
```

Do not rerun creation to restore an existing group. Retain its signed snapshot,
group ID and owner key. For later changes load the most recently accepted
snapshot, verify it with the pinned key and revise it.

## Start with enforcement

```bash
python3 -m tailnet_agents.admission_server \
  --authority-public-key state/owner.pub \
  --group-id YOUR-EXACT-GROUP-ID \
  --audience receiver-identity \
  --require-policy \
  --policy-file state/group.policy
```

Set `TAILNET_VERIFIED_READ_TOKEN` as described in [HTTP admission](admission-http.md).
For non-loopback connections also configure [TLS](tls-deployment.md).
`--policy-file` implies enforcement. `--require-policy` without a file allows
startup but denies admission until an authorized signed snapshot is submitted.
Restart can omit the file once stored, but must retain `--require-policy`.
Reapplying the same latest snapshot is harmless; an older file fails startup.
Active snapshots now have a maximum signed age: 300 seconds by default, or a
stricter persisted `--policy-max-age` limit. Restart and duplicate delivery do
not renew them. Registration leases cannot exceed the policy deadline. Before
expiry, the existing human authority must issue a newer signed revision with a
current timestamp, even when membership is unchanged. Do not recreate the group.
Without renewal, registration fails and discovery hides affected records while
preserving the original group and identity for recovery. See
[configuration and migration](policy-sync.md#signed-policy-age-and-renewal).

Submit subsequent snapshots with the authenticated shared client:

```python
from tailnet_agents.client import Client
client = Client('http://127.0.0.1:8771', 'YOUR-READ-TOKEN')
client.request('/v1/policies', {'policy': approved})
```

Remote use requires HTTPS and trusted CA configuration. The service requires
both the read token and owner signature. Possessing the read token alone cannot
add members. Directory HTTP routes never accept owner private keys or issue policies. The
separate opt-in loopback human gateway signs with an existing local key; it never
accepts private keys over HTTP or sends them to directories.

## Remove, renew and dissolve

Remove a subject from the member map, then `revise_policy(owner, current, members)`
and submit the new snapshot. Existing directory entries disappear immediately
and registration/renewal fails even if a grant has not expired.

Each member lists explicitly approved grant IDs, up to eight, and allowed
permissions. The grant must pass its existing signature/expiry/revocation checks,
have an approved ID and request a subset of these permissions. A newly issued
grant requires a policy revision approving its new ID. To re-admit a removed
member, approve a new grant; copying an old grant ID back into policy explicitly
re-authorizes it, so do not do so unintentionally. Advertised skills still convey
no task execution authority.

For dissolution use `revise_policy(owner, current, {}, dissolve=True)` and submit
it. A learned dissolution is permanent for this group instance, including after
restart and even if a later owner-signed active snapshot has a higher revision.
Creating a replacement group requires a new ID. Offline presence does not change
policy or dissolve anything.

## Persistence, rollback and limits

Snapshots are typed Ed25519 JWS messages with exact fields: `owner`, `group_id`,
`name`, `revision`, `issued_at`, `state`, `members`. Revisions are positive integers;
member maps are limited to 64 identities and messages to 16 KiB. Effective capacity
can be lower depending on encoded size. Only `active` and `dissolved` exist.

The SQLite database pins authority and group. Enforcement mode persists and
cannot be disabled by restarting in grant-only mode. Existing grant-only databases
can opt in; an empty/unapproved policy immediately blocks previous records.
A receiver rejects lower revisions, unequal same-revision snapshots, time rollback,
foreign owners/groups and malformed policies. Exact duplicate delivery is idempotent.
An owner-signed newer full snapshot may skip revisions for offline recovery.

Directory operations serialize policy updates with registration/discovery; a
successful update affects subsequent checks. Previously returned records and
already dispatched tasks are not cancelled. Registration leases still expire
and require fresh possession proof after directory restart.

Configured directory peers can now pull full signed snapshots periodically.
No automatic enrollment, global ordering, owner-key rotation or partition-wide
immediate revocation exists. Signed age is now bounded, with up to 30 seconds of
future-timestamp tolerance and no expiry grace. A partitioned receiver cannot
learn a removal immediately; its last policy authorizes only until its original
deadline. Learned dissolution never expires. Ordered source failover does not
weaken rollback or conflict rejection.
[Signed candidate discovery](discovery.md) can locate existing policy-approved
identities via explicit-interface multicast or configured seeds. It carries no
grant and never modifies this policy, enrolls a member or selects trusted sources.
Two owner-signed snapshots at the same revision cause a conflict requiring human
resolution via a higher revision; terminal dissolution remains irreversible at
receivers that learned it. Restoring an older database backup can lose learned
revocations/tombstones: retain current policy externally and replay it before use.
SQLite tokens and backups are plaintext; protect the database and owner key.
