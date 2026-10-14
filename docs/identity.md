# Agent identity and admission primitives (v0.17)

This optional library component uses Ed25519 through `cryptography`.
[VerifiedDirectory](verified-directory.md) integrates it with registration through
an in-process API. It is not wired into existing registry HTTP routes, Bridge,
UI or mesh simulator. Existing services still
use their documented bearer-token authentication. A separate [loopback HTTP admission endpoint](admission-http.md) is available.
TLS transport is provided for controlled trials; actual cross-machine validation
and a human grant-signing UI remain pending.

## Installation

```bash
python3 -m pip install -e '.[identity]'
```

Core services do not require this dependency. Identity tests are skipped when
it is unavailable; CI has a separate identity installation that runs them.

## Offline example

Run in a protected working directory. File creation refuses to overwrite keys.
Use your real group ID, not its display name. This example creates fresh demo
keys; it does not grant authority to real network nodes.

```python
from tailnet_agents.identity import (
    Admission, generate_identity, issue_grant, prove_possession,
)

owner = generate_identity('state/owner.pem')
agent = generate_identity('state/agent.pem')
group_id = 'YOUR-EXISTING-GROUP-ID'
grant = issue_grant(owner, agent.public_key(), group_id,
                    ['join', 'discover', 'task.echo'], lifetime=3600)

receiver = Admission(owner.public_key(), group_id, audience='receiver-identity')
nonce = receiver.challenge()
proof = prove_possession(agent, grant, nonce, audience='receiver-identity')
claims = receiver.admit(grant, agent.public_key(), proof, nonce,
                        permission='task.echo')
```

Reload an existing key with `load_identity(path)`. Owner keys are for human
administration; execution agents must never receive the owner's private key.
The verifier must receive the trusted owner PUBLIC key through a trusted setup
channel, not from the joining agent. The demo `audience` is a verifier identifier;
production requires binding it to a verified remote identity/channel.

## Signed format and scope

Tokens use compact JWS serialization with EdDSA/Ed25519. Header algorithm, type
and trusted key fingerprint are checked exactly. Grant and possession-proof
message types differ, preventing cross-type reuse. This is a custom grant profile,
not a standard A2A credential or an interoperable identity product.

Grant claims: issuer fingerprint, subject fingerprint, exact group ID, explicit
permissions, issued/not-before/expiry times and random credential ID (`jti`).
No wildcard group, administrative delegation or automatic group-creation
permission is supported. Current allowlist: `join`, `discover`, `chat.group`,
`chat.direct`, `task.echo`. Every grant requires `join`. Lifetime is at most
24 hours; no clock-skew allowance is added, so synchronize verifier clocks.

The verifier checks issuer, group, requested permission, expiry and the supplied
revocation set. Possession proof binds the subject key to the credential hash,
challenge nonce and verifier audience. An optional context digest binds
application request content; VerifiedDirectory requires it for metadata integrity. Challenges expire in 30 seconds, are
single-use on successful admission, and are limited to 256 live entries.
Invalid claims, unsupported algorithms/types, duplicate JSON fields and
noncanonical base64url are rejected.

## Security and integration limits

- Private keys are unencrypted local PKCS8 PEM files, created mode 0600. Host
  compromise or database/secret access is outside this protection. No key
  recovery, rotation or secure hardware integration is implemented.
- `Admission` is single-threaded and in-memory. Wrap it with synchronization
  before using it in concurrent handlers. Restart drops outstanding challenges.
- Revocation is a caller-supplied set of credential IDs. The caller must persist
  and refresh it. VerifiedDirectory persists verified owner-signed revocations,
  and configured-peer sync replicates them. No immediate partition-wide guarantee
  exists; ordinary bearer registry/Bridge routes still use their existing checks.
- Verified admission has TLS and opt-in [signed group policy](group-policy.md),
  including terminal dissolution. TLS exporter binding, relay-resistant network
  handshakes and admission rate limits remain pending. Configured-peer signed policy propagation is available.
  A signed response alone does not authenticate a channel.
- Signature serialization has tests, but no external JWT/JWS conformance suite
  or independent security audit has been run.
- A grant passing verification does not execute a task or bypass a product's
  own permissions. Network transport and task receivers must enforce it.

Tests cover persistent identity, valid admission, nonce replay, wrong authority,
group and subject, expired/future grants, missing permissions, payload tampering,
proof audience/credential binding and local credential revocation.

Primary API reference:
https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/

## Candidate announcement use (v0.19)

[Discovery](discovery.md) uses an existing approved simulation identity key to
sign a separately typed, short-lived locator. Neither a grant nor a private key
is transmitted in announcements. The scanner verifies the key against its local
signed policy, but results do not establish grant validity, endpoint ownership
or admission. The existing grant/proof checks remain mandatory and unchanged.
