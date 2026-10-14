# Implementation status — v0.19 (unreleased)

This file and README describe current behavior. Architecture is the target design;
its future requirements must not be read as implemented security guarantees.

| Area | Current state | Next work |
|---|---|---|
| Registry | Durable central directory | Distributed discovery/anti-entropy |
| Task transport | Echo, bearer authentication, in-memory deduplication | Durable state and real adapters |
| MCP | Local tools subset | Real client interoperability verification |
| Human UI | Configured people/roles, explicit groups, private scopes, paging/polling | Browser QA, durable outbox, sessions |
| Lifecycle | Local human member revocation and terminal dissolution | Signed network propagation |
| Agent identity | Optional Ed25519 keys, scoped grants and possession proofs | Human policy issuance and key renewal |
| Verified directory | Library + HTTP/TLS admission, read token, durable signed revocation | Real LAN/tailnet trial, human policy issuance and mesh replication |
| Signed group policy | Durable snapshots, bounded signed age, approved grant IDs, terminal dissolution, opt-in HTTP enforcement | Human policy renewal UX, UI integration and explicit runtime enrollment |
| Policy replication | Ordered source failover, independent revocation cursors, HTTP/TLS pull and read-protected status | Multi-source reconciliation/quorum and explicit source enrollment |
| Candidate discovery | Opt-in signed IPv4 multicast, credential-free HTTP/TLS seeds, local-policy checks, expiry and identity merging | Physical LAN/tailnet trials, mDNS/peer enumeration and explicit runtime enrollment |
| Mesh | State simulator; candidate discovery is separate | Integrated cryptographic admission, signed presence and network group engine |
| Product agents | None | OpenClaw/Claude Code/Codex/Qoder/Grok interface validation |

New groups are human-created. Agent restart recovery retains an existing group
ID and valid qualification; failure to discover peers must not create a new group.
All-node downtime is sleep, not destruction. Local UI dissolution retains history.

UI human membership and cryptographic Agent credentials remain separate. The
verified directory can enforce signed member policy when explicitly enabled.
That mode persists across restart and cannot be reopened as grant-only. Existing
grant-only databases stay compatible. This does not create a human approval UI;
policies are issued by a trusted administrator API. The
existing registry/Bridge HTTP routes have not changed authentication. The mesh simulator's static IDs are not cryptographic identities.
The UI's three Echo participants are not real authorized network agents.

Verification: local core/identity tests, HTTP integration tests, simulated group
fault scenarios and JS syntax checks. Browser interaction, real tailnet/LAN,
external JWS interoperability and product Agent integration are not validated.
Policy propagation is tested between actual loopback HTTP/TLS services. Each
service still has independent registration leases and task/chat state. Peer
outages retain the last accepted policy and revocations but cannot extend its
signed authorization deadline. Active policies expire after 300 seconds by
default; the persisted maximum age can be tightened but not increased on restart.
Expired registration/renewal is denied and discovery hides affected records.
Leases cannot outlive policy or grant expiry. The same identity/group resumes
after a valid newer owner-signed policy; no group is created during recovery.

Source failover tries up to eight explicitly configured endpoints in order on
transport, authorization, signature, revision, freshness or scan-completion
failure. Each has a separate credential, CA and revocation cursor. Every poll
retries the primary. This is not newest-of-all-sources reconciliation: a healthy
primary can hide an unseen newer policy until its signed age expires. There is
no immediate partition-wide revocation, automatic policy re-signing or running
task cancellation. Signed tombstones and learned revocations remain durable.

Migration from v0.17 adds a policy-age setting; an old active snapshot may already
be expired at upgrade. Back up the database and prepare a fresh owner revision.
The policy wire format is unchanged. Versions before v0.18 do not enforce this
age limit. v0.18.0 is published as a GitHub prerelease with a matching version tag.

v0.19 adds a locator layer for already human-approved identities, using existing
keys and group IDs. The optional public `/v1/discovery` route and explicitly
selected LAN interface disclose only signed minimal metadata. Announcements live
at most 30 seconds, with no grant/token/private-key data. Seed requests carry no
Authorization/Cookie credentials, disable proxies/redirects and verify TLS.
Only administrator-configured seed origins are contacted. Unknown/foreign/stale
records are ignored and identities merge across providers. Conflicts remain
sticky throughout one scan; older announcements cannot claim sources of newer
versions. The Linux LAN receiver checks ingress interface and multicast destination
using IP_PKTINFO, rejecting unicast and truncated/missing metadata. LAN verification
is bounded to 128 attempts per second without ending the scan early.

The CLI requires an existing synchronized directory database opened read-only.
It verifies signed relevant revocations, enforces the persisted age bound and
re-reads state before output; newly learned revocations/tighter bounds apply and
policy changes require a retry. Scanning does not reset leases or modify registry
state. Static-policy-file scanning has been removed before the v0.19 release.
LAN receive filtering requires Linux and a primary local IPv4 address; seeds
remain available on other platforms. Same-interface floods and immediate delivery
of unseen remote revocations are not solved.

These are candidates, not admitted members or trusted policy sources. A signed
record does not establish endpoint ownership, grant expiry or permission to run
tasks. Existing proof-based admission remains unchanged. There is no automatic
group creation, credential issuance, enrollment or real Agent integration.
Tests include real loopback multicast, HTTP/TLS, subprocess startup/scanning,
restart with the same key/group, revoked self-signed seed/LAN announcements,
mid-scan state changes and absence of registration/lease side effects.
The full suite contains 155 tests (38 for candidate discovery).
Actual NIC/router/tailnet behavior remains unvalidated. See [discovery](discovery.md).
v0.19.0 is prepared in this PR and is not yet published or tagged.

## Documentation maintenance rule

Every behavior change must update README's current feature table, the relevant
usage guide and this status file. Update architecture only for changed decisions;
label future requirements. Record protocol changes and migration consequences.
Do not append contradictory version notes as a substitute for rewriting current
instructions. Never commit credentials, generated keys or runtime databases.
