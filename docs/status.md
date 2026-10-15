# Implementation status — v0.25

This file and README describe current behavior. Architecture is the target design;
its future requirements must not be read as implemented security guarantees.

| Area | Current state | Next work |
|---|---|---|
| Registry | Durable central directory | Distributed discovery/anti-entropy |
| Task transport | Echo, bearer authentication, in-memory deduplication | Durable state and real adapters |
| MCP | Local tools subset | Real client interoperability verification |
| Human UI | Local roles/chat and opt-in signed policy creation/approval/removal/renewal/dissolution/export and explicit recipient delivery; separate grant issuance/download | Automatic secure provisioning, broader browser QA, durable outbox, sessions |
| Lifecycle | Local human member revocation and terminal dissolution | Signed network propagation |
| Agent identity | Optional Ed25519 keys, human-issued scoped grants, verified private-file installation and possession proofs | Trusted manual transfer, owner rotation and key renewal |
| Peer presence | Opt-in one-hop direct exports and configured multi-source pulls; independent signed grant/policy/revocation checks, bounded attributed cache and durable observation heads | No local lease/permission creation, onward gossip, relayed UI or distributed admission fencing |
| Runtime monitoring | Explicit signing-admin/creator reads from configured sources; signature/policy checks, scoped pages and browser expiry/race guards | Direct receiver observations only; peer copies use a separate API/CLI |
| Simulation runtime | Existing identity/group, signed heartbeat leases, durable boot/sequence ordering, graceful offline and paginated observations | POSIX; configured directory; authenticated manual UI monitoring; separate one-hop observation replication |
| Verified directory | Library + HTTP/TLS admission, read token, durable signed revocation and signed-runtime presence | Real LAN/tailnet trial, physical transport trials and mesh replication |
| Signed group policy | Durable snapshots, bounded signed age, approved grant IDs, terminal dissolution, opt-in HTTP enforcement | Live receiver monitoring and candidate-to-runtime trust handoff |
| Policy replication | Ordered source failover, independent revocation cursors, HTTP/TLS pull and read-protected status | Multi-source reconciliation/quorum and explicit source enrollment |
| Candidate discovery | Opt-in signed IPv4 multicast, credential-free HTTP/TLS seeds, local-policy checks, expiry and identity merging | Physical LAN/tailnet trials, mDNS/peer enumeration and explicit runtime enrollment |
| Mesh | State simulator, separate candidate discovery and one-hop signed observation replication | Integrated network group engine, cross-node messages and tasks |
| Product agents | None | OpenClaw/Claude Code/Codex/Qoder/Grok interface validation |

New groups are human-created. Agent restart recovery retains an existing group
ID and valid qualification; failure to discover peers must not create a new group.
All-node downtime is sleep, not destruction. Local UI dissolution retains history.

Human chat membership and cryptographic Agent credentials remain separate. The
optional trusted loopback UI signer can create a signed group with the same ID,
separately issue scoped grants and approve membership, remove identities, explicitly renew policy and sign
terminal dissolution. A configured admin and the original private key/public pin
are required, persisted and checked on restart. Private keys are never accepted
or returned by HTTP. The default local UI works without the identity extra.
Policies require manual application or explicit preview/confirmation to a configured recipient;
reading, polling and discovery neither renew nor deliver them. The three Echo
participants remain unauthenticated chat simulations. Existing registry/Bridge
HTTP authentication is unchanged; the mesh simulator's IDs are not cryptographic.

Verification: local core/identity tests, HTTP integration tests, simulated group
fault scenarios and JS syntax checks. The new signing workflow has Chromium functional coverage. Broader browser QA, real tailnet/LAN,
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
The v0.19 baseline contains 155 tests (38 for candidate discovery).
The first post-merge main identity CI run failed and passed on rerun; its original
failure cause remains unconfirmed because log downloads were inaccessible.
Actual NIC/router/tailnet behavior remains unvalidated. See [discovery](discovery.md).
v0.19.0 is published as a GitHub prerelease with a matching version tag.

v0.20 adds 23 policy-admin tests and one core default-mode check,
bringing the full suite to 179.
Policy changes, audit and retry acknowledgments commit atomically; stale revisions
and changed retry payloads conflict. Removed grant IDs cannot be reapproved in
the UI. Creation, approvals and renewals require explicit human action. Existing
local groups remain local and startup never converts them. Browser tests exercise
creation, verified preview, approval, export, lost-response retry, removal and
terminal dissolution; backend tests exercise real UI/directory HTTP and restart.
Browser regressions defer policy reads after mutations, verify export stays
disabled until the latest revision is read, and cover read failure/retry without
repeating an acknowledged mutation. A dedicated CI browser job runs these checks.
At v0.20, credential issuance/provisioning, background delivery, remote sessions,
owner recovery/rotation and full runtime enrollment remained unimplemented. See
[human policy signing](human-policy.md). v0.20.0 is published as a GitHub prerelease with a matching version tag.

v0.21 adds explicit recipient configuration and human-confirmed policy
delivery with signed readback and historical revision/freshness receipts. Recipient
URLs/groups/CA and credential environment names are configured only on the trusted
human machine. Startup, preview, policy signing and discovery do not contact them.
A lost response can recover from persistent intent/history without renewing or
registering anything. Local policy changes proceed during network I/O; a changed
snapshot returns conflict, and old copies may already have arrived. There is no
atomic multi-recipient revocation or automatic replacement.
Multiple Agents on one host remain independent public-key identities, with
separate human approval, leases and removal/revocation. Same-host discovery does
not merge subjects. Restart reloads each original key and group; shared IP,
hostname, display name or Tailscale device is never a membership uniqueness key.
The v0.21 suite contains 208 tests (24 new delivery checks and five same-machine
multi-Agent checks), plus Chromium UI delivery
and lost-acknowledgment regression in CI. Real Agents and physical LAN/tailnet/WAN
remain unvalidated. In v0.21 grant issuance UX remained manual. See
[policy delivery](policy-delivery.md). v0.21.0 is published as a GitHub prerelease with a matching annotated tag.

## v0.22 credential issuance

The configured human signer can preview an existing Agent public key, scope and
fixed lifetime, explicitly issue a credential, download it and separately preview
membership approval. Issuance leaves policy revision/membership unchanged and
never contacts recipients. A stable persisted request reconstructs the same
credential after response loss/restart without extending expiry. Only public
claims/request metadata and a token hash are stored; local history is not tamper-proof.
The recipient installer validates owner/group/expiry/its own original identity
and creates a new 0600 file, refusing overwrite, symlinks and wrong recipients.
Multiple Agents on one host receive distinct credentials and approvals.

The v0.22 suite contains 234 tests (26 new issuance/installation tests), plus Chromium
preview-race, issuance/download/retry and separate-approval checks. Secure remote
transfer remains a human operation; real Agent runtime enrollment, live revocation
monitoring, key rotation/recovery and physical LAN/tailnet validation remain open.
See [credential issuance](credential-issuance.md). v0.22.0 is published as a GitHub prerelease with a matching annotated tag.

## v0.23 simulation runtime and signed presence

The opt-in runtime loads an existing approved simulation key/grant/group and uses
a private, exclusively locked state file. Startup advances a durable generation
and creates a new boot ID while keeping the original Agent identity. Signed
heartbeats bind metadata, state, sequence and expiry into fresh possession proofs.
The directory enforces ordering, authorization age/expiry/revocation and persists
observations; restart invalidates live leases without losing membership/history.
Explicit offline, expired leases and unauthorized observations remain distinct.
Signed-runtime identities cannot fall back to legacy registration on that directory.

Authenticated presence pages/CLI verify signatures and report point-in-time
directory observations. Two live processes on one host renew independently;
stopping one preserves the other. The suite contains 275 tests (41 new runtime/
presence cases), including fractional clocks with the minimum ten-second TTL,
transport consumption and grant/policy expiry gates. Signed timestamps retain
fractional precision; remaining leases use one receipt-time snapshot and round
down without extending deadlines. Online is an authorized heartbeat, not verified executor health.
At v0.23, peer presence replication, authenticated UI integration, real product adapters,
strong distributed fencing and physical LAN/tailnet trials remain unimplemented.
See [runtime operations](agent-runtime.md). v0.23.0 is published as a GitHub prerelease with a matching annotated tag.

## v0.24 authenticated runtime monitoring

The trusted human gateway can read one page of signed runtime observations from
an explicitly selected configured directory. Signing-admin/group-creator, Host
and Origin checks protect access; no credentials or full grants reach the browser.
Owner/group/Agent signatures, metadata, cursors, expiry and signed source-policy
status are verified. Source policy must match the local snapshot for confirmed
online status; changes during I/O discard the result without blocking mutations.
Only GET requests run, with no signing/delivery/registration/lease changes.

The UI labels source and time, keeps same-host subjects separate, ages leases
conservatively with monotonic elapsed time, and clears old observations on failed
reads, source/group/policy changes, close and logout. It stays separate from Echo
chat members. The suite contains 296 tests (21 new monitoring checks), plus a
Chromium monitoring/race regression alongside existing signing/delivery coverage.
At v0.24, peer presence replication, continuous revocation monitoring, real product adapters
and physical LAN/tailnet trials remain open. See [monitoring](runtime-monitoring.md).
v0.24.0 is published as a GitHub prerelease with a matching annotated tag.

## v0.25 configured peer presence replication

Sources explicitly opt in to exporting local signed heartbeats and scoped grants.
Receivers pull all configured same-group sources, independently verify Agent and
owner signatures, local grant approval/policy age/revocations, and commit each
validated page to a separate cache plus durable observation heads. Copies are not
local registrations. Exact replays cannot extend deadlines or promote expired/
unauthorized cache rows; old instances remain suppressed after restart or source
removal. Contradictory boots/tokens require a higher generation to clear conflict.

The authenticated API/CLI groups distinct Agent subjects with local/source
attribution, policy/expiry checks and bounded subject pages. One-hop exports never
forward cached rows; ordinary presence/browser reads still omit grants. The suite
contains 322 tests, including 26 replication cases covering actual HTTP/TLS and
service/reader CLIs, replay/conflict, independent multi-Agent identities, bounded
scans, transaction rollback, partitions, restart and shutdown. Multi-hop gossip,
relayed UI, cross-node chat/tasks, real adapters and physical LAN/tailnet validation
remain unimplemented. See [peer presence](peer-presence.md). v0.25.0 is published as a GitHub prerelease with a matching annotated tag.
Merged main verification: 322 identity tests pass without skips; core passes 50
with 272 expected skips; both Chromium checks pass. The policy browser first
hit a five-second download-button assertion timeout; isolated retry and a
second repeat pass. This timing failure remains recorded in release notes.

## Documentation maintenance rule

Every behavior change must update README's current feature table, the relevant
usage guide and this status file. Update architecture only for changed decisions;
label future requirements. Record protocol changes and migration consequences.
Do not append contradictory version notes as a substitute for rewriting current
instructions. Never commit credentials, generated keys or runtime databases.
