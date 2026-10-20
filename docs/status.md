# Implementation status — v0.34 (unreleased)

This file and README describe current behavior. Architecture is the target design;
its future requirements must not be read as implemented security guarantees.

Source and documentation are available under the [MIT License](../LICENSE).
The [security policy](../SECURITY.md) describes private vulnerability reporting
and maintenance scope. This remains an experimental prototype; licensing does
not change the deployment or authorization boundaries below.

| Area | Current state | Next work |
|---|---|---|
| Registry | Durable central directory | Distributed discovery/anti-entropy |
| Signed tasks | Scoped Echo identities, durable signed intents/results, cancellation barriers, advisory notes, terminal archives/row quotas, a fixed signed-task MCP caller, independently checked UI human confirmation and local caller/consent admission budgets | Archives retain input/results; no payload deletion, running stop, verified external resolution, real adapters or HA; legacy bearer API remains in memory |
| MCP | Independent legacy bearer tools and explicit signed-task stdio caller, stable task IDs, confirmed single-task submit/cancel/archive, local/remote verified reads | Trusted local caller authority; no independent Human consent, real product/client validation or modern MCP task extensions |
| Human UI | Local roles/chat and opt-in signed policy creation/approval/removal/renewal/dissolution/export and explicit recipient delivery; separate grant issuance/download, explicit signed-task bindings/consents and capacity reads | Automatic secure provisioning, broader browser QA, durable outbox, sessions |
| Lifecycle | Local human member revocation and terminal dissolution | Signed network propagation |
| Agent identity | Optional Ed25519 keys, human-issued scoped grants, verified private-file installation and possession proofs | Trusted manual transfer, owner rotation and key renewal |
| Network messages | Explicit configured HTTP/TLS store, signed group/direct text, current scoped proof authorization, durable outbox/deduplication and catch-up cursors | Trusted plaintext storage; no E2E, Human UI integration, multi-store failover or automatic replies |
| Peer presence | Opt-in one-hop direct exports and configured multi-source pulls; independent signed grant/policy/revocation checks, bounded attributed cache and durable observation heads | No local lease/permission creation, onward gossip, relayed UI or distributed admission fencing |
| Runtime monitoring | Explicit signing-admin/creator reads from configured sources; signature/policy checks, scoped pages and browser expiry/race guards | Direct receiver observations only; peer copies use a separate API/CLI |
| Simulation runtime | Existing identity/group, signed heartbeat leases, durable boot/sequence ordering, graceful offline and paginated observations | POSIX; configured directory; authenticated manual UI monitoring; separate one-hop observation replication |
| Verified directory | Library + HTTP/TLS admission, read token, durable signed revocation and signed-runtime presence | Real LAN/tailnet trial, physical transport trials and mesh replication |
| Signed group policy | Durable snapshots, bounded signed age, approved grant IDs, terminal dissolution, opt-in HTTP enforcement | Live receiver monitoring and candidate-to-runtime trust handoff |
| Policy replication | Ordered source failover, independent revocation cursors, HTTP/TLS pull and read-protected status | Automatic reconciliation/quorum and explicit source enrollment |
| Human policy review | All configured recipients compared on explicit request; persistent signed history guards; fixed-time renewal preview/confirmation | No automatic source choice/adoption, fork recovery, grant renewal or delivery; failures leave history incomplete |
| Candidate discovery | Opt-in signed IPv4 multicast, credential-free HTTP/TLS seeds, local-policy checks, expiry and identity merging | Physical LAN/tailnet trials, mDNS/peer enumeration and explicit runtime enrollment |
| Mesh | State simulator, separate candidate discovery and one-hop signed observation replication | Integrated network group engine, multi-store messages and real executors |
| Adapter contracts | Strict reference Echo contract; offline product inventory and explicit nonce-bound signed metadata inspection | Compatible metadata is not execution permission or product health; no real interface validation, launchers or plugins |
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
relayed UI, real adapters and physical LAN/tailnet validation
remain unimplemented; v0.26 adds separate designated-store network messages, while
v0.27 adds a separate durable signed Echo task executor. See [peer presence](peer-presence.md). v0.25.0 is published as a GitHub prerelease with a matching annotated tag.
Merged main verification: 322 identity tests pass without skips; core passes 50
with 272 expected skips; both Chromium checks pass. The policy browser first
hit a five-second download-button assertion timeout; isolated retry and a
second repeat pass. This timing failure remains recorded in release notes.

## v0.26 signed group/direct network messages

Opt-in `--messages` adds a designated conversation store to policy-enforced
admission. Existing human-approved simulated Agent identities send signed text
and use single-use proofs bound to each send/read operation. Current grant,
policy age, permissions, approved IDs and revocations gate retries and history.
Direct messages require an approved recipient and are read only by participants;
neither bearer readers nor the owner get implicit read access. The store holds
plaintext, so E2E privacy is not implemented. Group readers see retained history.

The CLI persists original envelopes before sending, keeps uncertain messages
pending, deduplicates committed messages across both-end restarts and verifies
full history pages before atomically storing inbox entries/cursors. State pins
original key/owner/group/origin/audience/CA, with private POSIX files and exclusive
process locks. Same-host independent clients use different keys/state files.
No message creates a group/member, lease, Agent reply or task. Local Echo UI
remains separate. The suite contains 355 tests including 33 messaging cases with
real HTTP/TLS and service/client processes. Local validation: all 355 identity
tests pass without skips; core passes 50 with 305 expected skips; both Chromium
regressions, mesh simulator, dependency and documentation-link checks pass. See
[network messages](network-messages.md).

Unimplemented: E2E encryption, Human UI integration, push/automatic polling,
multi-store replication/failover, explicit cancellation/retention UX, real product
adapters and physical LAN/Tailscale/WAN trials; v0.27 adds separate signed durable Echo tasks. v0.26.0
is published as a GitHub prerelease with a matching annotated tag. Merged-main
verification: all 355 identity tests pass without skips; core passes 50 with 305
expected skips; both Chromium regressions pass on their first run.

## v0.27 durable signed Echo tasks

The admission service explicitly enables a simulation executor with an existing
Agent key and approved `task.echo` grant. Caller and executor independently require
current policy, permissions and unrevoked credentials; fresh operation-bound
proofs gate submissions/queries. IDs, intent hashes, both identities and context
are covered by task/receipt signatures. Directory read credentials and chat scopes
confer no task access. Results are caller-only.

Caller state persists original intent/ID and fixed executor/origin before sending;
a local paginated list recovers saved IDs if terminal output was lost.
Executor state commits queued/running/result boundaries. Lost responses and
both-end restart return the same completed/failed receipt; interrupted running
work becomes terminal `uncertain` without another adapter invocation. Queued
work never starts on startup/query; explicit authorized flush can retry it.
Private POSIX state and exclusive executor locks preserve original identities,
group, audience and caller service/CA pins. Same-host multiple executors use
independent keys/databases/listeners. Graceful close drains active calls.

The suite contains 390 tests, including 35 durable-task cases with real HTTP/TLS,
service/client processes, a subprocess exiting after a simulated side effect,
transaction failures before invocation/after execution, duplicate concurrency,
revocation/expiry/dissolution, result signature/conflict checks and recovery.
Local verification: all 390 identity tests pass without skips; core passes 50
with 340 expected skips; both Chromium regressions pass. CLI, dependencies,
package/MCP version, mesh simulator and 24-document link/anchor checks pass.
See [durable tasks](durable-tasks.md). No real product Agent is connected.

Unimplemented: real side-effect adapters, general exactly-once execution, database
rollback/key-clone recovery, MCP/Human UI integration, asynchronous scheduling,
automatic retry/polling, cancellation/uncertain resolution, retention/quota UI,
HA and physical LAN/Tailscale/WAN trials. The legacy bearer bridge remains
in-memory and independent. v0.27.0 is published as a GitHub prerelease with a matching annotated tag.
Merged main validation: 390 identity tests pass without skips; core passes 50
with 340 expected skips; both Chromium regressions pass on their first run.

## v0.28 all-source review and human renewal

The configured signing admin/group creator can explicitly compare every configured
policy recipient, including backups an available primary would hide. The gateway
verifies scoped owner signatures, reads freshness metadata between two snapshot
reads and reports attributed revision/semantic agreement and conservative age.
Every remote call is GET; source observations never alter local membership, grants,
leases, selected sources or active policy. Valid signed facts from partial or
changing reads still enter an atomic durable evidence ledger.

Known higher history, same-revision semantic conflict, timestamp rollback,
post-dissolution revisions or a learned terminal policy block new signatures,
including legacy manual renew/approval/removal/dissolution. Source failure/removal
and restart cannot erase those facts. Equivalent differently serialized tokens
are not semantic conflicts. No policy is automatically imported or selected.

The browser prepares a fixed-time, 60-second renewal consent after explicit reads.
Separate confirmation rechecks original snapshot, evidence and source bindings,
signs unchanged members/grant IDs, and commits audit/evidence/deduplication together.
An identical committed retry recovers the original acknowledgment after expiry or
new evidence, without a second signature. Expiry, browser clock rollback and late
responses after group/close/policy changes invalidate pending consent. Failed reads
clear earlier source rows. Unreachable sources cannot establish complete history;
human renewal may proceed only when the retained signed history is safe.

The suite contains 423 tests (33 new source-review/consent checks), with a third
Chromium workflow for explicit reads, confirmation, expiry, races, sticky conflicts
and narrow-screen layout. Full local rerun: all 423 identity tests pass without
skips; core passes 50 with 373 expected skips. The initial full run had one existing
runtime-monitor registration failure (`waiting` instead of `registered`) alongside
a server-side BrokenPipe; timeout is suspected but unconfirmed. Its isolated
21-test file passed, as did the complete rerun. See [policy review](policy-review.md)
for behavior and limits. All three final serial Chromium regressions passed;
JS syntax, dependencies, package/MCP version, mesh simulation and 25-document
link/anchor checks pass. PR #16 passed all six remote CI checks. v0.28.0 is
published as a GitHub prerelease with a matching annotated tag. Merged-main
verification: all 423 identity tests pass without skips; core passes 50 with 373
expected skips; all three Chromium regressions pass on their first run.

Unimplemented: automatic reconciliation/quorum, authority-history import and fork
resolution, evidence pruning/retention, owner rotation/recovery, real product
adapters and physical LAN/Tailscale/WAN trials. The evidence ledger contains signed
member snapshots; protect its consistent backups. Database rollback or deletion
cannot safely resolve a conflict. Normal directory pulls retain ordered failover.

## v0.29 reference adapter contracts and probing

The default durable executor uses an explicit Echo reference adapter with the
existing `echo-v1` identity and unchanged task wire format/SQLite context. Contract
inspection declares exact byte bounds, `task.echo`, synchronous execution, no
external side effects and running-to-uncertain recovery. Unknown contracts/types,
implicit retry or product substitution are rejected. In-process test callbacks
remain usable but cannot advertise a verified Echo contract.

The offline catalog lists real products as unimplemented/unvalidated and separates
Grok model API from Grok Agent. Explicit read-authenticated metadata probes bind
a fresh 256-bit nonce, configured source, original executor/owner/group/audience,
contract and bounded signed timestamps. The server checks its own current grant,
policy and revocation state; clients verify signatures/pins, source/nonce and age.
Descriptors last at most 15 seconds and cannot outlive the receiver's policy or
executor grant. Probe results do not establish caller execution rights, owner-signed
membership evidence, product health or future availability. They create no tasks,
members, leases or local caller state, and cannot resume queued/uncertain work.

The suite contains 453 tests: five new core contract/catalog checks and 25 new
signed HTTP/TLS/CLI probe checks. All 30 focused tests and all 453 full identity
tests pass without skips on the first run. Core passes 55 with 398 expected skips;
all three serial Chromium checks pass. Package/MCP version, dependency checks,
mesh simulation, JS syntax and 26-document link/anchor checks pass. See the PR for
remote CI results and [adapter contracts](adapters.md) for behavior and limits.

Unimplemented: real OpenClaw/Codex/Claude Code/Qoder/Grok interfaces, executable
product/plugin selection, arbitrary task kinds or filesystem/tool authority,
product login/session provisioning, model API integration, cancellation/timeouts
for real adapters, owner/key recovery and physical LAN/Tailscale trials. The Human
UI and MCP still use their separate simulated/legacy paths. v0.29.0 is published
as a GitHub prerelease with a matching annotated tag. PR #17 passed all six CI
checks. Merged-main validation: all 453 identity tests pass without skips; core
passes 55 with 398 expected skips; all three Chromium checks pass on their first run.

## v0.30 pre-execution cancellation and advisory uncertainty records

A caller explicitly previews its original task locally and confirms task ID/hash
before requesting cancellation. The client commits a durable cancellation barrier
before I/O; `flush` skips it after transport/receipt/storage failure, a queued
refresh or process restart. Nonterminal pending cancellations are separately counted
as `cancel_pending`, and show/list/receipt views retain `cancellation_requested`.

The executor accepts cancellation only for absent/queued original signed intents.
Current authorization for both principals and a fresh cancel-bound proof remain
required. Cancellation and the running marker serialize under one lock. A committed
signed `cancelled` tombstone prevents late original submissions from executing;
retries return the same receipt. Started/terminal work conflicts and is not stopped.
Tombstones retain input/ID history and count toward capacity; pruning remains open.

For a locally verified `uncertain` receipt, explicit preview/confirmation can append
a caller-signed review tied to original request/receipt hashes and context. Decisions
are human-entered advisory statements, not authenticated Human-principal attestations
or independently verified external effects. The signed record explicitly preserves
`task_status: uncertain`; it changes no result, membership, permission or retry gate.
Local history/review works after credential expiry/dissolution without remote I/O.

Caller state upgrades from the old binding list to `task-operations-v1` while
retaining keys/group/source and original tasks. Older callers reject that format,
preventing them from ignoring the cancellation barrier. Upgrade client and executor
together and protect consistent backups; no downgrade/reset bypass is supported.

The suite contains 483 tests (30 new task-operation checks). Focused operation and
existing 35 durable-task checks pass; an actual v0.29 caller also rejected migrated
state while v0.30 restored the cancellation barrier. Merged-main verification:
all 483 identity tests pass without skips; core passes 55 with 428 expected skips;
all three serial Chromium checks pass on their first run. Dependencies, package/MCP
version, mesh simulation, JS syntax and 27-document link/anchor checks pass.
PR #18 passed all six CI checks, and the merge commit passed main CI.
v0.30.0 is published as a GitHub prerelease with a matching annotated tag.
See [task operations](task-operations.md) for commands, migration and limits.

Unimplemented: stopping running/external work, verified uncertainty resolution,
requeue/migration after review, remote Human UI/MCP operations, note distribution,
retention/pruning, real product adapters and physical LAN/Tailscale trials.

## v0.31 explicit task archives and admission quotas

The original caller previews a locally verified terminal record and confirms its
ID, request hash and receipt hash before an authenticated archive request. Only
completed/failed/cancelled rows can move. One SQLite transaction under the directory
lock moves the full original input/status/receipt to the archive. No input/output
is deleted, and archival cannot free disk space or erase backups. Reads and late
submissions consult both areas and return the byte-identical original receipt.
Uncertain work remains in the active area; reviews cannot make it archivable.

Four configurable bounds apply to new submit/cancellation IDs: active rows and
total active+archive history, globally and by caller public-key identity. Defaults
are 256/10000 globally and min(64, active)/min(1000, history) per caller. Archival
releases active slots but retains total-history usage. Existing reads/retries and
eligible archival work at/above quota; new IDs return 429. Restart can explicitly
change operational bounds without forgetting or evicting history. No automatic
retention, executor disk/byte quota or rate limiter is claimed by these archives.

Executor startup migrates its context to `echo-v1/task-history-v1`, preserving the
original identity/group/audience, intents and `echo-v1` adapter contract. Older
executors reject this one-way format before overlooking archived IDs. Caller
format remains `task-operations-v1`; submit/get/cancel and result schemas remain
compatible with v0.30 callers. Archive placement is authenticated response metadata,
not a separately signed storage attestation or a new task result state.

Thirty-three new checks cover HTTP/TLS, actual client/service CLIs, four quota
bounds, independent same-host callers/executors, late submissions/cancelled
tombstones, concurrent reads/retries, lost ACK/local commit failures, transaction
rollback and format/history validation. Merged-main verification: all 516 identity
tests pass without skips; core passes 55 with 461 expected skips; all three serial
Chromium checks pass on their first run. Actual v0.30 sources also confirmed executor downgrade
rejection and caller archived-read/new-submit compatibility with original state.
Dependencies, package/MCP version, mesh simulation, JS syntax and 28-document
link/anchor checks pass. PR #19 passed all six CI checks, and its merge commit
passed main CI. v0.31.0 is published as a GitHub prerelease with a matching annotated
tag. See [task archives and quotas](task-history.md) for commands, backup and migration.

Unimplemented: payload pruning/compaction, automatic archive/retention, export/import,
executor byte/disk quotas, running-work cancellation, verified uncertainty resolution,
external Human sessions, real product adapters and physical LAN/Tailscale trials.

## v0.32 explicit signed-task MCP caller

A separate `tailnet-tasks-mcp` stdio entrypoint opens one original caller identity,
group, scoped grant, source/audience/CA, executor pin and private state from explicit
configuration. Twelve tools expose local stable-ID queue/preview/history/status,
single confirmed original submission, remote get/receipt verification, cancellation,
full-record archival and advisory-note reads. Local startup/listing never discovers
or submits work; tool arguments cannot replace configuration/credentials/executor.

Stable queue IDs persist the original signed intent before returning. Same ID/input
recovers it after lost output/restart; changed input conflicts. Single submit leaves
other pending work alone and respects durable cancellation barriers. Known running
and terminal results are returned locally without another network submission;
uncertainty/review notes never permit replay. Explicit refresh still requires current
remote authorization. This adds no wire format, database schema or new migration.

Config/key/grant reads require bounded owned private regular files. The original
caller context and POSIX state lock are shared with the CLI; concurrent use or
changed bindings fail. MCP clients use the configured Agent's authority; confirmation
arguments are caller assertions, not authenticated Human consent. Review creation
remains CLI-only. Existing legacy bearer tools stay independent and do not adopt
signed tasks; the new process has no registry/discovery fallback.

Thirty-one new checks (six core, 25 identity) cover exact tool schemas, private
configurations, single-task behavior, concurrent/stable queue IDs, failed/lost
ACK/receipt commits, running/uncertain/cancel barriers, same-host callers, HTTP/TLS
and actual stdio processes/restart. Merged-main verification: all 547 identity tests
pass without skips (312.821s); core passes 61 with 486 expected skips (10.435s); all
three serial Chromium checks pass on their first run. Actual v0.31 caller source
also retained the MCP original intent and cancellation barrier through CLI/new-MCP
handoff with the original identity/group.
Dependencies, installed entrypoint/version, mesh simulation, JS syntax and
29-document/225-local-link checks pass. [PR #20](https://github.com/lgdu/tailnet-agents/pull/20)
passed all six CI checks; merged-main CI also passed all three jobs. v0.32.0 is
published as a GitHub prerelease with a matching annotated tag. See
[signed-task MCP](task-mcp.md) for setup, tools, authority and recovery boundaries.

Unimplemented: actual product client interoperability/inbound workers, external
Human authentication/sessions, consent through MCP, MCP review creation,
modern protocol/task extensions, scheduling/polling, running cancellation, verified
uncertain resolution, payload deletion and physical LAN/Tailscale trials.

## v0.33 Human-confirmed signed Echo tasks

The trusted loopback gateway accepts one to sixteen explicitly configured original
caller bindings. A binding requires the existing signed UI group, matching owner,
configured admin human/group creator and original caller context/state. Other
admins, participants and observers cannot read/confirm it; browser/tool fields
cannot choose a credential path, origin, executor or Human identity. Existing
bindings cannot be silently removed or replaced on restart. Same-host callers
remain independent public-key subjects with separate outboxes.

Each queue/submit/refresh/cancel/archive action first stores a stable-ID preview
with exact original input, task, executor and policy snapshot. A separate Human
confirmation expires after 60 seconds if unstarted and commits `started` before
caller mutation/network I/O. Failure/restart requires explicit retry of that same
consent/intent. Completed acknowledgments remain historical local reads. Tasks and
consent history are paginated local reads; startup, chat, previews and listing
never submit work. Cancellation barriers and immutable uncertain/terminal receipts
remain unchanged. UI and caller records use separate transactions; a started
consent can represent a successful but unacknowledged operation.

The separate configured UI bearer credential authenticates this local Human; no
external identity provider, Human signature or task-wire consent enforcement is
claimed. Trusted OS operators can still use CLI/MCP with the Agent key. The UI
stores additional plaintext consent inputs/results and immutable binding contexts;
no task wire/caller/executor migration is added. Back up all original state and
observe earlier one-way migrations. See [Human task UI](task-ui.md).

Validation: 24 new checks cover default-off core behavior, private bindings,
role/group/schema isolation, consent expiry/clock rollback, policy changes,
concurrent/lost acknowledgments, transaction failures, restart/CLI loading,
cancellation barriers, uncertain refusal, HTTPS/CA, current remote authorization
and same-host independent callers. A fourth Chromium script checks actual human
interaction, edited drafts, expiry, original-ID retry/archive/cancel recovery,
late responses, logout and narrow layouts. Merged-main verification: all 571
identity tests pass without skips (363.456s); core passes 63 with 508 expected
skips (10.832s); all four serial Chromium workflows pass on their first run.
The delayed re-preview check confirms the old display is cleared and task-ID
confirmation stays locked until the response. Actual v0.32 caller source also
preserved the original UI intent, cancellation barrier and started consent through
CLI/UI handoff without replay. Dependencies, installed CLI/version, JS syntax,
mesh simulation and 30-document/243-local-link checks pass. [PR #21](https://github.com/lgdu/tailnet-agents/pull/21)
passed all six final CI checks; merged-main CI also passed all three jobs.
v0.33.0 is published as a GitHub prerelease with a matching annotated tag.

Remaining: external Human authentication/sessions, Human uncertainty-review
creation, real product adapters/interoperability, MCP Human-consent bridging,
modern task extensions, scheduling, running stop, verified external resolution,
payload pruning, executor byte/disk bounds, HA and physical LAN/Tailscale trials.

## v0.34 local task storage admission (unreleased)

Original callers enforce configured unresolved/total task counts, charged payload
bytes and local review counts before accepting new records. Charged usage includes
a 16384-byte signed receipt plus cancellation-metadata reservation per task; saved
results/barriers do not compete with new work for that space. Existing stable-ID
queue recovery and signed review retries precede admission. Completed/failed/
cancelled receipts free only unresolved slots; uncertain work keeps its slot and
all original history remains charged through executor archival.

The UI separately limits retained consent count/charged bytes per Human/binding,
including 32768 result bytes reserved for each bounded Echo acknowledgment. New
previews are atomically admitted; saved preview/started/done recovery is available
at/above budget. A full UI budget also blocks a new cancellation preview: increase
configured limits/restart, or stop UI and use the original caller CLI. Existing
caller cancellation never depends on admitting another task. No quota bypasses
Human consent, changes membership, deletes history or chooses another executor.

CLI `storage`, existing signed MCP status and explicit UI capacity reads expose
limits/usage. Limits are typed startup/configuration options, not persisted policy
or physical disk bounds. Lowering below occupancy retains state; old clients do
not enforce new budgets. Task wire/caller/executor formats and UI tables remain
unchanged. Prior migrations and full consistent backups remain required. See
[local task storage](task-storage.md).

Twenty-six new checks (four core, 22 identity) cover exact byte boundaries,
multibyte accounting, concurrent/transactional admission, quota errors and schema
checks, receipt/cancel/review recovery, real CLI/config/MCP behavior, same-host
independence and UI saved-confirmation restart. Chromium adds explicit usage,
full-preview denial and same-consent queue recovery. Clean pinned-main baseline:
all 571 identity tests pass (372.307s). Final local verification: all 597 identity
tests pass without skips (344.993s); core passes 67 with 530 expected skips
(10.547s); all four serial Chromium workflows pass. Actual v0.33 caller/UI source
also preserves original identities/groups, intents, cancellation barriers and
consent history through handoff; reopening retains over-limit rows and blocks new
admission without replay. Package/MCP version, dependencies, installed CLI, JS
syntax, mesh scenarios and 31-document/257-local-link checks pass. See the PR for
remote CI results.

Remaining: executor aggregate byte/disk quotas, payload pruning/compaction,
Human UI uncertainty-review creation, external Human sessions, real adapters,
verified external outcomes, scheduling, running stop, HA and physical trials.

## Documentation maintenance rule

Every behavior change must update README's current feature table, the relevant
usage guide and this status file. Update architecture only for changed decisions;
label future requirements. Record protocol changes and migration consequences.
Do not append contradictory version notes as a substitute for rewriting current
instructions. Never commit credentials, generated keys or runtime databases.
