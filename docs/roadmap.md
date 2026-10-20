# Remaining work for the v0.33 development line

The verified directory can persist and exchange signed policy and credential
revocations between configured peers. The human UI remains a local simulated chat application, with an optional
trusted owner signer and explicit policy-export handoff. This is not yet a complete heterogeneous Agent collaboration network.
v0.18 adds bounded signed-policy age, restart-safe enforcement and ordered
source failover. Sources cannot renew old authorization merely by replaying it.
Human policy renewal, trusted clocks and real-network trials are still required.
v0.19 adds opt-in signed LAN multicast and explicitly configured HTTPS seed
discovery. These produce candidates only; they never enroll a peer or grant
membership, choose policy sources or generate identities/groups at startup.

v0.20 adds human-confirmed signing, verified grant preview/approval, removal,
manual renewal, terminal dissolution, local audit and policy export. Grant
issuance/provisioning was a separate manual step at that stage. v0.21 adds explicitly
configured recipient delivery with signed readback and historical freshness receipts.
v0.22 adds separate human-confirmed credential issuance/download, stable recovery
and an identity-checking private-file installer. Transfer remains manual through
a trusted channel; membership approval and runtime proof remain separate.
v0.23 adds an opt-in simulation runtime, persistent incarnation ordering, signed
heartbeat leases and authenticated online/offline observations at one configured
directory. Same-host processes retain independent identities and state.
v0.24 adds authenticated, explicitly read runtime monitoring on the trusted human
gateway, with source/time attribution, signed-policy agreement, expiry and stale
response guards. The monitor does not copy presence into another directory.
v0.25 adds separate opt-in one-hop presence exports/pulls, independent scoped
grant verification, source attribution and durable merged-observation ordering.
Copied observations never become local admission leases or automatic membership.
v0.26 adds signed group/direct text through one designated trusted store, scoped
operation proofs, durable outbox/receiver deduplication and atomic catch-up cursors.
The simulation CLI remains separate from Human UI chat; store operators hold plaintext.
v0.27 adds an explicit signed Echo executor and durable caller/executor state.
Running work interrupted before result commit becomes uncertain and cannot be
automatically rerun or migrated; queued work requires an explicit authorized retry.

| Priority | Work | Acceptance evidence |
|---|---|---|
| P1 | Discovery operations and explicit runtime enrollment | Validate physical LAN/tailnet behavior, optional mDNS/peer enumeration and a separately authorized handoff from candidate to admitted runtime |
| P1 | Policy history reconciliation and recovery | Explicit safe authority-history import/fork resolution, evidence retention, and quorum semantics; v0.28 delivers all-source diagnosis and human renewal consent |
| P2 | Task operations | Build on cancellation/reviews, archives/row quotas, v0.32 fixed signed-task MCP and v0.33 explicit Human UI consent: safe payload compaction, byte/outbox bounds, verified external outcomes, running cancellation and scheduling; no automatic replay |
| P2 | Message operations | Human UI integration, explicit blocked-outbox cancellation, retention/quotas, push and multi-store routing; any relay privacy claim requires E2E encryption |
| P2 | Presence operations | Multi-hop propagation and relayed UI preserve original deadlines, provenance and observed conflicts |
| P2 | Real adapters | Build on the reference contract/probe; validate available product interfaces individually, explicit task scopes and recovery behavior; model APIs and product Agents are distinct |
| P2 | Secure provisioning operations | Authenticated confidential transfer, credential retention/pruning, recovery and key rotation are verified without confusing installation with admission |
| P2 | Operational deployment | Actual household LAN and cross-region tailnet trials, certificate/key renewal, backups, rate limits and service packaging |
| P2 | Release readiness | Browser interaction QA, interoperability/security review and installation instructions; MIT licensing and a private vulnerability reporting policy are in place |

v0.28 adds explicit all-source policy diagnosis, persistent conflict/terminal
evidence and fixed-time human renewal consent, without automatic snapshot adoption.
v0.29 adds a strict Echo reference contract, offline implementation inventory and
explicit signed metadata probe. Real product interfaces remain unvalidated; no
installed product is scanned or launched, and metadata grants no task rights.
Suggested next order: validate available product interfaces → explicitly scoped
real adapters → physical deployment trials. While product access remains unavailable,
v0.30 provides explicit pre-execution cancellation and caller-signed local
uncertainty notes using simulation, without stopping running work or rewriting
outcomes. v0.31 adds explicit full-record terminal archives and global/per-key row
quotas without deleting deduplication history. v0.32 adds a separately configured
signed-task MCP caller with stable intent IDs and explicit single-task operations.
v0.33 adds an explicitly bound Human UI task bridge with independent UI credential,
role/group checks and durable preview/confirmation; chat and MCP do not acquire
Human authority. Next independent work can bound caller outboxes and payload bytes;
safe payload compaction remains separate and must preserve original deduplication.
History reconciliation, safe fork resolution and physical enrollment remain open.
Real product connections remain conditional on actual interface access.
Discovery is separate from authorization. A fresh or isolated Agent waits for
human approval or restores existing valid qualification; it never creates a group.

Real Agent access is not required for the first phases: use distinct synthetic
identities in real HTTP/TLS processes and verify network failures and permissions.
Use real product adapters only after the common transport and lifecycle are tested.

Each delivered behavior must update README, protocol/deployment guides, status,
and tests. Publish the corresponding GitHub version tag when releasing the merged
version; PR version bumps remain unreleased until then. A passed loopback test is not evidence of WAN
compatibility or a fully secured production mesh.
