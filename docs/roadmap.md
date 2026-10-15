# Remaining work for the v0.26 development line

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

| Priority | Work | Acceptance evidence |
|---|---|---|
| P1 | Discovery operations and explicit runtime enrollment | Validate physical LAN/tailnet behavior, optional mDNS/peer enumeration and a separately authorized handoff from candidate to admitted runtime |
| P1 | Durable tasks | Executor persists request/result identity; caller recovery cannot silently execute uncertain side effects twice |
| P1 | Multi-source reconciliation and policy renewal UX | Compare sources beyond ordered failover, diagnose equivocation, renew signed authorization through explicit human-controlled administration |
| P2 | Message operations | Human UI integration, explicit blocked-outbox cancellation, retention/quotas, push and multi-store routing; any relay privacy claim requires E2E encryption |
| P2 | Presence operations | Multi-hop propagation and relayed UI preserve original deadlines, provenance and observed conflicts |
| P2 | Real adapters | Validate available OpenClaw, Codex, Claude Code, Qoder and Grok interfaces individually; model APIs and product Agents are distinct |
| P2 | Secure provisioning operations | Authenticated confidential transfer, credential retention/pruning, recovery and key rotation are verified without confusing installation with admission |
| P2 | Operational deployment | Actual household LAN and cross-region tailnet trials, certificate/key renewal, backups, rate limits and service packaging |
| P2 | Release readiness | Browser interaction QA, interoperability/security review, installation instructions and owner-selected open-source license |

Suggested order after the signed messaging stage: durable execution → real adapters and deployment trials.
Multi-source reconciliation and renewal UX remain independent administration work.
Discovery is separate from authorization. A fresh or isolated Agent waits for
human approval or restores existing valid qualification; it never creates a group.

Real Agent access is not required for the first phases: use distinct synthetic
identities in real HTTP/TLS processes and verify network failures and permissions.
Use real product adapters only after the common transport and lifecycle are tested.

Each delivered behavior must update README, protocol/deployment guides, status,
and tests. Publish the corresponding GitHub version tag when releasing the merged
version; PR version bumps remain unreleased until then. A passed loopback test is not evidence of WAN
compatibility or a fully secured production mesh.
