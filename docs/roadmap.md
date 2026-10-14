# Remaining work after v0.17

The verified directory can persist and exchange signed policy and credential
revocations between configured peers. The human UI is a separate local simulated
application. This is not yet a complete heterogeneous Agent collaboration network.

| Priority | Work | Acceptance evidence |
|---|---|---|
| P0 | Policy freshness and source failover | A disconnected or stale source cannot silently preserve admission forever; recovery does not weaken authorization |
| P0 | LAN and configured-seed discovery | Nodes locate peers without granting membership; LAN broadcasts never trigger credential leakage or silent group creation |
| P0 | Human UI signing workflow | Human creation/approval/removal/dissolution produces signed network policy, with clear audit and safe owner-key handling |
| P1 | Signed presence and stable Agent runtime | Authorized restart restores the original identity/group; leases, runtime incarnations and offline display converge |
| P1 | Cross-node group/direct messages | Authenticated identities, group scopes, recipient privacy, durable outbox, deduplication and reconnect catch-up are verified across nodes |
| P1 | Durable tasks | Executor persists request/result identity; caller recovery cannot silently execute uncertain side effects twice |
| P1 | Multi-source synchronization | Partitions, conflicting revisions, source replacement and relayed records have explicit, tested recovery behavior |
| P2 | Real adapters | Validate available OpenClaw, Codex, Claude Code, Qoder and Grok interfaces individually; model APIs and product Agents are distinct |
| P2 | Operational deployment | Actual household LAN and cross-region tailnet trials, certificate/key renewal, backups, rate limits and service packaging |
| P2 | Release readiness | Browser interaction QA, interoperability/security review, installation instructions and owner-selected open-source license |

Suggested order: freshness/discovery → human-controlled enrollment → presence
and messages → durable execution → real adapters and deployment trials.
Discovery is separate from authorization. A fresh or isolated Agent waits for
human approval or restores existing valid qualification; it never creates a group.

Real Agent access is not required for the first phases: use distinct synthetic
identities in real HTTP/TLS processes and verify network failures and permissions.
Use real product adapters only after the common transport and lifecycle are tested.

Each delivered behavior must update README, protocol/deployment guides, status,
tests and the GitHub version tag. A passed loopback test is not evidence of WAN
compatibility or a fully secured production mesh.
