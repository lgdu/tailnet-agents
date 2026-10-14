# Implementation status — v0.16

This file and README describe current behavior. Architecture is the target design;
its future requirements must not be read as implemented security guarantees.

| Area | Current state | Next work |
|---|---|---|
| Registry | Durable central directory | Distributed discovery/anti-entropy |
| Task transport | Echo, bearer authentication, in-memory deduplication | Durable state and real adapters |
| MCP | Local tools subset | Real client interoperability verification |
| Human UI | Configured people/roles, explicit groups, private scopes, paging/polling | Browser QA, durable outbox, sessions |
| Lifecycle | Local human member revocation and terminal dissolution | Signed network propagation |
| Agent identity | Optional Ed25519 keys, scoped grants and possession proofs | Human policy issuance and credential-revocation propagation |
| Verified directory | Library + HTTP/TLS admission, read token, durable signed revocation | Real LAN/tailnet trial, human policy issuance and mesh replication |
| Signed group policy | Durable signed snapshots, approved grant IDs, terminal dissolution, opt-in HTTP enforcement | UI integration, peer discovery and policy freshness |
| Policy replication | Periodic configured-peer HTTP/TLS pull and read-protected status | Multi-source reconciliation, credential revocations and discovery |
| Mesh | State simulator only | Cryptographic admission, LAN/seed/tailnet providers |
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
outages retain the last accepted policy; no freshness or immediate global
revocation guarantee is provided.

## Documentation maintenance rule

Every behavior change must update README's current feature table, the relevant
usage guide and this status file. Update architecture only for changed decisions;
label future requirements. Record protocol changes and migration consequences.
Do not append contradictory version notes as a substitute for rewriting current
instructions. Never commit credentials, generated keys or runtime databases.
