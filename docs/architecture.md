# ADR 001: Authorized, self-organizing agent groups

Status: accepted direction; implementation staged. This document supersedes
"destroy the group when its last online member disappears". Existing registry
mode remains usable. Mesh mode is not implemented on the network yet.

The [README architecture diagrams](../README.md#architecture) show the current
independent implementation paths and the planned integrated peer network.
Solid arrows describe implemented calls; dashed arrows describe future
integration. Discovery, authorization and product adapters remain distinct.

## Product contract

A human owns a trust domain and explicitly creates each logical group.
Authorized agents discover and resume those groups across LAN,
Tailscale, or configured seed links. Machines need not belong to Tailscale on a
LAN. Discovery grants no membership or execution authority. Agent products are
executors behind bridges, not trusted permission engines.

A group survives member downtime and restart. An empty online set means sleep,
not destruction. Membership credentials, identity and conversation history are
persistent; presence is temporary. Explicit authorized dissolution permanently
closes that group instance. A new instance has a new ID, even with the same name.

## Identities and durable data

| Object | Stable identity | Persistence |
|---|---|---|
| Trust domain | Owner public key / domain ID | Human-controlled trust configuration |
| Group instance | Random unique group ID bound to signed policy | Member nodes and approved storage |
| Agent | Independent public key / agent ID | Local private key, grants and group references |
| Human | Independent authenticated user principal | Trusted UI account/session provider |
| Runtime incarnation | Fresh boot identifier | Presence and diagnostics only |
| Message/task | Unique ID and origin | Relevant authorized storage/executor |

Human principals and agents are distinct. A restarted process retains the agent
identity and group instance, but starts a fresh runtime incarnation. IP addresses,
DNS names and display names are locators, not identity. Private keys never gossip.

## Components

1. Discovery providers: LAN mDNS/DNS-SD, tailnet peer probing, static seeds.
2. Group engine: verified membership claims, anti-entropy synchronization,
   local reachability observations, persistent checkpoints.
3. Authorization verifier: signed policies and scoped credentials, proof of
   private-key possession, expiry and revocation checks.
4. Task adapter: authenticated peer calls, durable idempotency and results.
5. Human gateway: trusted Web UI, human sessions, chat routing and approvals.
6. Conversation store: initially one designated node per group.

Discovery announcements contain protocol version, group ID, policy fingerprint
and an entry endpoint; do not expose detailed capabilities or private history
before authentication. Candidate addresses must be validated independently and
must never receive credentials before verified identity/channel setup.

LAN discovery is limited to interfaces selected by the user; guest Wi-Fi
isolation and blocked multicast require seeds. Tailnet probing uses only visible,
allowed candidate devices, with bounded concurrency and explicit ports. Merge
candidates from providers by verified identity, not address.

## Group state transitions

| Trigger | Result |
|---|---|
| Authorized member finds an existing group | Verify identity, policy and grant; synchronize |
| Authorized member has saved group but finds no peer | Resume same group provisionally; keep searching |
| Agent has no saved or authorized group | Remain unbound; show a join/create request to a human |
| Authorized human confirms creation | Create a new signed group instance and issue scoped invitations |
| Member disconnects | Locally mark unreachable; preserve member qualification |
| Member restarts | Restore identity/group; authenticate; synchronize; announce fresh incarnation |
| Member explicitly leaves | Publish signed leave with monotonically newer member revision |
| Owner authorizes rejoin after leave | Issue admission according to current policy |
| All members become unreachable | No active runtime, persistent group remains recoverable |
| Administrator dissolves | Publish durable signed terminal record; never revive this group ID |

Two disconnected replicas of the SAME group reconcile later. Different group
IDs do not automatically merge. If two humans independently confirm creation of two groups,
the UI displays both; an authorized human chooses consolidation in a later phase.
A network timeout never proves that a group does not exist.

## Replication and conflict rules

Replicate verified member claims, group policy and signed terminal records.
A member authors its own join/heartbeat/leave claims. Other members can report
reachability observations but cannot impersonate the subject or revoke it.
Higher valid revisions supersede lower revisions; contradictory claims at an
equal revision are equivocation and require explicit handling, not last-arrival
wins. Persist revision counters across restart. Detect cloned identity instances;
production fencing/credential rotation is required before accepting conflicting
writers. A group-level terminal dissolution record dominates membership updates.

The simulator models these ordering rules after verification. Production needs
standard cryptographic encoding, domain separation, policy/credential validation,
replay bounds and an admission check. A Python caller-supplied sender string is
NOT authentication. Gossip/SWIM alone is NOT the permission layer.

## Authorization and revocation

Preconfigure the owner's public key. Credentials bind domain, group scope,
subject key, role, allowed skills, expiry and issuer. Default members cannot
issue grants. New-group creation belongs to authorized HUMAN principals, not agent runtime
policy. Membership and recovery permissions are separate from creation.
Each task is authorized by the receiving bridge regardless of model output.

During partition, immediate global revocation is unavailable. Ordinary grants
have bounded validity; sensitive actions require sufficiently fresh authorization
confirmation and fail closed when unavailable. Revocation and dissolution must
remain durable longer than stale credentials can be accepted. Offline nodes may
not yet know dissolution; sensitive work cannot rely only on their stale copy.
Authority key recovery/rotation and credential renewal UX remain open decisions.

## Human interaction

The human UI shows groups, verified members, local reachability, capabilities,
tasks and pending approvals. Do not display inferred reachability as global fact.
Initially use one trusted human gateway; accepting an arbitrary member's Web UI
as an administrator entry is not safe. Later alternate entry points need explicit
trust registration and signed human authorization semantics.

Group chat supports explicit mentions. Ordinary messages go to a designated
moderator agent, not every agent. Agent messages do not trigger automatic peer
replies by default. Explicit discussion rounds bound participants and depth.
Messages include conversation ID, message ID, sender principal, reply reference,
message kind and provenance. Chat, task submission and approval are distinct.

Private chat ACLs include only the human and target agent. Initial trusted
storage can enforce those ACLs; confidentiality from storage or relay operators
requires end-to-end encryption before making that promise. Do not advertise E2E
privacy based only on UI filtering. No group administrator implicit read access.

Conversation history uses a designated store initially. Its downtime does not
stop discovery or peer tasks, but history/delivery can be unavailable. A UI outbox
holds unsent messages and shows pending status. No false "delivered" acknowledgment.
Group dissolution does not imply irreversible deletion of history; retention is
an explicit separate human action.

## Tasks

The caller chooses an executor. Deduplication lives on that executor and must
be durable before real side effects. Do not automatically migrate an uncertain
task to another executor. Model permissions and network permissions are both
necessary; network membership never grants filesystem or secret access.

## Implementation stages

- v0.4: central directory, Echo bridges and MCP tools (existing).
- v0.5: design contract and deterministic mesh state simulator.
- v0.6–v0.10: local human UI, roles, explicit groups and lifecycle.
- v0.11: optional Agent signature/grant primitives, not integrated with mesh.
- v0.12: in-process verified directory admission and durable signed revocation;
  existing network services remain unchanged.
- v0.13: separate loopback HTTP admission and signed registration client;
  no cross-machine mesh or UI policy integration.
- v0.14: direct TLS admission transport with client CA/hostname validation;
  real LAN/tailnet trials and signed group-policy integration remain pending.
- Next: cryptographic identity/admission implementation and network mesh transport.
- Next: trusted human gateway with simulated chat participants and durable history.
- Then: validated agent adapters, durable tasks and real LAN/tailnet trials.

Do not replace working registry mode until mesh fault and authorization tests pass.

## Acceptance scenarios

Restart retains identity and original group. Creator departure does not dissolve.
Partition recovery converges membership without granting extra permissions.
Foreign-domain/group claims and unauthorized admission are rejected. Stale leave
or join messages cannot roll state back. All-node downtime is recoverable from
saved state. Authorized dissolution is terminal once learned. Chat does not loop;
private history is isolated; uncertain tasks are not silently executed twice.

## ADR amendment: human-confirmed group creation

New logical groups MUST be created by a human action with a concrete name,
new unique ID, trust policy, selected initial members and history policy.
Agent runtime cannot silently invent a group ID, clone a group from a display
name, or expand membership when discovery times out. An agent can suggest
creation/join and display candidates; an authorized human makes the decision.

Previously authorized agents may automatically rejoin or resume a saved group
instance, using the SAME group ID and still-valid qualification. That is recovery,
not new creation. Show "restoring original group" or "waiting for peers" in the
human interface. No timeout may turn restoration into new-group creation.
If credential renewal, policy freshness or dissolution status cannot be established,
apply the authorization rules above; do not silently bypass them.

The current chat demo requires human creation for fresh groups; existing legacy
group history is preserved on upgrade. The simulator receives its policy from
the test harness. Neither currently creates dynamic
network groups. v0.9 implements a local human group-creation form and database membership checks.
Its signed approval flow and mesh propagation remain to be implemented. The old automatic-creation proposal is superseded.

Current implementation boundaries are tracked in [status.md](status.md); signed group
policy and lifecycle replication remain future work even though grant primitives exist.
