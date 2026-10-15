# Registry operations (v0.4)

## Durable directory

```bash
python3 -m tailnet_agents.registry --database state/registry.sqlite3
```

This is the CLI default. `--database :memory:` runs an ephemeral development
instance. Run **one registry process per database**; this prototype is not an
HA cluster. WAL is enabled for atomic transactions. Keep the state directory
on local persistent storage. SQLite database files are git-ignored, and new
database files are restricted to mode 0600 on POSIX.

Tokens remain in the process environment; they are never stored in SQLite.
The database contains agent IDs, owner labels, endpoints, skills and lease
expiry. Protect the directory as private infrastructure metadata.

On restart, registrations and ownership survive, while all old leases are
invalidated. Bridges renew them normally (typically within 20 seconds once
reachable). No endpoint is declared online solely from a pre-restart lease.
Lease timestamps use wall-clock time; synchronize the registry host clock.
Expired IDs remain reserved to the same owner until explicit deregistration.
Rotating a node token while retaining its owner label preserves ownership.

## Status

```bash
python3 -m tailnet_agents.cli --registry "$REGISTRY_URL" status
```

Returns `registered`, `online` and `stale` counts. It requires the normal
registry token. Online means a valid lease, not a verified healthy agent.
`/healthz` only reports process liveness. No node names or tokens appear in
aggregate status.

## Deregister a node

Stop its bridge first, otherwise its renewal will register it again. Use
that node owner's registry token:

```bash
curl -X DELETE "$REGISTRY_URL/v1/agents/node-b-echo" \
  -H "Authorization: Bearer $TAILNET_REGISTRY_TOKEN"
```

Explicit deletion releases the agent ID. Requests from other owners return
404, as do unknown IDs. Revoking a node's token denies future requests but
its last registration can remain discoverable until its TTL expires.

## Consistent backup

Use SQLite's backup API while the service is running. Do not copy only the
main database file while WAL writes are active. Example from the repository:

```bash
python3 - <<'PY'
import sqlite3
from pathlib import Path
backup = Path('state/registry-backup.sqlite3')
with sqlite3.connect('state/registry.sqlite3') as source:
    with sqlite3.connect(backup) as destination:
        source.backup(destination)
backup.chmod(0o600)
PY
```

To restore, stop the registry, preserve its current state directory as a
rollback copy, and place a consistent backup in a **new** state directory.
Start with `--database` pointing at the restored file. Reuse the corresponding
owner labels and provide current tokens through the environment. Restored
leases are invalidated on startup and bridges must renew.

## Current boundaries

- Registry: durable metadata and ownership; one local SQLite database.
- Bridge: task history and idempotency still in memory, lost on restart.
- MCP: configured peers only, sequential calls and fixed network timeouts.
- Runtime: Echo only; real tailnet deployment and product interoperability untested.
- No role-based visibility, quotas, metrics exporter or HA failover yet.

VerifiedDirectory uses an additional, separate database with pinned authority and
credential records. Back up it consistently using SQLite backup, and protect it
as credential material. It is currently a library API; ordinary registry startup
does not enable its checks. See [verified-directory](verified-directory.md).

## Multiple Agents on one host

In verified mode, provision a separate identity file and scoped grant for each
simulated Agent, for example `state/agent-a/agent.pem` and
`state/agent-b/agent.pem`, both referencing the same existing human-created group.
Explicitly approve each grant with the human signer and apply or confirm delivery
of the resulting policy. Sharing a machine/IP/Tailscale device never grants the
other Agent membership. Use separate listener ports such as 8901 and 8902, or an
explicitly configured routing gateway. Display names may coincide.

Invoke `tailnet-verified-register` for each Agent with its own `--agent-key`,
`--grant-file` and `--record-file`, and the existing directory's `--url` and
`--audience`. See [verified admission](admission-http.md) for the full command.
On restart, reload each original key/grant and group reference; never regenerate
the keys as a boot action. Directory restart clears leases and requires each
Agent to prove possession again. Reusing a key renews that one identity rather
than adding a second Agent. Removing or revoking one subject/credential leaves
other authorized subjects on the same host intact. The UI's Echo actors remain
simulated; automatic real product enrollment is not implemented.

## Policy-age operations and migration

The separate verified service's policy mode now bounds active signed age to 300
seconds by default, persisting the limit in SQLite. Back up before upgrading
v0.17 state. Prepare a fresh human-authorized revision if the stored snapshot is
expired. Retain its original group ID and Agent keys. Do not recreate groups,
delete revocations or downgrade the executable to restore availability.
A smaller `--policy-max-age` is allowed; increasing a saved limit is rejected.
Monitor `/v1/policy-sync` policy expiry rather than liveness or historical sync
success, and keep verifier clocks synchronized. See [policy sync](policy-sync.md)
for independently authenticated primary/backup sources and CA configuration.

## Version and GitHub tag

Publish only a validated release commit on main. Verify `pyproject.toml`, MCP
serverInfo and README/docs describe the same version, run both CI modes and the
mesh simulator, then create an annotated
GitHub tag on that exact release commit. Read the new version from the manifest:

```bash
tailnet_release_version="$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"
git tag -a "v${tailnet_release_version}" -m "Tailnet Agents v${tailnet_release_version}"
git push origin "refs/tags/v${tailnet_release_version}"
```

Run these from the verified release commit on main; do not tag a different
checkout or move an existing published tag. Creating a PR is not publishing a release.
Create the GitHub Release from that same tag and keep prototype versions marked
as prereleases. Release notes must include verification results, migration steps
and remaining implementation/validation limits.

## Candidate-discovery operations

Discovery remains off unless an existing approved simulation key and explicit
advertised endpoint are configured. Enable LAN announcements only on a selected
IPv4 interface, and use HTTPS/CA-pinned seeds across LAN or Tailscale. Keep the
discovery seed list separate from credential-bearing policy-source configuration.
Never copy read tokens into a seed file or promote a discovered endpoint into a
trusted source automatically. See [discovery](discovery.md) for disclosure,
duration/size limits, conflict output and actual-network validation limits.

Restart reuses the same private key, group ID and database; the key is never
generated by service startup. Policy expiry/removal/revocation can suppress
announcements without deleting the group. Point the scanner's required
`--directory-database` at the existing local policy-mode database maintained by
administration/sync. The scanner reads policy, signed revocations and the persisted
age bound without resetting leases; do not copy a static policy file as a substitute.
It re-reads before output and fails for retry if the policy changed. LAN receiving
requires Linux IP_PKTINFO and a primary local IPv4 address; unsupported setups
must use seeds. Same-interface multicast flooding can still congest queues.

## Human signing gateway

v0.20 adds an opt-in loopback UI signer. Keep the existing owner private key on
the trusted human machine, never on a directory replica. Configure the private
key, its public pin and one human admin explicitly; protect the private key with
mode 0600 or stricter and retain that configuration across restart. Do not expose
this signer through a reverse proxy or Tailscale Serve. Existing local-only groups
remain local. There is no key generation, identity replacement, group conversion
or automatic renewal on startup.

Back up the UI database consistently: it now contains signed policies, pinned
authority, retired grant IDs, request deduplication and audit. Protect the owner
key separately; never commit either. Restoring a stale backup can lose accepted
revisions/retirements. Export current signed policies externally and do not run
independent signers from diverged backups. This is not rollback-proof storage.

New approval/removal/renewal/dissolution affects remote directories only after a
human explicitly applies the latest exported policy or confirms delivery to a
configured recipient. Recheck receiver revision
and freshness via its existing authenticated routes; reads of the UI do not
renew or deliver anything. Scope previews do not replace the receiver's learned
revocation and possession checks. See [human policy signing](human-policy.md).

v0.21 adds optional `--policy-targets-file` configuration on the signing UI.
It refers only to already-created signed groups and fixed recipients; it never
creates groups or sends on startup. Keep read tokens in the named environment
variables and CA files locally. Preview, signing and UI refresh perform no remote
I/O. Confirm the displayed URL, revision and policy hash before delivery.

Backups now also contain delivery intents and historical acknowledgments. An
unknown attempt may have reached the directory; retry the same request explicitly
to read it back. A completed acknowledgment retains its original timestamp and
does not establish current freshness. If local policy changed during delivery,
the recipient may hold the older revision even when the UI reports conflict;
preview and explicitly deliver the latest revision. There is no background retry
or atomic multi-recipient revocation. See [policy delivery](policy-delivery.md).

## Human-issued credentials and recipient files (v0.22)

Back up the UI database consistently with its original owner key/public pin and
human identity. It now records public issuance claims, scope, fixed expiry,
request deduplication and credential hashes. Complete signed grants are not
stored, but the trusted owner signer can reconstruct valid records only on an
explicit issue/recovery POST. History and startup never export credentials.
Treat metadata/backups as private; audit is not tamper-proof or rollback-resistant.

The browser cannot set restrictive permissions on Downloads files. Use private
storage and an existing authenticated confidential channel to the intended Agent.
`tailnet-grant-install` takes the token through stdin, validates the original
Agent key, owner/group and expiry, then exclusively creates a mode-0600 file.
It refuses existing files/symlinks and removes a failed partial write. Use trusted
parent directories and independently protect/delete downloaded and transferred
copies; there is no automatic transfer or secure-deletion guarantee.

Each Agent on a host uses its own key/grant directory. Installation does not
approve membership, renew signed policy or establish a live registration. Approve
the credential separately and explicitly deliver the new policy before proof-based
admission. Expiry/retirement does not overwrite installed state or issue a new
credential. See [credential issuance](credential-issuance.md).

## Simulation runtime state and presence (v0.23, unreleased)

Keep each Agent's original key/grant, owner pin and human-created group ID, plus
its own private `--state` SQLite file. Runtime state pins identity/group and
persists generation/sequence; startup advances generation without generating an
identity or group. POSIX ownership/private-file checks and cooperative exclusive
locking apply. Separate same-host Agents use independent keys and state files.

Back up both runtime and directory databases consistently. Directory ordering
survives restart, while old live leases are invalidated. Stale runtime backups,
lost state and cloned keys can conflict with accepted generations. Preserve the
original files and diagnose rather than resetting counters/deleting state or
creating a new group; automatic counter repair/strong distributed fencing is not
implemented. Local operators and parent directories remain trusted.

Signed-runtime enrollment is per-identity forward migration: successful opt-in
blocks legacy registration for that subject. Use the runtime/extended SDK on
subsequent restarts. SIGINT/SIGTERM attempts signed offline; crash/network failure
ages out the bounded lease. Member removal/dissolution and authorization expiry
still require their existing human policy workflow and fail closed independently.

`tailnet-presence` reads authenticated pages from a fixed configured directory,
checks signatures and bounds, and distinguishes online/offline/expired/unauthorized.
Only that directory's signed-runtime subjects appear. Pages and online status
are point-in-time observations, not executor health or globally replicated state.
The local Echo UI remains separate. See [runtime operations](agent-runtime.md)
for commands, TLS, lease timing, retries, migration and backup limits.
