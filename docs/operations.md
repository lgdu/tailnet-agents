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

v0.18.0 in this PR is unreleased. Merge and validate main before publishing it.
At release, verify `pyproject.toml`, MCP serverInfo and README/docs describe the
same version, run both CI modes and the mesh simulator, then create an annotated
GitHub tag on that exact release commit:

```bash
git tag -a v0.18.0 -m 'Tailnet Agents v0.18.0'
git push origin refs/tags/v0.18.0
```

Run these from the verified release commit on main; do not tag a different
checkout or move an existing published tag. Creating a PR is not publishing a release.
