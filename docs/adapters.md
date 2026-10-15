# Reference adapter contracts and inspection (v0.29)

Only synthetic Echo is implemented. An existing human-approved executor retains
its own original key, group and database; discovery, inventory and probing never
create groups, credentials, membership or executor identities. Multiple Agents
on the same LAN/Tailscale host keep independent public keys and approvals.

v0.31 [task archives/quotas](task-history.md) changes the executor's storage marker
to `echo-v1/task-history-v1` to prevent unsafe downgrade. The reference adapter and
advertised contract remain `echo-v1`; inspection neither archives nor frees quota.

## Offline inventory

```bash
tailnet-adapters catalog
# Without installing an entry point:
python3 -m tailnet_agents.adapters catalog
```

This command needs only the core installation. It emits JSON without scanning
installed binaries, reading product credentials, launching processes or contacting
any network. The implementation inventory is:

| Target | Implemented interface | Validation |
|---|---|---|
| Simulation | Echo reference, signed durable task service | Synthetic HTTP/TLS tests |
| OpenClaw | None | Not run |
| Codex product Agent | None | Not run |
| Claude Code | None | Not run |
| Qoder | None | Not run |
| Grok Agent | None | Not run |
| Grok model API | None; separate model API target | Not run |

An installed executable, an MCP client configuration or model API access is not
proof of an inbound product worker. No undocumented product flags are assumed.

## Reference contract

The strict v1 descriptor embeds exactly these fields:

| Field | Echo value |
|---|---|
| `version` | Integer `1` |
| `adapter_id` / `product` | `echo-v1` / `simulation` |
| `task_kind` / `permission` | `echo` / `task.echo` |
| `input_max_bytes` / `output_max_bytes` | `2048` / `2048`, UTF-8 text bytes |
| `execution` / `side_effects` | `synchronous` / `none` |
| `restart` | `running-to-uncertain` |
| `automatic_retry` | Boolean `false` |

Unknown fields, types, task kinds, products or broader permissions fail validation;
there is no generic plugin loader. The default executor now uses `EchoAdapter`,
retaining the original `echo-v1` SQLite binding and signed task format. Existing
in-process `adapter=` test callbacks remain test hooks; probes reject them rather
than running describe hooks or claiming they are verified Echo/product adapters.
Input/output and [durable task recovery](durable-tasks.md) rules remain enforced.
A future semantic change needs a new contract/adapter version and an explicit
migration; silently replacing an existing executor is not supported.

The displayed `contract_hash` is SHA-256 of UTF-8 `json.dumps(contract,
sort_keys=True, separators=(',', ':'), allow_nan=False)` with default ASCII escaping.
It identifies the accepted contract, not executable provenance or a software build.

## Explicit metadata probe

Install `.[identity]`, start the existing [signed Echo service](durable-tasks.md)
with `--tasks` and its original approved key/grant, and provide its directory read
credential securely through `TAILNET_VERIFIED_READ_TOKEN`. Supply **public** pins:

```bash
tailnet-adapters probe \
  --url https://node.YOUR-TAILNET.ts.net:8771 \
  --authority-public-key state/owner.pub \
  --executor-public-key state/executor.pub \
  --group-id YOUR-EXISTING-GROUP-ID \
  --audience directory-a \
  --ca-cert state/ca.pem
```

LAN HTTPS origins work identically; certificate SAN/hostname/IP validation is
mandatory. Only loopback development may use HTTP. `--token-env` selects another
existing read credential environment name; no secret is accepted as a CLI value.
No private key, caller grant or writable caller state is needed. The CLI contacts
only this explicit origin, refuses redirects and disables ambient HTTP proxies
for credential-bearing directory calls. It never follows discovered/advertised
Agent endpoints or tries alternative products/sources automatically.

The client generates a fresh 256-bit nonce and sends one read-authenticated
`POST /v1/task-adapter-probe` containing only `{nonce}`. This POST requests metadata;
it creates no task/admission challenges or database rows. The endpoint exists
only with an explicit task executor. The executor checks its own current grant,
policy, approved ID and learned revocations, then signs a descriptor binding:

- Original owner/group/audience/executor, validated request origin and nonce.
- Exact Echo contract and signed issue/expiry timestamps.
- Expiry at most 15 seconds after issue, additionally capped by its current
  grant and this directory's policy deadline; fractional deadlines are preserved.

The client verifies the pinned executor signature, expected context/source/nonce,
strict contract and timestamps **after** the response is read. Expired descriptors,
more than five seconds of future issue time, unknown claims and replay under a
fresh nonce are rejected. Output omits the raw JWS, credentials, grants and private
keys. It reports `compatible_metadata`, source/identity, check time, signed deadline,
contract/hash, `execution: not_attempted`, `execution_authorization: not_checked`
and `product_integration: simulation_only`. Errors are fixed diagnostics without
upstream response bodies or credential values.

This is a historical metadata/possession observation from a pinned executor.
Owner/group bindings are its signed assertions; the response does not carry
owner-signed policy/grant evidence for independent admission verification. It does
not establish the caller's execution rights, future reachability, product health,
exclusive endpoint ownership or independent attestation of executable behavior.
A revocation after the snapshot can invalidate actual operations immediately.
Actual submit/query still needs current `task.echo`, fresh operation-bound proof,
approved credential IDs and both principals' authorization. Read credentials and
metadata cannot replace those checks. Probing never submits, resumes, retries,
cancels or resolves queued/running/uncertain work.

## Before adding a real product

Keep each future integration behind a separate explicit adapter selection and
permission model. Validate the actual documented interface/version and distinguish
outbound MCP tools, inbound execution and model APIs. Specify workspace/tool/secret
access, user approval needs, input/output bounds, error redaction, cancellation,
timeouts and process ownership before allowing external side effects. Persist the
original executor/contract binding and preserve durable intent/running/result
boundaries; uncertain work must not be automatically replayed or migrated.

Real product access is currently unavailable. No binary installation, login,
workspace access or external API call is performed in this release. Human UI/MCP
integration, generic adapter loading, real task kinds, stopping running work, verified uncertainty
resolution, product sessions and physical LAN/Tailscale trials remain open.
v0.30 adds separate [pre-execution task cancellation and advisory local notes](task-operations.md);
metadata probing itself never invokes either operation.

## Verification

Five core checks exercise UTF-8 limits, strict contract types, immutable returned
metadata and an offline catalog subprocess without site packages. Twenty-five
identity checks use actual loopback HTTP/TLS and synthetic identities for nonce,
signature/context/source failures, independent expiry caps, credential scope,
revocation/dissolution, no execution/state writes, same-host executors/restart,
TLS trust/hostname, proxy/redirect isolation and the CLI. Three existing Chromium
regressions continue to cover the separate Human UI workflows.
