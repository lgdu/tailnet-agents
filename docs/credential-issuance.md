# Human credential issuance and installation — v0.22 (unreleased)

The optional trusted loopback signer can issue a scoped grant to an existing
simulation Agent public key after explicit human preview and confirmation.
Issuance, installing the grant, approving membership, delivering policy and
proving possession are separate steps. None creates an Agent identity or group
automatically. Real product enrollment remains unimplemented.

## Prepare and review an existing identity

Use the original owner key/public pin, human admin and UI database from
[human policy signing](human-policy.md). Explicitly create the signed group first.
The Agent retains its own private key; only its public key goes into the UI.
Never provision the owner authority private key to an Agent. The issuer rejects
using the owner public key as the Agent subject.

For an already provisioned simulation Agent, obtain the public key locally:

```bash
python3 - <<'PY'
from tailnet_agents.identity import encode, load_identity, public_bytes
key = load_identity('state/agent-a/agent.pem')
print(encode(public_bytes(key.public_key())))
PY
```

Use a distinct persistent key and grant location for every Agent on the same
machine. Shared LAN IP, hostname, Tailscale device or display name does not merge
subjects. Do not generate replacement keys at startup or copy one key into every
Agent's state directory. This workflow accepts existing keys; initial key creation
remains an explicit human provisioning action described in [identity](identity.md).

Open **管理群组 → 为已有 Agent 签发凭证**. Enter the canonical raw Ed25519
base64url public key, select the full permission set and choose a 1–86400 second
lifetime. `join` is required; the other permissions are opt-in. Permission names
do not establish a functioning chat/task runtime or bypass its authorization.
Admission also needs at least ten seconds of remaining grant/policy lifetime
for a directory lease.

Select **预览身份、权限与固定期限**. Check the public-key fingerprint against the
intended Agent through a trusted channel, the original group/owner, complete scope
and displayed absolute expiry. Preview changes no membership, issues nothing and
contacts no recipient. Editing the draft invalidates consent; delayed responses
for older drafts cannot restore it.

## Explicit issuance and recovery

Select **确认仅签发此凭证** within the preview window (up to 60 seconds, capped
by the grant's own expiry). The grant's issued/not-before/expiry times are fixed
at preview; waiting or retrying does not extend them. A changed policy revision
or snapshot hash requires a new preview for a new issuance.

The server transaction records the exact request, public claims, credential hash
and issuance time with a stable request ID. It stores no complete signed grant
or Agent private key. Issuance leaves the signed policy and its revision unchanged.
The response containing the credential is admin/creator-only and `no-store`.
It is held in browser memory, not URL, localStorage or sessionStorage; it enters
the existing approval text field only after an explicit approval-preview action.
Logout/group changes discard the in-memory copy. Downloaded files are separate.

An identical retry reconstructs the same deterministic Ed25519 signature from
the original stored claims: same credential ID, bytes and expiry, not a renewal.
Changed consent with the same request ID conflicts. Acknowledged issuance followed
by a page-read failure retries local reads only; download stays disabled until
that read succeeds. After reload/restart, history lists public metadata without
credentials; **明确取回这份原凭证** explicitly recovers that existing request.
Startup and history reads do not reconstruct or export grants.

Expired/not-yet-valid grants cannot be retrieved. Local membership removal retires
its approved credential IDs and blocks their retrieval; issue a new grant
explicitly if readmission is intended. Dissolution blocks new issuance and
retrieval but preserves history. A completed request can recover after unrelated
policy revision changes, with its original scope and timestamps. Remote revocations
are not monitored here; retrieving a copy cannot undo a learned revocation.

## Download, transfer and install for one Agent

Select **下载此 Agent 的凭证**. Browser download permissions depend on the OS;
the web page cannot promise mode 0600 for the Downloads copy. Keep it private,
avoid shared folders and transfer only to the intended Agent through an existing
authenticated confidential channel such as SSH. LAN/Tailscale reachability alone
does not authenticate the destination or make every file copy safe. There is no
automatic URL-based upload, clipboard write or remote provisioning service.

On the intended Agent machine, install `.[identity]` and run:

```bash
tailnet-grant-install \
  --agent-key state/agent-a/agent.pem \
  --authority-public-key state/owner.pub \
  --group-id YOUR-EXISTING-GROUP-ID \
  --output state/agent-a/grant.jwt < PRIVATE-TRANSFERRED-FILE.grant
```

`python3 -m tailnet_agents.grant_install` is equivalent. The credential comes
through stdin, not command-line arguments or logs. The installer bounds input to
16 KiB, verifies owner signature, exact group, expiry and the subject against
this Agent's existing key before writing. It creates a new file with mode 0600,
flushes/fsyncs it and never overwrites a file or symlink. Write failure removes
the partial output. It prints only identity/group/credential ID/expiry metadata.
Use a trusted local state directory; parent directories and existing Agent keys
are operator-controlled. There is no directory fsync, encrypted-at-rest storage,
secure deletion guarantee or distributed installation transaction.

An existing output requires an explicit operator choice of a new path and later
configuration update; expiry never silently overwrites or renews that file.
Safely manage the original downloaded/transferred copy too; installation does
not delete it or change its permissions. A successful install proves validation
of that artifact, not admission or live authorization.

## Separately approve and join

Choose **预览此凭证的成员审批** to pass the in-memory grant to the existing
membership preview. Inspect the proposed *complete* membership scope, then confirm
approval separately. Download/issuance does not click approval or deliver policy.
Export/apply or [explicitly deliver](policy-delivery.md) the new signed snapshot.

The simulation client can then use its own original key and installed grant with
`tailnet-verified-register`. The directory independently checks current policy,
grant ID/scope, signed age, learned revocations and a fresh possession proof.
Installing or approving alone cannot register it. Repeat independently for Agent B
on the same host; separate listeners use different ports or an explicitly
configured gateway. Restart restores each original identity/group and requires
each Agent to renew its own lease.

## Validation and limits

Tests exercise actual UI HTTP issuance, unchanged policy, separate approval and
delivery, two same-host simulation identities, receiver possession proofs,
concurrent/lost-response retries, restart, expiry, role/scope rejection, private
file creation, wrong-recipient refusal and the real stdin installer CLI.
Chromium covers edited-preview races, explicit issuance/download, lost response
recovery and the existing delayed policy-export and delivery regressions.

The UI database contains plaintext public grant claims, scope and retry metadata;
the owner signer can reconstruct valid issued credentials. This is not storage
confidential from the operator, tamper-proof audit or backup rollback protection.
Preserve the database, original owner key/public pin and human principal together.
Local retention/pruning, owner rotation/recovery, remote human sessions, automatic
secure transfer, live credential-revocation monitoring and real Agent adapters
remain future work. Do not expose the human signer through a reverse proxy.
