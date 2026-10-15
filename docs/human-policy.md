# Human policy signing — v0.22

The local UI can optionally act as a trusted human signing gateway. An explicitly
configured admin can create a new signed group, preview and approve pre-issued
Agent grants, remove identities, renew policy and dissolve the group. The UI's
group ID is the signed network group ID. This does not connect real Agents or
turn the Echo chat participants into authorized network members.

## Configure the existing authority

Install `.[identity]`. Keep the gateway on the human administrator's trusted
machine, bound to loopback. Never expose it through Serve, a reverse proxy or a
public port. Tokens grant access to the signer, so protect them like signing
authority. Sessions, hardware-backed keys and owner recovery/rotation are not
implemented. Owner private keys are plaintext PEM in process memory and on disk.

Use an existing Ed25519 owner key and its separately provisioned public pin from
[identity setup](identity.md). Startup does not generate either file or a group.
The private key must be a regular file owned by the process user, mode 0600 or
stricter; symlinks are rejected. Secure loading requires POSIX file checks.

```bash
python3 -m tailnet_agents.ui \
  --database state/chat.sqlite3 \
  --policy-owner-key state/owner.pem \
  --policy-owner-public-key state/owner.pub \
  --policy-admin demo-owner
```

Set `TAILNET_UI_TOKEN` securely as in [UI setup](ui.md). With `TAILNET_UI_USERS`,
select one configured human ID with the admin role as `--policy-admin` instead.
All three policy flags must be provided together. Other admins may still manage
their local chat groups but cannot sign with this authority or export its policies.
No HTTP route accepts or returns a private key or changes signer configuration.

The database pins both the owner public identity and human administrator.
Subsequent starts require the same key, pin, principal and admin role. Omitting
signing flags or changing the persisted identity fails startup, preserving state.
Startup verifies saved signed policies against their original local group state;
it never re-signs or renews them. Existing local-only groups remain local-only.
There is no implicit conversion or reassignment of their IDs.

## Explicit human workflow

1. Log in as the configured policy admin. Open **创建群组**, choose the name and
   human members, and explicitly select **创建所有者签名策略**. Confirm creation.
   This creates one new group ID with an empty Agent member map. Human chat
   membership and Agent signing permissions remain separate.
2. Open **管理群组** and copy the exact signed group ID. Prepare a scoped grant
   for an existing simulation public key through the separate
   [human credential issuance workflow](credential-issuance.md), or the library
   example in [group policy](group-policy.md). Review explicit scope and fixed
   lifetime, confirm issuance and install for that Agent separately. Issuance does
   not approve membership, renew policy or register an Agent.
3. Paste that grant, select **校验并预览授权范围**, and inspect the verified identity,
   grant permissions/expiry and the complete proposed member permissions. Only
   **确认批准** changes the signed policy. Preview checks owner signature, group,
   lifetime and local retired IDs; it cannot know unsynchronized remote revocations.
4. Download the current `.policy` file. Compare the displayed public pin with
   directory configuration, then explicitly deliver the file to the configured
   directory through its authenticated policy route or startup `--policy-file`.
   Alternatively, explicitly configure and preview/confirm [recipient delivery](policy-delivery.md).
   Signing alone does not contact a directory, discovered URL or policy source.
5. Use **明确续期策略** before the directory's signed-age deadline. This explicitly
   signs a higher revision without changing members, even if the old policy has
   expired. Reading, polling, restart and discovery cannot renew policy. Grant
   lifetime and the directory's learned revocations still apply independently.
6. Removing a signed identity removes all its approved grant IDs. Those IDs are
   retained locally as retired and cannot be approved again in this UI; readmission
   requires a newly issued grant. Other credentials for a member merge up to the
   existing eight-ID limit and union the explicitly previewed permissions. To
   reduce a member's complete scope, remove it and approve a new restricted grant.
7. Enter the exact group name to dissolve. Local read-only history, a terminal
   signed policy and its audit record commit together. Download/apply or explicitly deliver that terminal
   policy too. Repeated dissolution does not sign again; the group cannot reopen.

For a running, already pinned directory, explicit application uses the existing
client; HTTPS and CA/hostname validation are mandatory outside loopback:

```python
import os
from pathlib import Path
from tailnet_agents.client import Client

# This origin is configured by the human, never copied from discovery automatically.
directory = Client('http://127.0.0.1:8771', os.environ['TAILNET_VERIFIED_READ_TOKEN'])
directory.request('/v1/policies', {'policy': Path('state/current.policy').read_text().strip()})
```

Save the downloaded policy as `state/current.policy` before this example. For a
new directory use the exact group ID shown in the UI. Approval in the UI alone
does not change an existing directory: until explicit delivery it retains its
previous policy and signed deadline. Normal configured-peer replication can
then distribute accepted snapshots over LAN or Tailscale. Possession of a signed
policy or grant still does not register an Agent; admission requires a fresh
audience/record-bound possession proof.

## Atomic changes, retries and audit

Creation retains the existing `(creator, request_id)` deduplication, including
whether signing was selected. Approval/removal/renewal require `expected_revision`
and a stable `request_id`. A stale revision or changed retry payload returns 409.
An identical committed retry returns its original acknowledgment without signing
again, even if a later operation already advanced the policy. Dissolved groups
deny policy operations including old retries; repeated dissolution remains idempotent. Signature, size/schema, clock rollback or database errors
cannot partially commit a policy, retired ID, audit record or local dissolution.

On an uncertain network response, the page keeps the exact request and blocks
other policy mutations/group switching until retry or logout. A browser reload
or logout loses this page-local retry state: inspect current revision/audit before
submitting another operation. There is no durable browser outbox. Creation
likewise retains its key only while the dialog remains open.

Policy mutations and management refreshes invalidate the previous downloadable
snapshot. Download stays disabled until the latest read completes; successful
signing alone does not display a download-ready message. The refreshed revision
must reach the mutation's acknowledged revision, and older overlapping refreshes
cannot overwrite a newer result. If signing was acknowledged but the following
read fails, the page keeps exports disabled and retries only reads. If the signing
response itself was lost, it retries the original idempotent mutation first.
Dissolution likewise blocks downloads until its terminal snapshot is read.

Policy audit records include actor, operation, subject, revision, policy hash
and time. The policy, requests and audit commit in the same SQLite transaction.
The original grant is neither stored in SQLite nor returned in exports; retry
deduplication stores its hash. Audit is local plaintext data, not a tamper-proof
log against the database operator. Protect consistent backups; restoring an old
backup may lose accepted revisions and retired IDs. Keep latest signed policy
externally and do not run independent writers from divergent backups.

## Validation and remaining scope

Tests cover real HTTP UI and directory admission, role/owner/group boundaries,
manual delivery, no automatic registration, grant preview, retries, concurrent
revision conflicts, signature failure rollback, grant limits, removal/readmission,
clock rollback/explicit renewal, terminal dissolution, migration, safe key loading
and real service restarts. A Chromium functional run also exercises creation,
preview, approval, download, lost-response retry, removal and dissolution. Deferred
policy responses test that approval/renewal/removal/dissolution cannot download
older snapshots; failed reads keep exports disabled, and a read-only retry restores
an export matching the current server policy without another POST.

The optional reproducible browser check lives in `scripts/check_policy_ui.py`.
Install Playwright in a development environment, use an existing Chromium binary
(or install Chromium through Playwright), and run:

```bash
python3 scripts/check_policy_ui.py --browser /usr/bin/chromium
```

It uses ephemeral synthetic keys, temporary databases and random loopback UI/recipient
ports, then shuts its own servers down. It is separate from unittest; GitHub Actions runs
it as a dedicated `policy-ui` job using the runner's Chrome installation.
`--artifacts /tmp/policy-ui-check` optionally saves desktop/narrow-screen images
after credentials are cleared. Do not use production credentials for this check.

No real product Agent is connected. Background policy delivery, automatic
confidential credential transfer, live directory/revocation monitoring, browser
sessions, remote admin deployment, owner rotation/recovery, peer presence replication,
mesh chat and durable tasks remain future work. Physical LAN/tailnet/WAN behavior
is unvalidated; this change reuses the existing signed policy wire format.
