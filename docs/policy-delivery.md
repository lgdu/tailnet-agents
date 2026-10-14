# Explicit policy delivery — v0.21

The trusted loopback human gateway can deliver its current signed snapshot to an
explicitly configured recipient. Opening a group, listing recipients, previewing
consent, signing a policy and restarting the UI never contact recipients. A human
must confirm the origin, group, owner, revision and snapshot hash first.

This copies authorization state. It does not issue credentials, register Agents,
renew signed timestamps, cancel running work or promote discovered endpoints into
trusted recipients/sources. Grant issuance/provisioning remains manual.

## Configure recipients on the human machine

First explicitly create the signed group with [human policy signing](human-policy.md).
Retain its exact ID, database, owner key/public pin and human administrator. Prepare
the receiving verified directory with that same group and owner public pin; it
does not need the owner private key. Configure TLS for non-loopback endpoints.

Save trusted `state/policy-targets.json`:

```json
[
  {
    "id": "lan-directory",
    "url": "https://directory.lan.example:8771",
    "group_id": "YOUR-EXISTING-SIGNED-GROUP-ID",
    "token_env": "TAILNET_RECIPIENT_LAN_READ",
    "ca_cert": "lan-ca.pem"
  },
  {
    "id": "tailnet-directory",
    "url": "https://node.YOUR-TAILNET.ts.net:8771",
    "group_id": "YOUR-EXISTING-SIGNED-GROUP-ID",
    "token_env": "TAILNET_RECIPIENT_TAILNET_READ"
  }
]
```

Set each named environment variable securely to that recipient's read credential.
Values never belong in this JSON, a browser field, URL or command line. CA paths
are relative to the file; omission uses system trust. This configuration is
separate from credential-free discovery seeds and ordered policy-pull sources.

Configure 1–8 unique IDs/origins in a file no larger than 16 KiB. Origins contain
no paths, queries, fragments or user credentials. HTTPS is mandatory outside
loopback, including LAN/Tailscale, with CA and hostname validation. Proxies and
redirects are disabled. Recipient groups must already exist as signed groups in
this UI database; configuration never creates or imports them. Unknown fields,
missing credentials and mismatched groups fail configuration.

Restart the gateway with its original authority and the explicit recipient file:

```bash
python3 -m tailnet_agents.ui \
  --database state/chat.sqlite3 \
  --policy-owner-key state/owner.pem \
  --policy-owner-public-key state/owner.pub \
  --policy-admin demo-owner \
  --policy-targets-file state/policy-targets.json
```

Use the configured human admin ID instead of `demo-owner` when using multiple
UI users. Omitting the targets flag disables new deliveries while retaining
historical records. The UI remains loopback-only on the trusted human machine;
the recipient's configured origin may be on LAN or Tailscale.

## Preview and confirm

Open **管理群组 → 明确送达签名策略**, choose a configured recipient and select
**预览接收方与当前版本**. This is local-only: it shows the exact origin, group,
owner, revision, active/dissolved state and snapshot hash without sending a read
credential. Check the intended recipient, then select **确认送达此快照**.

The POST body contains only a configured ID/fingerprint, expected revision/hash
and stable request ID. It cannot supply an arbitrary origin or inline credential.
The server binds consent to startup configuration including CA contents; a policy
or recipient configuration change requires a fresh preview. Credential-value
rotation at the same configured origin does not change its routing fingerprint.

Delivery preflights the recipient's owner/group-signed policy. Newer, conflicting
same-revision and terminal state are not overwritten. If it already has the exact
snapshot, the gateway skips POST. Otherwise it sends that snapshot to the existing
protected policy route, validates the acknowledgment, reads the signed snapshot
back and reads recipient freshness. Wrong signatures/scopes, inconsistent copies
or malformed status cannot become a successful receipt.

The gateway verifies revision/timestamps and the reported maximum-age bound,
then conservatively evaluates age with its own clock too. A stale policy may be
copied successfully but is labeled expired and cannot authorize admission. A
terminal policy is deliverable after local dissolution. No copy operation renews
policy, issues a grant or opens a dissolved group. Explicit human renewal produces
a new snapshot that requires another preview/confirmation.

## Receipts, failures and recovery

Receipts include recipient metadata, revision, snapshot hash, policy state,
authorization state, age bound/deadline and check time. They are historical
authenticated readback observations, not receiver-signed attestations, ongoing
health checks or proof of Agent membership/execution rights. The page shows their
observation time and deadline; recipient state can change afterwards. To obtain
another observation, explicitly preview and confirm again with a new request.

Delivery intent/outcome/receipt persist with the original group and human actor;
read tokens and private keys do not enter SQLite history or browser responses.
Same request ID with changed consent conflicts. Completed identical retries return
the original timestamped receipt without network I/O. If acceptance is unknown,
retrying the same request checks the recipient first and avoids a second POST
when the snapshot is already present. There is no background retry on restart.

If the UI already received a success response but cannot refresh its local page,
its retry only rereads local state. If the UI response was lost, the persistent
delivery request protects recovery. Reload/logout loses browser pending state;
inspect historical records before confirming another delivery.

Network I/O holds no local policy lock. A concurrent removal/renewal/dissolution
can proceed; the gateway rechecks consent before writing and before recording
success. If local policy changed in flight, a recipient may already have accepted
the old snapshot. The operation returns conflict instead of claiming the current
policy is delivered. Re-read local state and explicitly send the latest snapshot;
no automatic rollback, policy import or unconfirmed replacement is attempted.
Immediate partition-wide revocation and atomic multi-recipient delivery are not
implemented. Deliveries are serialized within one gateway and one recipient is
selected per confirmation.

Client operations have two-second socket-operation timeouts and a 1 MiB response
cap; these are not strict whole-request wall-time limits. UI requests can time out
before final acceptance is known. Protect synchronized clocks and consistent UI
backups; local history is plaintext and not rollback-proof. A restored old backup
or a compromised configured receiver remains outside these guarantees.

## Validation and remaining work

Tests use real HTTP/TLS recipients, synthetic identities and a real UI CLI restart.
They cover no-contact previews, protected delivery, exact signature/hash readback,
age bounds, terminal state, roles/scopes, TLS/redirect rejection, stable retries,
restart recovery and policy changes during slow network I/O. Chromium checks the
visible preview, explicit confirmation, lost delivery acknowledgment/retry and
terminal delivery; the same check runs in CI.

Credential issuance/provisioning UI, runtime enrollment, live receiver monitoring,
owner recovery/rotation, distributed presence/chat and durable tasks remain future
work. No real product Agent or physical LAN/WAN/tailnet trial is included.
