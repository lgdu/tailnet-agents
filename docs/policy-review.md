# All-source policy review and human renewal (v0.28)

This workflow belongs to the trusted loopback human gateway. It requires the
original owner key/public pin, configured signing admin and group creator, and an
existing explicitly human-created signed group. It uses simulated identities;
no real product Agent is connected. Normal directory replication still uses
[ordered failover](policy-sync.md), not newest-source selection or quorum.

## Configure and compare

Use the existing `--policy-targets-file` [recipient configuration](policy-delivery.md)
on the human gateway. Up to eight explicit origins have independent read tokens,
CA trust and group bindings. Include every recipient you intend to compare, even
if it is also a backup for directory replication. Directory `--policy-sources-file`
and gateway recipients are separate configurations. LAN and Tailscale HTTPS
origins can coexist; only loopback may use HTTP. Tokens stay on the gateway;
redirects and environment proxies are disabled by the existing directory client.
Discovery cannot add or promote sources.

Opening management, reading policy exports and listing recipients performs no
remote I/O. **核对所有配置来源** explicitly visits every recipient for this group,
in parallel with at most eight workers. Each stable successful read uses:

1. `GET /v1/policies`, verifying owner signature and exact group.
2. `GET /v1/policy-sync`, checking age metadata against the signed claims.
3. `GET /v1/policies`, detecting changes during the read and checking age again
   with the gateway clock after network I/O.

Metadata is a transport-authenticated observation, not an owner-signed deadline.
The signature binds issue time; each recipient's own `max_age` determines its
deadline. The panel labels the check time and historical freshness, never live
global authority. One recipient can be stale while another copy is fresh. Keep
clocks synchronized; local expiry/future checks can only make the result stricter.

Rows distinguish `read`, `missing`, `changing` and `error`, and compare snapshots
as `same`, `equivalent`, `ahead`, `behind`, `conflict`, `missing` or `unknown`.
Equivalent means identical verified claims with different token serialization.
Errors use fixed diagnostics and do not expose tokens, full grants or upstream
exception text. Failure replaces earlier positive rows. The report is discarded
if the local policy or configured target objects change during I/O. Network I/O
does not hold the chat transaction lock.

## Durable signed evidence

An explicit check writes verified signed snapshots to `ui_policy_evidence` in the
gateway database. It is a POST with a local evidence write, although remote calls
are GET only. It neither signs policy nor alters membership, grants, local active
policy, leases, directory state or delivery history. Valid snapshots obtained
before a later read fails or changes still become evidence. A scan's evidence
writes commit atomically. Local signatures also enter this ledger.

The export/report exposes a summary: known highest revision, statement count,
digest, terminal-known flag, renewal eligibility and these blocking reasons:

| Reason | Meaning |
|---|---|
| `remote_ahead` | A signed revision exceeds this authority's current revision |
| `equivocation` | Different verified semantic claims share one revision |
| `time_rollback` | A later signed revision has an older issue time |
| `after_dissolution` | Signed history contains a revision after a terminal one |
| `known_dissolution` | A terminal policy is known while local policy is active |

Known unsafe history blocks **all new policy signatures**: approval, removal,
legacy/manual renewal, reviewed renewal and new dissolution. Retrieving an
already committed identical acknowledgment or repeating an already completed
dissolution makes no new signature. Grant issuance remains separate and does not
approve membership. Source failure/removal, closing the page and gateway restart
cannot clear retained evidence; startup revalidates its signatures and hashes.
This local guard does not revoke an already issued snapshot at remote receivers;
exports and separately confirmed delivery retain their existing behavior.

The ledger retains full signed member snapshots and their approved grant IDs,
not full grants, plus first-observation attribution. Reports omit those snapshots.
Protect the gateway database and consistent backups as private membership data.
There is no pruning or tamper-proof audit guarantee against the database operator.
Upgrading seeds existing current policies; history never observed before upgrade
cannot be reconstructed. Do not delete evidence, reset the database or restore
an older backup to bypass a conflict. Preserve all signed facts and the original
key/group. Safe authority-history import and explicit fork resolution are future
work; this prototype intentionally stops signing instead of selecting a branch.

## Explicit renewal consent

**预览人工续期（先核对来源）** performs another all-source check, then prepares a
60-second consent only if retained history permits renewal. It binds the original
owner/group, exact local revision/token hash, evidence digest, configured target
fingerprints and a **fixed issue timestamp**. No signature or recipient write
occurs. Empty/missing/unreachable sources cannot prove complete history: the
operator must verify authority history before proceeding. There is no quorum or
availability requirement masquerading as such a proof.

**确认按以上固定时间续期** rechecks the consent, then signs the next revision with
unchanged members, permissions and credential IDs. Confirmation does not extend
grant expiry, change revocation state or deliver policy. Explicitly export or
confirm [delivery](policy-delivery.md) afterward. The directory's deadline remains
`fixed issued_at + its own max_age`; it is not restarted at confirmation/delivery.
An expired old policy can be renewed, but local clock rollback cannot sign an
earlier timestamp. Policy, evidence, audit and retry acknowledgment commit together.

Expired previews, edited consent and changed policy/evidence/target bindings are
rejected. Browser wall-clock rollback, elapsed time, group change, management
closure, refresh and logout clear pending consent or discard late responses.
Requests use one stable request ID. A lost acknowledgment can recover the exact
committed result even after preview expiry, a later policy change, new conflicts
or dissolution; it cannot issue another revision. Reusing an ID with different
content conflicts. Successful signing still requires reading the acknowledged
current snapshot before downloads are enabled.

The legacy explicit `/api/policy-renew` remains available to programmatic callers;
it does not implicitly scan sources and is guarded by the same retained evidence.
This is not automatic renewal or a guarantee against unknown remote history.

## Verification and limits

The 33 new unittest cases cover actual loopback HTTP/TLS, all-source reads,
independent age bounds, signature/context failures, partial/changing reads,
persistent forks/terminal history, transactional faults, consent, races and retry
recovery. `scripts/check_policy_review_ui.py --browser /usr/bin/chromium` exercises
the actual browser with two receivers, clock changes, group/close races, failed
reads, retained conflicts and a narrow viewport. CI runs it after the existing
policy and runtime browser regressions.

Automatic snapshot adoption, quorum/reconciliation, safe fork repair, owner/key
recovery, evidence retention, real adapters and physical LAN/Tailscale trials
remain unimplemented. Multiple Agents on one host keep separate keys and grants;
none of these reads creates identities, groups, membership or execution rights.
