# Authenticated runtime monitoring — v0.24

The trusted human gateway can explicitly read a signed presence page from an
already configured directory. This view is separate from the three local Echo
chat participants. It reports one directory's recent authorized heartbeats;
it does not establish executor health, endpoint reachability or global presence.

## Configuration and use

Use the original owner signer/public pin and configured signing admin, an existing
human-created signed group, and the same `--policy-targets-file` used for
[explicit policy delivery](policy-delivery.md#configure-recipients-on-the-human-machine). Recipient IDs,
origins, group IDs, CA paths and credential environment names are administrator
configuration. No extra key/group is generated. Source configuration is off by
default; groups without signing continue to work as local Echo chat.

```bash
tailnet-agents-ui --database state/chat.sqlite3 \
  --policy-owner-key state/owner.pem \
  --policy-owner-public-key state/owner.pub \
  --policy-admin owner \
  --policy-targets-file state/policy-targets.json
```

Use the documented `TAILNET_UI_USERS` human credentials and recipient credential
environment variables. Keep values out of config files, URLs and browser fields.
The existing recipient file accepts 1–8 explicit unique origins/groups, using
HTTPS on LAN and Tailscale with CA/hostname checks, disabled proxies/redirects,
and HTTP only on loopback. Discovered candidates never become monitor sources.

1. Log in as the configured signing admin who created the signed group.
2. Open **群组成员与生命周期**, then **签名 runtime 目录观测**.
3. Select the configured directory and press **读取此目录状态**.
4. Check the displayed source ID/origin, read/observation times, policy agreement
   and each distinct Agent subject. A shared name/host/endpoint never merges keys.
5. **下一页** reads one additional page of at most 20 subjects and replaces the
   current page. Pages are separate observations, not an atomic group snapshot.

Login, opening management, listing sources, changing selection and normal chat
polling do not contact directories. Explicit reads only GET `/v1/policies`, one
`/v1/presence` page, then `/v1/policies` again. They never register, sign, deliver,
renew, discover, grant permissions or contact the advertised Agent endpoints.

## Verification and status meanings

The gateway verifies owner-signed policies before/after reading and the Agent
signatures, original owner/group/subject, metadata binding, page cursor and
presence deadlines. The policy status must match the signed snapshot's revision,
issue time and configured receiver maximum-age status. The gateway rechecks expiry
after network I/O and conservatively caps rows at policy expiry. A future source
observation clock is rejected; synchronized trusted clocks are still required.

A confirmed online row requires a fresh receiver policy identical to the current
local signed policy and an approved local subject. A changed local or source
snapshot/configuration during I/O returns conflict and discards the page; the
local database lock is never held during network requests. A different but valid
source policy is diagnostic only: online becomes **在线授权未确认**, with no
policy adoption or delivery. After local removal or renewal, explicitly deliver
the intended revision if the source still holds the old copy.

| Display | Meaning |
|---|---|
| 目录曾观测在线（租约未到期） | Configured receiver accepted a signed, authorized heartbeat under the matching policy |
| 已签名离线 | Historical Agent-signed offline state; membership remains separate |
| 租约已到期 | The conservative observation deadline has elapsed |
| 授权无效 | Receiver reports revoked/removed/expired/dissolved authorization, or current policy cannot authorize the row |
| 在线授权未确认 | Receiver's signed policy differs from the gateway's current policy |
| No rows | No signed runtime observations in this page; approved membership is unchanged |

Grant approval/expiry/learned revocation are the authenticated receiver's
observation, not a complete independently exported grant proof or receiver-signed
attestation. The gateway does not possess peer revocation histories or infer
execution permissions from this view. Legacy unsigned registrations stay outside
this signed feed. Continuous cross-directory convergence remains future work.

The browser ages observations locally without further network requests and uses
elapsed monotonic time plus conservative gateway/browser time bounds. Clock
rollback cannot turn an expired displayed snapshot online again. This can expire
a row early under clock skew/slow requests. A new explicit read is required for a
new observation. Starting another read clears the old page; errors leave no old
online rows. Source/group changes, policy mutations, close and logout invalidate
pending responses. No monitor observations or credentials enter browser storage.

## API and limits

GET `/api/runtime-presence?group_id=GROUP&target_id=ID&after=SUBJECT&limit=20`
uses the existing human Bearer credential and loopback Host/Origin checks. Only
the configured signing admin/group creator may read. `after` defaults to empty;
otherwise it is a full Ed25519 subject. Limit is an integer 1–20. Unknown/repeated
query keys, arbitrary source URLs and malformed cursors are rejected before I/O.

The response contains the configured public target, group, read/source times,
verified policy status/hash and match flag, display fields for each Agent, and
`has_more`/`next_after`. It omits complete grants, raw heartbeat tokens, private
keys and source credentials. Results use `Cache-Control: no-store` and are not
saved to SQLite. Existing signed group state/credentials and directory lease
storage are unchanged; reads cannot extend a lease.

Errors are 400 (input/config selection), 403 (human/group permission), 409
(snapshot/config changed), or sanitized 502 (transport/signature/page failure).
Clients must clear previous online state when a refresh fails. Each source GET
uses existing two-second socket-operation timeouts and the 1 MiB response cap;
these are not a strict whole-request bound. A browser abort does not guarantee
server-side I/O cancellation; remaining work is read-only and cannot apply policy.

This release does not replicate presence between directories, join candidates,
add real product adapters, execute tasks or validate physical LAN/Tailscale/WAN
behavior. Remote human sessions, source enrollment/rotation UX and global
reachability consensus remain unimplemented.
