# Verified admission over TLS (v0.14)

The verified admission service can now bind an IPv4 LAN or tailnet address when
TLS and explicit HTTP host names are configured. Default remains loopback HTTP.
This is transport support for controlled trials, not a tested production mesh.
The human UI and ordinary Echo bridge are unchanged; these options apply only
to the verified admission service/client.

## Trust setup

Prepare a server certificate/key through your chosen certificate authority.
The certificate must include the exact URL hostname or IP address in its SANs.
Deliver the trusted CA and the intended service URL/audience to callers through
a trusted channel. TLS certificates and Ed25519 Agent/owner keys serve different
purposes: do not interchange them. The certificate authenticates the server URL;
the grant and possession proof authenticate the admitted Agent.

The service needs the already approved group ID, pinned authority public key
and agreed audience. Signed human group-creation policy is not validated by this
service yet. No automatic Agent group creation is added.

## LAN example

Substitute the actual IPv4 address and certificate paths on the server:

```bash
python3 -m tailnet_agents.admission_server \
  --authority-public-key state/owner.pub \
  --group-id YOUR-GROUP-ID \
  --audience receiver-identity \
  --host 192.168.1.20 \
  --port 8771 \
  --tls-cert state/server-cert.pem \
  --tls-key state/server-key.pem \
  --allow-host 192.168.1.20
```

For this IP URL, the certificate must have IP SAN `192.168.1.20`; a DNS SAN or
matching Common Name alone is insufficient. Prefer your actual stable DNS name
when available: allow that hostname and use it in the client URL. Allowed hosts
are specified without ports and cannot be wildcards. The service checks the
actual listening port. Binding IPv6 is not implemented in this prototype.

Set `TAILNET_VERIFIED_READ_TOKEN` before startup as in the admission guide.
Only intended peers should reach the port under the host/network access policy.

On another machine, transfer only its own Agent key/grant and the trusted CA:

```bash
python3 -m tailnet_agents.verified_client \
  --url https://192.168.1.20:8771 \
  --agent-key state/agent.pem \
  --grant-file state/agent.grant \
  --record-file state/record.json \
  --audience receiver-identity \
  --ca-cert state/ca-cert.pem
```

`--ca-cert` selects a private CA trust file. Omit it to use system CA trust.
Certificate validation and hostname checking remain enabled; there is no
insecure/skip-verification option. Repeated registration uses fresh challenges.

## Tailscale

The same server can bind its IPv4 tailnet address, allow its actual MagicDNS
hostname and use a certificate for that hostname. Callers use the corresponding
HTTPS URL, subject to tailnet access policy. Tailscale connectivity does not
replace Agent admission. No peer enumeration or automatic tailnet discovery is
implemented by this milestone; the URL is explicitly configured.

This implementation terminates TLS directly. A TLS-terminating reverse proxy
would require explicit external-host/port/origin and trusted proxy semantics;
do not assume this direct-server configuration works behind arbitrary proxies.

## Transport controls and remaining work

- TLS 1.2 or later, certificate chain and hostname verification.
- Non-loopback binds require both certificate/key and explicit allowed hosts.
- HTTP Host and browser Origin checked against configured host/port and scheme.
- Client redirects refused; ambient HTTP proxies disabled.
- Server TLS handshake timeout: 5 seconds; HTTP request timeout: 10 seconds.
- Challenge/body limits from the admission guide still apply.

There is no mTLS; subject identity is verified with signed admission proofs.
The challenge is bound to a configured audience and record, not a TLS exporter.
Cert renewal, owner-key rotation, per-source rate limits, hardened HTTP serving,
signed policy binding, discovery plugins and distributed lifecycle remain work
items. TLS acceptance currently occurs in the server accept path and can delay
other accepts up to its timeout. Do not treat it as a hardened public service.

Tests generate a temporary CA/server certificate and run actual HTTPS requests
on loopback. They verify valid admission, stable discovery, unknown CA rejection,
SAN hostname mismatch rejection and refusal of plaintext non-loopback config.
They do not test actual household routers, tailnet links, firewalls or WAN latency.

Primary TLS API reference: https://docs.python.org/3.11/library/ssl.html
