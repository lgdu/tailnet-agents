# Two bridges on a tailnet

This milestone connects **Echo bridges**, not real model agents. No model API
keys or subscriptions are needed. Use Python 3.11+ and your existing Tailscale
installation. Every node must be able to reach the registry and intended peer
ports under your tailnet access policy.

## 1. Registry host

Clone the repository, then run from its root. Provision independent random
registry tokens for nodes A and B (at least 32 ASCII characters each).
Keep credentials in environment variables or a secret manager, outside git.

```bash
export TAILNET_AGENT_TOKENS='{"node-a":"REPLACE_WITH_RANDOM_TOKEN_A","node-b":"REPLACE_WITH_RANDOM_TOKEN_B"}'
python3 -m tailnet_agents.registry
```

Replace the placeholders; they intentionally do not pass secret-length validation.
Use Tailscale Serve to map this host's private HTTPS origin to loopback port
8765. Retain the actual resulting URL as `REGISTRY_URL`. Do not enable Funnel.
The registry can also run on a bridge host, but needs a distinct HTTPS route or
port. Separate hosts simplify the first deployment.

## 2. Bridge A

Use node A's registry token. Provision a separate random task token for B to
call A; it is unrelated to the registry token.

```bash
export TAILNET_REGISTRY_TOKEN='REPLACE_WITH_RANDOM_TOKEN_A'
export TAILNET_PEER_TOKENS='{"node-b":"REPLACE_WITH_RANDOM_B_TO_A_TOKEN"}'
python3 -m tailnet_agents.bridge \
  --id node-a-echo \
  --registry "$REGISTRY_URL" \
  --advertise-url "$BRIDGE_A_HTTPS_ORIGIN"
```

Use Tailscale Serve to map A's private HTTPS origin to loopback port 8766.
`BRIDGE_A_HTTPS_ORIGIN` must be an origin such as
`https://machine-a.YOUR-TAILNET.ts.net`, without a path or query.

## 3. Bridge B

Repeat the setup on B with node B's registry token, ID `node-b-echo`, B's HTTPS
origin, and an independent A-to-B task token. Each bridge renews its 60-second
lease every 20 seconds. Stopping a bridge removes it from discovery once its
last lease expires. The registry does not probe endpoints.

## 4. Discover and call B from A

In another terminal on A:

```bash
export TAILNET_REGISTRY_TOKEN='REPLACE_WITH_RANDOM_TOKEN_A'
export TAILNET_REMOTE_TOKEN='REPLACE_WITH_RANDOM_A_TO_B_TOKEN'
python3 -m tailnet_agents.cli --registry "$REGISTRY_URL" discover --skill echo
python3 -m tailnet_agents.cli --registry "$REGISTRY_URL" send \
  --agent node-b-echo \
  --allow-host machine-b.YOUR-TAILNET.ts.net \
  --message 'Hello from A' \
  --key example-request-001
```

Replace the allowed hostname with the exact hostname in B's registered origin.
The host allowlist is supplied independently of registry records. The client
rejects redirects and disables ambient HTTP proxies to protect credentials.
Use B's token for A and A's hostname to call A from B.

The result includes an ID, status and echoed text. Use the same key and message
when retrying a request whose response was lost; a changed message with the
same key returns 409. Deduplication is per caller and lasts only until the
bridge restarts. A wait deadline does not cancel the remote task.

## Validation and limits

```bash
python3 -m unittest discover -s tests -v
```

The tests start a registry and two bridges on local HTTP ports. They verify
registration, discovery, task execution, retries and cross-caller result
isolation. Advertised HTTPS origins are mapped to loopback HTTP endpoints in
the test harness. These tests do not verify a real tailnet or TLS deployment.

Task capacity is 256 records per process including completed work. There is
no eviction, persistence, execution cancellation or task deadline in this
Echo prototype. Registry reads expose all agent metadata to authenticated
registry clients. Shared knowledge and filesystem access are out of scope.
