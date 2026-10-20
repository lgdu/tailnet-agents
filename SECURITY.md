# Security policy

Tailnet Agents is an experimental prototype with synthetic Echo agents. Real
product Agent integration and physical LAN/Tailscale deployment trials remain
unvalidated. Read [current status](docs/status.md) and the
[architecture boundaries](docs/architecture.md) before evaluating a deployment.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/lgdu/tailnet-agents/security/advisories/new).
Use the repository's **Security → Report a vulnerability** entry. Please do not
post exploit details or sensitive data in public issues or pull requests.

Include the affected tag or commit, configuration, expected and actual behavior,
the affected authorization or data boundary, and a minimal sanitized reproduction.
Do not include live tokens, private keys, personal messages or database dumps.

If the private reporting entry is unavailable, wait until a private channel is
available before sharing sensitive details; do not fall back to a public issue.

## Maintenance scope

Reports against current `main` and the latest GitHub prerelease are welcome.
Older releases do not receive maintained security backports. Security fixes are
handled on a best-effort basis; there is no guaranteed response or fix deadline.

## Deployment boundaries

- Keep the Human UI on trusted loopback access. It holds keys and uses configured
  bearer credentials; external identity/session integration remains unimplemented.
- Keep keys, tokens, SQLite state and backups outside git with private filesystem
  permissions. Task and message stores retain plaintext; no end-to-end encryption
  or confidentiality from trusted OS/database operators is claimed.
- Network discovery and LAN/Tailscale reachability do not grant membership or task
  rights. Groups require an explicit human action; scoped authorization and current
  policy remain separate checks.

See [operations](docs/operations.md) and [TLS deployment](docs/tls-deployment.md)
for the implemented configuration and recovery limits. Public source availability
does not make the services suitable for public Internet exposure.
