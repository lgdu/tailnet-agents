"""Install a human-issued grant for one existing Agent; no network or enrollment."""
import argparse
import json
import os
from pathlib import Path
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .identity import decode, identity_id, load_identity, verify_grant


def install_grant(token, agent_key, owner_key, group_id, output, *, now=None):
    claims = verify_grant(token, owner_key, group_id, now=now)
    if claims['sub'] != identity_id(agent_key.public_key()):
        raise ValueError('grant is for another Agent identity')
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(descriptor, 'w') as destination:
            destination.write(token + '\n')
            destination.flush()
            os.fsync(destination.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return {'subject': claims['sub'], 'group_id': group_id, 'grant_id': claims['jti'], 'expires_at': claims['exp']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent-key', required=True, help='this Agent original private PEM; never generated')
    parser.add_argument('--authority-public-key', required=True, help='existing owner public pin file')
    parser.add_argument('--group-id', required=True, help='existing human-created group ID')
    parser.add_argument('--output', required=True, help='new grant file; existing paths are never overwritten')
    args = parser.parse_args()
    try:
        data = sys.stdin.buffer.read(16385)
        if len(data) > 16384:
            raise ValueError('grant input exceeds limit')
        token = data.decode('ascii').strip()
        owner = Ed25519PublicKey.from_public_bytes(decode(Path(args.authority_public_key).read_text().strip()))
        result = install_grant(token, load_identity(args.agent_key), owner, args.group_id, args.output)
    except (ValueError, OSError):
        parser.exit(1, 'Grant installation failed; check target identity, owner/group, expiry and new output path.\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
