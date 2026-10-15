"""Read one signed presence page from an explicitly configured directory."""
import re

from .group_policy import POLICY_FUTURE_SKEW, verify_policy
from .policy_delivery import policy_hash
from .presence import read_presence, verify_presence
from .identity import decode
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def validate_page(after, limit):
    if (not isinstance(after, str) or (after and not re.fullmatch(r'ed25519:[a-f0-9]{64}', after)) or
            type(limit) is not int or not 1 <= limit <= 20):
        raise ValueError('invalid runtime presence page')


def read_runtime_presence(target, owner, local_token, clock, *, after='', limit=20):
    """Only GET configured origins. No registration, delivery, signing or storage.

    Receiver authorization remains a receiver observation, not an exported grant
    proof. A mismatching signed policy cannot produce a confirmed online row.
    """
    validate_page(after, limit)
    local = verify_policy(local_token, owner, target.group_id)
    token, policy = target._read(owner)
    page = read_presence(target.client, owner, target.group_id, after=after, limit=limit, now=clock())
    latest, _ = target._read(owner)
    if latest != token:
        raise FileExistsError('目录策略在读取期间变化，请重新读取。')
    status = page['policy']
    if (set(status) != {'state', 'revision', 'issued_at', 'expires_at', 'max_age'} or
            type(status['max_age']) is not int or not 1 <= status['max_age'] <= 86400):
        raise ValueError('invalid directory policy status')
    if policy is None:
        if status != {'state': 'missing', 'revision': None, 'issued_at': None, 'expires_at': None, 'max_age': status['max_age']} or page['entries']:
            raise ValueError('missing policy cannot attest presence')
    elif (type(status['revision']) is not int or status['revision'] != policy['revision'] or
          type(status['issued_at']) is not int or status['issued_at'] != policy['issued_at'] or
          type(status['expires_at']) is not int or status['expires_at'] != policy['issued_at'] + status['max_age'] or
          status['state'] not in ('fresh', 'stale', 'future', 'dissolved') or
          (status['state'] == 'dissolved') != (policy['state'] == 'dissolved')):
        raise ValueError('directory policy status does not match signed policy')
    now = clock()  # Recheck after every network request, including policy readback.
    if page['observed_at'] > now + 5:
        raise ValueError('directory observation clock is in the future')
    state = status['state']
    if policy is not None:
        conservative = ('dissolved' if policy['state'] == 'dissolved' else
                        'future' if policy['issued_at'] > now + POLICY_FUTURE_SKEW else
                        'stale' if now >= status['expires_at'] else 'fresh')
        if conservative != 'fresh': state = conservative
    entries = []
    for entry in page['entries']:
        key = Ed25519PublicKey.from_public_bytes(decode(entry['public_key']))
        claims = verify_presence(entry['presence'], key, owner, target.group_id, entry['record'])
        expires = min(entry['expires_at'], status['expires_at'])
        observed_state = entry['state']
        if observed_state == 'online':
            if now >= expires or claims['issued_at'] > now + 5:
                observed_state = 'expired'
            elif token != local_token:
                observed_state = 'unconfirmed'
            elif state != 'fresh' or local['state'] != 'active' or entry['subject'] not in local['members']:
                observed_state = 'unauthorized'
        entries.append({'subject': entry['subject'], 'record': entry['record'], 'state': observed_state,
                        'source_state': entry['state'], 'expires_at': expires, 'observed_at': entry['observed_at'],
                        **{field: claims[field] for field in ('generation', 'boot_id', 'sequence', 'issued_at')}})
    return {'target': target.public(), 'group_id': target.group_id, 'checked_at': now,
            'observed_at': page['observed_at'], 'policy': status | {'state': state, 'matches_local': token == local_token,
                'policy_hash': None if token is None else policy_hash(token)},
            'entries': entries, 'has_more': page['has_more'], 'next_after': page['next_after']}
