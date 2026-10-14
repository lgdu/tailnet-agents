"""Signed simulation-runtime observations, separate from membership authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import urlencode

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .client import Client, validate_url
from .identity import AdmissionError, decode, identity_id, sign, verify
from .registry import Registry

PRESENCE_TYPE = 'tailnet-agent-presence+jwt'
MAX_COUNTER = 2**53 - 1


def canonical_record(record):
    if not isinstance(record, dict) or set(record) - {'endpoint', 'name', 'protocol', 'skills', 'ttl_seconds'}:
        raise AdmissionError('invalid presence record fields')
    normalized = Registry.normalize_record(record | {'id': 'pending'})
    del normalized['id']
    parsed = validate_url(normalized['endpoint'])
    parsed.port  # Reject malformed advertised ports without resolving/contacting the endpoint.
    if len(json.dumps(normalized).encode()) > 4096:
        raise AdmissionError('presence record exceeds 4096 bytes')
    return normalized


def record_hash(record):
    return hashlib.sha256(json.dumps(canonical_record(record), sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def presence_context(record, token):
    if not isinstance(token, str) or len(token) > 16384:
        raise AdmissionError('invalid presence token')
    payload = {'record': canonical_record(record), 'presence_hash': hashlib.sha256(token.encode()).hexdigest()}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def verify_presence(token, key, owner, group_id, record, *, now=None):
    claims = verify(token, key, PRESENCE_TYPE)
    if (set(claims) != {'version', 'owner', 'group_id', 'subject', 'record_hash', 'generation', 'boot_id', 'sequence', 'state', 'issued_at', 'expires_at'} or
            type(claims['version']) is not int or claims['version'] != 1 or
            claims['owner'] != identity_id(owner) or claims['group_id'] != group_id or
            not isinstance(group_id, str) or not 1 <= len(group_id) <= 128 or
            claims['subject'] != identity_id(key) or claims['subject'] == claims['owner'] or
            claims['record_hash'] != record_hash(record) or
            any(type(claims[field]) is not int or not 1 <= claims[field] <= MAX_COUNTER for field in ('generation', 'sequence')) or
            not isinstance(claims['boot_id'], str) or not re.fullmatch(r'[a-f0-9]{32}', claims['boot_id']) or
            claims['state'] not in ('online', 'offline') or
            any(type(claims[field]) is not int or claims[field] < 0 for field in ('issued_at', 'expires_at')) or
            not 0 < claims['expires_at'] - claims['issued_at'] <= canonical_record(record)['ttl_seconds']):
        raise AdmissionError('invalid presence claims')
    if now is not None and (claims['issued_at'] > now + 5 or now >= claims['expires_at']):
        raise AdmissionError('presence expired or timestamp in the future')
    return claims


def make_presence(key, owner, group_id, record, generation, boot_id, sequence, *, state='online', now=None, expires_at=None):
    now = int(time.time()) if now is None else now
    claims = {'version': 1, 'owner': identity_id(owner), 'group_id': group_id,
              'subject': identity_id(key.public_key()), 'record_hash': record_hash(record),
              'generation': generation, 'boot_id': boot_id, 'sequence': sequence, 'state': state,
              'issued_at': now, 'expires_at': now + canonical_record(record)['ttl_seconds'] if expires_at is None else expires_at}
    token = sign(key, claims, PRESENCE_TYPE)
    verify_presence(token, key.public_key(), owner, group_id, record, now=now)
    return token


def read_presence(client, owner, group_id, *, after='', limit=20, now=None):
    if type(limit) is not int or not 1 <= limit <= 20 or not isinstance(after, str) or (after and not re.fullmatch(r'ed25519:[a-f0-9]{64}', after)):
        raise ValueError('invalid presence page')
    response = client.request('/v1/presence?' + urlencode({'after': after, 'limit': limit}))
    if (not isinstance(response, dict) or set(response) != {'owner', 'group_id', 'observed_at', 'policy', 'entries', 'has_more', 'next_after'} or
            response.get('owner') != identity_id(owner) or response.get('group_id') != group_id or
            type(response['observed_at']) not in (int, float) or not 0 <= response['observed_at'] < float('inf') or
            not isinstance(response['policy'], dict) or response['policy'].get('state') not in ('missing', 'fresh', 'stale', 'future', 'dissolved') or
            not isinstance(response.get('entries'), list) or len(response['entries']) > limit or
            type(response.get('has_more')) is not bool or not isinstance(response.get('next_after'), str)):
        raise ValueError('invalid configured-directory presence response')
    now = time.time() if now is None else now
    cursor = after
    for entry in response['entries']:
        if not isinstance(entry, dict) or set(entry) != {'id', 'subject', 'public_key', 'record', 'presence', 'state', 'expires_at', 'observed_at'}:
            raise ValueError('invalid presence entry')
        key = Ed25519PublicKey.from_public_bytes(decode(entry['public_key']))
        claims = verify_presence(entry['presence'], key, owner, group_id, entry['record'])
        if (entry.get('id') != 'agent-' + claims['subject'].split(':')[1] or
                entry.get('subject') != claims['subject'] or
                entry.get('state') not in ('online', 'offline', 'expired', 'unauthorized') or
                type(entry.get('expires_at')) not in (int, float) or
                not 0 <= entry['expires_at'] <= claims['expires_at'] or
                type(entry['observed_at']) not in (int, float) or not 0 <= entry['observed_at'] <= response['observed_at'] or
                claims['subject'] <= cursor):
            raise ValueError('invalid presence observation')
        cursor = claims['subject']
        if entry['state'] == 'offline' and claims['state'] != 'offline':
            raise ValueError('offline observation requires a signed offline state')
        if entry['state'] == 'online':
            if claims['state'] != 'online' or response['policy']['state'] != 'fresh':
                raise ValueError('offline signature cannot attest online presence')
            if now >= entry['expires_at'] or claims['issued_at'] > now + 5:
                entry['state'] = 'expired'
    if response['next_after'] != cursor or (response['has_more'] and not response['entries']):
        raise ValueError('invalid presence cursor')
    return response


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True, help='explicit trusted directory origin')
    parser.add_argument('--authority-public-key', required=True)
    parser.add_argument('--group-id', required=True)
    parser.add_argument('--ca-cert')
    parser.add_argument('--after', default='', help='subject cursor from the previous page')
    parser.add_argument('--limit', type=int, default=20)
    args = parser.parse_args()
    try:
        owner = Ed25519PublicKey.from_public_bytes(decode(Path(args.authority_public_key).read_text().strip()))
        client = Client(args.url, os.environ.get('TAILNET_VERIFIED_READ_TOKEN', ''), timeout=2, ca_file=args.ca_cert)
        result = read_presence(client, owner, args.group_id, after=args.after, limit=args.limit)
    except (ValueError, OSError, KeyError, TypeError):
        parser.exit(1, 'Presence read failed; check configured directory, owner/group, read token and TLS.\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
