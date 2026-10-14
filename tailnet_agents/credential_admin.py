"""Explicit human grant issuance; independent of membership and network delivery."""
import hashlib
import json
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .identity import (GRANT_TYPE, PERMISSIONS, decode, identity_id, issue_grant,
                       sign, verify_grant)

FIELDS = {'public_key', 'permissions', 'lifetime', 'expected_revision', 'policy_hash'}
PREVIEW_SECONDS = 60


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def request(authority, payload):
    if (not isinstance(payload.get('public_key'), str) or
            not isinstance(payload.get('permissions'), list) or
            not 1 <= len(payload['permissions']) <= len(PERMISSIONS) or
            any(not isinstance(p, str) or p not in PERMISSIONS for p in payload['permissions']) or
            len(set(payload['permissions'])) != len(payload['permissions']) or 'join' not in payload['permissions'] or
            type(payload.get('lifetime')) is not int or not 1 <= payload['lifetime'] <= 86400 or
            type(payload.get('expected_revision')) is not int or payload['expected_revision'] < 1 or
            not isinstance(payload.get('policy_hash'), str) or not re.fullmatch(r'[a-f0-9]{64}', payload['policy_hash'])):
        raise ValueError('select an existing Agent public key, explicit permissions and 1..86400 second lifetime')
    key = Ed25519PublicKey.from_public_bytes(decode(payload['public_key']))
    if identity_id(key) == authority.owner:
        raise ValueError('owner authority key cannot serve as an Agent identity')
    normalized = {name: payload[name] for name in FIELDS}
    normalized['permissions'] = sorted(payload['permissions'])
    return key, normalized


def current(authority, db, group_id, payload):
    token, policy = authority.current(db, group_id)
    if policy['state'] != 'active':
        raise PermissionError('signed group is dissolved')
    if (policy['revision'] != payload['expected_revision'] or
            hashlib.sha256(token.encode()).hexdigest() != payload['policy_hash']):
        raise FileExistsError('policy changed; preview credential issuance again')


def consent(authority, group_id, normalized, issued_at):
    return digest(normalized | {'owner': authority.owner, 'group_id': group_id, 'issued_at': issued_at})


def preview(authority, db, group_id, payload):
    if set(payload) != FIELDS:
        raise ValueError('invalid credential preview fields')
    key, normalized = request(authority, payload)
    current(authority, db, group_id, normalized)
    now = int(authority.clock())
    return normalized | {'group_id': group_id, 'owner': authority.owner, 'subject': identity_id(key),
                         'issued_at': now, 'expires_at': now + normalized['lifetime'],
                         'preview_expires_at': min(now + PREVIEW_SECONDS, now + normalized['lifetime']),
                         'consent_hash': consent(authority, group_id, normalized, now)}


def result(authority, group_id, request_id, normalized, claims, grant_hash):
    token = sign(authority.key, claims, GRANT_TYPE)
    if hashlib.sha256(token.encode()).hexdigest() != grant_hash:
        raise ValueError('stored issuance integrity check failed')
    verify_grant(token, authority.key.public_key(), group_id, now=authority.clock())
    return {'grant': token, 'claims': claims, 'grant_hash': grant_hash, 'request_id': request_id,
            'issued_policy_revision': normalized['expected_revision'],
            'issued_policy_hash': normalized['policy_hash'], 'membership_changed': False}


def issue(authority, db, group_id, payload):
    if (set(payload) != FIELDS | {'issued_at', 'consent_hash', 'request_id'} or
            not isinstance(payload['request_id'], str) or not 1 <= len(payload['request_id']) <= 128 or
            type(payload['issued_at']) is not int):
        raise ValueError('invalid explicit credential issuance fields')
    key, normalized = request(authority, payload)
    if payload['consent_hash'] != consent(authority, group_id, normalized, payload['issued_at']):
        raise FileExistsError('credential consent changed; preview again')
    canonical = normalized | {name: payload[name] for name in ('issued_at', 'consent_hash', 'request_id')}
    serialized = json.dumps(canonical, sort_keys=True)
    previous = db.execute('SELECT payload,claims,grant_hash FROM ui_grant_issuances WHERE group_id=? AND request_id=?',
                          (group_id, payload['request_id'])).fetchone()
    if previous:
        if previous[0] != serialized:
            raise FileExistsError('credential request ID reused with changed consent')
        claims = json.loads(previous[1])
        if db.execute('SELECT 1 FROM ui_retired_grants WHERE group_id=? AND jti=?', (group_id, claims['jti'])).fetchone():
            raise PermissionError('removed credentials cannot be retrieved; explicitly issue a new grant')
        return result(authority, group_id, payload['request_id'], normalized, claims, previous[2])
    current(authority, db, group_id, normalized)
    now = authority.clock()
    if not payload['issued_at'] <= now < min(payload['issued_at'] + PREVIEW_SECONDS, payload['issued_at'] + normalized['lifetime']):
        raise FileExistsError('credential preview expired or is in the future; preview again')
    token = issue_grant(authority.key, key, group_id, normalized['permissions'],
                        now=payload['issued_at'], lifetime=normalized['lifetime'])
    claims = verify_grant(token, authority.key.public_key(), group_id, now=now)
    grant_hash = hashlib.sha256(token.encode()).hexdigest()
    db.execute('INSERT INTO ui_grant_issuances VALUES(?,?,?,?,?,?)',
               (group_id, payload['request_id'], serialized, json.dumps(claims, sort_keys=True), grant_hash, now))
    return result(authority, group_id, payload['request_id'], normalized, claims, grant_hash)


def history(authority, db, group_id):
    rows = db.execute('SELECT request_id,payload,claims,grant_hash,created FROM ui_grant_issuances WHERE group_id=? ORDER BY created DESC,rowid DESC LIMIT 50', (group_id,)).fetchall()
    entries = []
    for request_id, payload, claims, grant_hash, created in rows:
        claims = json.loads(claims)
        retired = db.execute('SELECT 1 FROM ui_retired_grants WHERE group_id=? AND jti=?', (group_id, claims['jti'])).fetchone()
        state = 'retired' if retired else 'expired' if authority.clock() >= claims['exp'] else 'future' if authority.clock() < claims['nbf'] else 'valid'
        entries.append({'request_id': request_id, 'request': json.loads(payload), 'claims': claims,
                        'grant_hash': grant_hash, 'created': created, 'state': state})
    return {'issuances': entries}
