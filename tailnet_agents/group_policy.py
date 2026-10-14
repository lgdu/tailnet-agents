"""Owner-signed group snapshots; trusted human administration API, no discovery."""
import re
import secrets
import time
from .identity import AdmissionError, PERMISSIONS, identity_id, sign, verify

POLICY_TYPE = 'tailnet-group-policy+jwt'
POLICY_FUTURE_SKEW = 30


def validate_policy(claims, owner_key, group_id):
    fields = {'owner', 'group_id', 'name', 'revision', 'issued_at', 'state', 'members'}
    if set(claims) != fields or claims['owner'] != identity_id(owner_key) or claims['group_id'] != group_id:
        raise AdmissionError('wrong policy authority, group or schema')
    if not isinstance(group_id, str) or not 1 <= len(group_id) <= 128:
        raise AdmissionError('invalid group id')
    if not isinstance(claims['name'], str) or not 1 <= len(claims['name'].strip()) <= 100:
        raise AdmissionError('invalid group name')
    if type(claims['revision']) is not int or not 1 <= claims['revision'] <= 2**53 - 1:
        raise AdmissionError('invalid policy revision')
    if type(claims['issued_at']) is not int or claims['issued_at'] < 0:
        raise AdmissionError('invalid policy timestamp')
    if claims['state'] not in ('active', 'dissolved'):
        raise AdmissionError('invalid group state')
    members = claims['members']
    if not isinstance(members, dict) or len(members) > 64 or (claims['state'] == 'dissolved' and members):
        raise AdmissionError('invalid policy members')
    for subject, member in members.items():
        if not isinstance(subject, str) or not re.fullmatch(r'ed25519:[a-f0-9]{64}', subject):
            raise AdmissionError('invalid policy subject')
        if not isinstance(member, dict) or set(member) != {'permissions', 'grant_ids'}:
            raise AdmissionError('invalid member schema')
        permissions, grants = member['permissions'], member['grant_ids']
        if (not isinstance(permissions, list) or len(permissions) > len(PERMISSIONS) or
                any(not isinstance(p, str) or p not in PERMISSIONS for p in permissions) or
                len(set(permissions)) != len(permissions) or 'join' not in permissions):
            raise AdmissionError('invalid member permissions')
        if (not isinstance(grants, list) or not 1 <= len(grants) <= 8 or
                any(not isinstance(g, str) or not re.fullmatch(r'[a-f0-9]{32}', g) for g in grants) or
                len(set(grants)) != len(grants)):
            raise AdmissionError('invalid approved grant ids')
    return claims


def verify_policy(token, owner_key, group_id):
    return validate_policy(verify(token, owner_key, POLICY_TYPE), owner_key, group_id)


def _signed_policy(owner, claims):
    validate_policy(claims, owner.public_key(), claims['group_id'])
    token = sign(owner, claims, POLICY_TYPE)
    if len(token) > 16384:
        raise AdmissionError('policy exceeds signed message limit')
    return token


def create_policy(owner, name, members, *, now=None):
    """Explicit administrator action. Never call on Agent startup/discovery timeout."""
    return _signed_policy(owner, {
        'owner': identity_id(owner.public_key()), 'group_id': secrets.token_hex(16),
        'name': name, 'revision': 1, 'issued_at': int(time.time()) if now is None else now,
        'state': 'active', 'members': members,
    })


def revise_policy(owner, previous_token, members, *, dissolve=False, now=None):
    previous = verify(previous_token, owner.public_key(), POLICY_TYPE)
    validate_policy(previous, owner.public_key(), previous.get('group_id'))
    if previous['state'] == 'dissolved':
        raise AdmissionError('dissolution is terminal')
    issued_at = int(time.time()) if now is None else now
    if type(issued_at) is not int or issued_at < previous['issued_at']:
        raise AdmissionError('policy time cannot move backwards')
    if type(dissolve) is not bool:
        raise AdmissionError('invalid dissolution flag')
    return _signed_policy(owner, previous | {
        'revision': previous['revision'] + 1, 'issued_at': issued_at,
        'state': 'dissolved' if dissolve else 'active', 'members': {} if dissolve else members,
    })


class PolicyStore:
    """One pinned group on caller's SQLite connection; caller serializes access.

    Snapshots may skip revisions. Same-revision conflicts and rollback fail closed.
    Learned dissolution is permanent. Active authorization has a bounded age
    measured from the owner's signed timestamp, never from receipt or polling.
    """
    def __init__(self, db, owner_key, group_id, *, clock=time.time, max_age=300):
        self.db, self.owner_key, self.group_id = db, owner_key, group_id
        self.clock, self.max_age = clock, max_age
        db.execute('CREATE TABLE IF NOT EXISTS group_policy (id INTEGER PRIMARY KEY CHECK(id=1), token TEXT NOT NULL)')
        self.current()  # Reject a corrupt or foreign snapshot on startup.

    def current(self):
        row = self.db.execute('SELECT token FROM group_policy WHERE id=1').fetchone()
        return None if row is None else verify_policy(row[0], self.owner_key, self.group_id)

    def apply(self, token):
        incoming = verify_policy(token, self.owner_key, self.group_id)
        if incoming['issued_at'] > self.clock() + POLICY_FUTURE_SKEW:
            raise AdmissionError('policy timestamp is in the future')
        with self.db:
            previous = self.current()
            if previous:
                if incoming == previous:
                    return previous
                if previous['state'] == 'dissolved':
                    raise AdmissionError('dissolution is terminal')
                if incoming['revision'] <= previous['revision']:
                    raise AdmissionError('policy rollback or revision conflict')
                if incoming['issued_at'] < previous['issued_at']:
                    raise AdmissionError('policy time rollback')
            self.db.execute('INSERT INTO group_policy VALUES(1,?) ON CONFLICT(id) DO UPDATE SET token=excluded.token', (token,))
        return incoming

    def status(self):
        policy = self.current()
        result = {'state': 'missing', 'revision': None, 'issued_at': None,
                  'expires_at': None, 'max_age': self.max_age}
        if policy is None:
            return result
        now = self.clock()
        expires = policy['issued_at'] + self.max_age
        state = ('dissolved' if policy['state'] == 'dissolved' else
                 'future' if policy['issued_at'] > now + POLICY_FUTURE_SKEW else
                 'stale' if now >= expires else 'fresh')
        return result | {'state': state, 'revision': policy['revision'],
                         'issued_at': policy['issued_at'], 'expires_at': expires}

    def authorize(self, grant):
        policy = self.current()
        if policy is None or policy['state'] != 'active':
            raise AdmissionError('active group policy required')
        now = self.clock()
        if policy['issued_at'] > now + POLICY_FUTURE_SKEW or now >= policy['issued_at'] + self.max_age:
            raise AdmissionError('fresh group policy required')
        member = policy['members'].get(grant['sub'])
        if (member is None or grant['jti'] not in member['grant_ids'] or
                not set(grant['permissions']) <= set(member['permissions'])):
            raise AdmissionError('grant not approved by current policy')
        return policy
