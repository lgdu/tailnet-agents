"""Opt-in signing on the trusted human's loopback gateway; no network I/O."""
import hashlib
import json
import os
import stat
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .group_policy import create_policy, revise_policy, verify_policy, POLICY_TYPE
from .identity import AdmissionError, decode, encode, identity_id, public_bytes, verify, verify_grant


class PolicyAuthority:
    def __init__(self, key, principal, *, clock=time.time):
        self.key, self.principal, self.clock = key, principal, clock
        self.owner = identity_id(key.public_key())

    @classmethod
    def from_files(cls, key_path, public_path, principal):
        # Read the very descriptor we inspect, never reopen after checking it.
        if not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'geteuid'):
            raise ValueError('secure local owner-key loading requires POSIX file checks')
        descriptor = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError('policy owner key must be an owned regular file with mode 0600 or stricter')
            data = source.read(4097)
        if len(data) > 4096:
            raise ValueError('invalid policy owner key size')
        key = serialization.load_pem_private_key(data, password=None)
        from pathlib import Path
        pin = Ed25519PublicKey.from_public_bytes(decode(Path(public_path).read_text().strip()))
        if not isinstance(key, Ed25519PrivateKey) or identity_id(key.public_key()) != identity_id(pin):
            raise ValueError('policy owner key does not match public pin')
        return cls(key, principal)

    def bind(self, db):
        db.execute('CREATE TABLE IF NOT EXISTS ui_policy_authority (id INTEGER PRIMARY KEY CHECK(id=1), owner TEXT NOT NULL, principal TEXT NOT NULL)')
        saved = db.execute('SELECT owner,principal FROM ui_policy_authority WHERE id=1').fetchone()
        if saved is not None and saved != (self.owner, self.principal):
            raise AdmissionError('cannot change persisted policy authority or human principal')
        db.execute('INSERT OR IGNORE INTO ui_policy_authority VALUES(1,?,?)', (self.owner, self.principal))
        db.execute('CREATE TABLE IF NOT EXISTS ui_group_policies (group_id TEXT PRIMARY KEY, token TEXT NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS ui_policy_requests (group_id TEXT NOT NULL, request_id TEXT NOT NULL, payload TEXT NOT NULL, result TEXT NOT NULL, PRIMARY KEY(group_id,request_id))')
        db.execute('CREATE TABLE IF NOT EXISTS ui_policy_events (id INTEGER PRIMARY KEY, group_id TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL, revision INTEGER NOT NULL, policy_hash TEXT NOT NULL, created REAL NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS ui_retired_grants (group_id TEXT NOT NULL, jti TEXT NOT NULL, PRIMARY KEY(group_id,jti))')
        db.execute('CREATE TABLE IF NOT EXISTS ui_grant_issuances (group_id TEXT NOT NULL, request_id TEXT NOT NULL, payload TEXT NOT NULL, claims TEXT NOT NULL, grant_hash TEXT NOT NULL, created REAL NOT NULL, PRIMARY KEY(group_id,request_id))')
        db.execute('CREATE TABLE IF NOT EXISTS ui_policy_deliveries (group_id TEXT NOT NULL, request_id TEXT NOT NULL, payload TEXT NOT NULL, target TEXT NOT NULL, revision INTEGER NOT NULL, policy_hash TEXT NOT NULL, outcome TEXT NOT NULL, receipt TEXT, updated REAL NOT NULL, PRIMARY KEY(group_id,request_id))')
        for group_id, token in db.execute('SELECT group_id,token FROM ui_group_policies'):
            claims = verify_policy(token, self.key.public_key(), group_id)
            group = db.execute('SELECT name,creator,dissolved FROM chat_groups WHERE id=?', (group_id,)).fetchone()
            if group != (claims['name'], self.principal, int(claims['state'] == 'dissolved')):
                raise AdmissionError('signed policy and local group state disagree')

    def require_actor(self, actor):
        if actor != self.principal:
            raise PermissionError('configured policy administrator required')

    def current(self, db, group_id):
        row = db.execute('SELECT token FROM ui_group_policies WHERE group_id=?', (group_id,)).fetchone()
        if row is None:
            raise ValueError('this local group has no signed policy')
        return row[0], verify_policy(row[0], self.key.public_key(), group_id)

    def _save(self, db, group_id, token, action, subject):
        policy = verify_policy(token, self.key.public_key(), group_id)
        digest = hashlib.sha256(token.encode()).hexdigest()
        db.execute('INSERT INTO ui_group_policies VALUES(?,?) ON CONFLICT(group_id) DO UPDATE SET token=excluded.token', (group_id, token))
        db.execute('INSERT INTO ui_policy_events(group_id,actor,action,subject,revision,policy_hash,created) VALUES(?,?,?,?,?,?,?)',
                   (group_id, self.principal, action, subject, policy['revision'], digest, self.clock()))
        return {'revision': policy['revision'], 'policy_hash': digest, 'state': policy['state']}

    def create(self, db, name):
        token = create_policy(self.key, name, {}, now=int(self.clock()))
        group_id = verify(token, self.key.public_key(), POLICY_TYPE)['group_id']
        self._save(db, group_id, token, 'create', group_id)
        return group_id

    def export(self, db, group_id):
        token, policy = self.current(db, group_id)
        events = db.execute('SELECT actor,action,subject,revision,policy_hash,created FROM ui_policy_events WHERE group_id=? ORDER BY id DESC LIMIT 50', (group_id,)).fetchall()
        return {'group_id': group_id, 'owner_public_key': encode(public_bytes(self.key.public_key())),
                'policy': token, 'policy_hash': hashlib.sha256(token.encode()).hexdigest(), 'claims': policy,
                'audit': [dict(zip(('actor', 'action', 'subject', 'revision', 'policy_hash', 'created'), row)) for row in reversed(events)]}

    def preview(self, db, group_id, grant):
        _, policy = self.current(db, group_id)
        if policy['state'] != 'active':
            raise PermissionError('signed group is dissolved')
        claims = verify_grant(grant, self.key.public_key(), group_id, now=self.clock())
        if db.execute('SELECT 1 FROM ui_retired_grants WHERE group_id=? AND jti=?', (group_id, claims['jti'])).fetchone():
            raise AdmissionError('removed credentials cannot be reapproved; issue a new grant')
        existing = policy['members'].get(claims['sub'], {'permissions': [], 'grant_ids': []})
        proposed = {'permissions': sorted(set(existing['permissions']) | set(claims['permissions'])),
                    'grant_ids': sorted(set(existing['grant_ids']) | {claims['jti']})}
        return {'subject': claims['sub'], 'grant_id': claims['jti'], 'expires_at': claims['exp'],
                'permissions': claims['permissions'], 'proposed_member': proposed, 'revision': policy['revision']}

    def change(self, db, group_id, operation, payload):
        expected = {'request_id', 'expected_revision'} | ({'grant'} if operation == 'approve' else {'subject'} if operation == 'remove' else set())
        if operation not in ('approve', 'remove', 'renew') or set(payload) != expected:
            raise ValueError('invalid policy operation fields')
        request_id, revision = payload['request_id'], payload['expected_revision']
        if not isinstance(request_id, str) or not 1 <= len(request_id) <= 128 or type(revision) is not int or revision < 1:
            raise ValueError('request ID and expected revision required')
        canonical = payload | {'operation': operation}
        if operation == 'approve':
            if not isinstance(payload['grant'], str):
                raise ValueError('signed grant required')
            canonical['grant'] = hashlib.sha256(payload['grant'].encode()).hexdigest()
        canonical = json.dumps(canonical, sort_keys=True)
        previous = db.execute('SELECT payload,result FROM ui_policy_requests WHERE group_id=? AND request_id=?', (group_id, request_id)).fetchone()
        if previous:
            if previous[0] != canonical:
                raise FileExistsError('policy request ID reused with changed payload')
            return json.loads(previous[1])
        token, policy = self.current(db, group_id)
        if policy['state'] != 'active':
            raise PermissionError('signed group is dissolved')
        if revision != policy['revision']:
            raise FileExistsError('policy changed; refresh and confirm the current revision')
        members = policy['members'].copy()
        subject = group_id
        if operation == 'approve':
            preview = self.preview(db, group_id, payload['grant'])
            subject = preview['subject']
            if preview['grant_id'] in members.get(subject, {}).get('grant_ids', []):
                raise ValueError('grant is already approved')
            members[subject] = preview['proposed_member']
        elif operation == 'remove':
            subject = payload['subject']
            if not isinstance(subject, str) or subject not in members:
                raise ValueError('select an existing signed member')
            removed = members.pop(subject)
            db.executemany('INSERT OR IGNORE INTO ui_retired_grants VALUES(?,?)', [(group_id, jti) for jti in removed['grant_ids']])
        updated = revise_policy(self.key, token, members, now=int(self.clock()))
        result = self._save(db, group_id, updated, operation, subject)
        db.execute('INSERT INTO ui_policy_requests VALUES(?,?,?,?)', (group_id, request_id, canonical, json.dumps(result)))
        return result

    def dissolve(self, db, group_id):
        token, policy = self.current(db, group_id)
        if policy['state'] != 'dissolved':
            updated = revise_policy(self.key, token, {}, dissolve=True, now=int(self.clock()))
            self._save(db, group_id, updated, 'dissolve', group_id)
