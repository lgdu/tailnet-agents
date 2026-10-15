"""Opt-in signed group/direct text at one explicitly configured history store."""
import hashlib
import json
import re
import time

from .identity import AdmissionError, identity_id, sign, verify, verify_grant

MESSAGE_TYPE = 'tailnet-agent-message+jwt'
MAX_COUNTER = 2**53 - 1


def subject_id(value):
    return isinstance(value, str) and re.fullmatch(r'ed25519:[a-f0-9]{64}', value) is not None


def message_id(value):
    return isinstance(value, str) and re.fullmatch(r'[a-f0-9]{32}', value) is not None


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def conversation_id(owner, group, sender, recipient):
    parties = [] if recipient is None else sorted({sender, recipient})
    return digest(json.dumps([owner, group, 'group' if recipient is None else 'direct', parties], separators=(',', ':')))


def verify_message(token, key, owner, group, audience, *, now=None):
    claim = verify(token, key, MESSAGE_TYPE)
    fields = {'version', 'owner', 'group_id', 'audience', 'sender', 'recipient', 'message_id',
              'conversation_id', 'reply_to', 'kind', 'text', 'created_at'}
    if (set(claim) != fields or type(claim['version']) is not int or claim['version'] != 1 or
            claim['owner'] != identity_id(owner) or claim['group_id'] != group or claim['audience'] != audience or
            claim['sender'] != identity_id(key) or
            (claim['recipient'] is not None and not subject_id(claim['recipient'])) or
            not message_id(claim['message_id']) or
            (claim['reply_to'] is not None and not message_id(claim['reply_to'])) or
            claim['kind'] != 'text' or not isinstance(claim['text'], str) or
            not 1 <= len(claim['text'].encode('utf-8')) <= 4096 or not claim['text'].strip() or
            type(claim['created_at']) is not int or not 0 <= claim['created_at'] <= MAX_COUNTER or
            (now is not None and claim['created_at'] > now + 30)):
        raise AdmissionError('invalid signed message context or schema')
    expected = conversation_id(claim['owner'], group, claim['sender'], claim['recipient'])
    if claim['conversation_id'] != expected:
        raise AdmissionError('wrong conversation')
    return claim


def make_message(key, owner, group, audience, text, mid, *, recipient=None, reply_to=None, now=None):
    sender = identity_id(key.public_key())
    claims = {'version': 1, 'owner': identity_id(owner), 'group_id': group, 'audience': audience,
              'sender': sender, 'recipient': recipient, 'message_id': mid,
              'conversation_id': conversation_id(identity_id(owner), group, sender, recipient),
              'reply_to': reply_to, 'kind': 'text', 'text': text,
              'created_at': int(time.time()) if now is None else now}
    token = sign(key, claims, MESSAGE_TYPE)
    verify_message(token, key.public_key(), owner, group, audience)
    return token


def validate_request(request):
    if not isinstance(request, dict):
        raise ValueError('message operation required')
    if request.get('operation') == 'send':
        if set(request) != {'operation', 'message'} or not isinstance(request['message'], str) or len(request['message']) > 16384:
            raise ValueError('invalid send operation')
    elif request.get('operation') == 'read':
        if (set(request) != {'operation', 'scope', 'peer', 'after', 'limit'} or
                request['scope'] not in ('group', 'direct') or
                (request['peer'] is not None if request['scope'] == 'group' else not subject_id(request['peer'])) or
                type(request['after']) is not int or not 0 <= request['after'] <= MAX_COUNTER or
                type(request['limit']) is not int or not 1 <= request['limit'] <= 20):
            raise ValueError('invalid read operation')
    else:
        raise ValueError('unknown message operation')
    return 'messages-v1:' + digest(json.dumps(request, sort_keys=True, separators=(',', ':'), allow_nan=False))


class MessageStore:
    """Uses the directory lock, policy/revocations and private SQLite transaction.

    This designated store is trusted with plaintext. No relay, executor, group
    creation, auto reply, presence lease or directory credential read path exists.
    """
    def __init__(self, directory):
        if not directory.require_policy:
            raise ValueError('messages require signed policy mode')
        self.directory = directory
        self.db = directory._registry.db
        with directory.lock, self.db:
            self.db.execute('CREATE TABLE IF NOT EXISTS network_message_context (id INTEGER PRIMARY KEY CHECK(id=1),audience TEXT NOT NULL)')
            previous = self.db.execute('SELECT audience FROM network_message_context WHERE id=1').fetchone()
            if previous and previous[0] != directory._admission.audience:
                raise AdmissionError('cannot replace original message service audience')
            self.db.execute('INSERT OR IGNORE INTO network_message_context VALUES(1,?)', (directory._admission.audience,))
            self.db.execute('CREATE TABLE IF NOT EXISTS network_messages (sequence INTEGER PRIMARY KEY AUTOINCREMENT,message_id TEXT UNIQUE NOT NULL,sender TEXT NOT NULL,recipient TEXT,conversation TEXT NOT NULL,token TEXT NOT NULL,public_key TEXT NOT NULL,stored_at REAL NOT NULL)')
            self.db.execute('CREATE INDEX IF NOT EXISTS network_conversation ON network_messages(conversation,sequence)')

    def challenge(self, request):
        context = validate_request(request)
        with self.directory.lock:
            return {'nonce': self.directory._admission.challenge(context), 'context': context}

    def execute(self, request, grant, key, proof, nonce):
        context = validate_request(request)
        directory = self.directory
        with directory.lock:
            claim = None
            if request['operation'] == 'send':
                claim = verify_message(request['message'], key, directory.owner_key, directory.group_id,
                                       directory._admission.audience, now=directory.clock())
                scope = 'group' if claim['recipient'] is None else 'direct'
            else:
                scope = request['scope']
            permission = 'chat.' + scope
            credential = verify_grant(grant, directory.owner_key, directory.group_id, permission,
                                      now=directory.clock(), revoked=directory._admission.revoked)
            policy = directory._policy.authorize(credential)
            directory._admission.admit(grant, key, proof, nonce, permission=permission, context=context)
            if claim is not None:
                recipient = claim['recipient']
                if recipient is not None:
                    member = policy['members'].get(recipient)
                    if (member is None or permission not in member['permissions'] or
                            not set(member['grant_ids']) - directory._admission.revoked):
                        raise AdmissionError('recipient not authorized by current policy')
                return self._store(request['message'], key, claim)
            return self._read(credential['sub'], request)

    def _store(self, token, key, claim):
        from .identity import encode, public_bytes
        with self.db:
            old = self.db.execute('SELECT token,sequence FROM network_messages WHERE message_id=?', (claim['message_id'],)).fetchone()
            if old:
                if old[0] != token:
                    raise FileExistsError('message id conflict')
                sequence = old[1]
            else:
                if claim['reply_to'] is not None:
                    parent = self.db.execute('SELECT conversation FROM network_messages WHERE message_id=?', (claim['reply_to'],)).fetchone()
                    if parent is None or parent[0] != claim['conversation_id']:
                        raise AdmissionError('reply must reference the same stored conversation')
                sequence = self.db.execute('INSERT INTO network_messages(message_id,sender,recipient,conversation,token,public_key,stored_at) VALUES(?,?,?,?,?,?,?)',
                    (claim['message_id'], claim['sender'], claim['recipient'], claim['conversation_id'], token,
                     encode(public_bytes(key)), self.directory.clock())).lastrowid
                if sequence > MAX_COUNTER:
                    raise ValueError('message sequence exhausted')
        # ACK only after commit, including when a previous response was lost.
        return {'state': 'stored', 'message_id': claim['message_id'], 'sequence': sequence, 'message_hash': digest(token)}

    def _read(self, subject, request):
        directory = self.directory
        conversation = conversation_id(identity_id(directory.owner_key), directory.group_id, subject, request['peer'])
        rows = self.db.execute('SELECT sequence,token,public_key,stored_at FROM network_messages WHERE conversation=? AND sequence>? ORDER BY sequence LIMIT ?',
                               (conversation, request['after'], request['limit'] + 1)).fetchall()
        entries = [dict(zip(('sequence', 'message', 'public_key', 'stored_at'), row)) for row in rows[:request['limit']]]
        return {'owner': identity_id(directory.owner_key), 'group_id': directory.group_id,
                'audience': directory._admission.audience, 'conversation_id': conversation,
                'after': request['after'], 'next_after': entries[-1]['sequence'] if entries else request['after'],
                'has_more': len(rows) > request['limit'], 'messages': entries}
