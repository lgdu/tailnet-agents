"""Synthetic-identity messaging CLI with durable outbox and catch-up cursors."""
import argparse
import fcntl
import json
import math
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import threading
import time
from urllib.error import URLError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .client import Client
from .discovery import origin
from .identity import (AdmissionError, GRANT_TYPE, decode, encode, identity_id, load_identity,
                       prove_possession, public_bytes, verify, verify_grant)
from .network_messages import (MAX_COUNTER, conversation_id, digest, make_message,
                               validate_request, verify_message)


class MessageClient:
    """One private state file per key and designated service; no automatic failover.

    All methods serialize local state and network operations. An interrupted send
    remains pending and retries the original envelope. Accepted means committed
    by the configured store, never read/executed by a recipient.
    """
    def __init__(self, url, key, owner, grant, group, audience, state, *, ca_file=None, clock=time.time):
        if not isinstance(audience, str) or not 1 <= len(audience) <= 128:
            raise ValueError('explicit service audience required')
        claim = verify(grant, owner, GRANT_TYPE)
        if type(claim.get('iat')) is not int:
            raise AdmissionError('invalid saved grant')
        verify_grant(grant, owner, group, now=claim['iat'])
        self.subject = identity_id(key.public_key())
        if claim['sub'] != self.subject or self.subject == identity_id(owner):
            raise AdmissionError('existing Agent key must match grant and differ from owner')
        self.http = Client(origin(url), '', ca_file=ca_file, timeout=5)
        self.key, self.owner, self.grant, self.group, self.audience = key, owner, grant, group, audience
        self.clock, self.lock = clock, threading.Lock()
        self.db = self.descriptor = None
        path = Path(state)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(self.descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError('message state must be an owned private regular file')
            fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.db = sqlite3.connect(path, check_same_thread=False)
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            ca_hash = None if ca_file is None else digest(Path(ca_file).read_text())
            context = json.dumps([identity_id(owner), group, self.subject, self.http.url, audience, ca_hash])
            with self.db:
                self.db.execute('CREATE TABLE IF NOT EXISTS message_context (id INTEGER PRIMARY KEY CHECK(id=1),context TEXT NOT NULL)')
                old = self.db.execute('SELECT context FROM message_context WHERE id=1').fetchone()
                if old and old[0] != context:
                    raise AdmissionError('cannot replace original message identity/group/service/CA')
                self.db.execute('INSERT OR IGNORE INTO message_context VALUES(1,?)', (context,))
                self.db.execute('CREATE TABLE IF NOT EXISTS message_outbox (position INTEGER PRIMARY KEY AUTOINCREMENT,message_id TEXT UNIQUE NOT NULL,token TEXT NOT NULL,state TEXT NOT NULL,receipt TEXT)')
                self.db.execute('CREATE TABLE IF NOT EXISTS message_inbox (sequence INTEGER PRIMARY KEY,message_id TEXT UNIQUE NOT NULL,conversation TEXT NOT NULL,entry TEXT NOT NULL)')
                self.db.execute('CREATE TABLE IF NOT EXISTS message_cursors (conversation TEXT PRIMARY KEY,after INTEGER NOT NULL)')
        except BaseException:
            self.close()
            raise

    def _request(self, request):
        context = validate_request(request)
        scope = request.get('scope')
        if scope is None:
            claim = verify_message(request['message'], self.key.public_key(), self.owner, self.group, self.audience)
            scope = 'group' if claim['recipient'] is None else 'direct'
        verify_grant(self.grant, self.owner, self.group, 'chat.' + scope, now=self.clock())
        challenge = self.http.request('/v1/messages/challenges', {'request': request})
        if (not isinstance(challenge, dict) or set(challenge) != {'nonce', 'context'} or
                not isinstance(challenge['nonce'], str) or not 1 <= len(challenge['nonce']) <= 128 or
                challenge['context'] != context):
            raise ValueError('challenge does not bind this operation')
        proof = prove_possession(self.key, self.grant, challenge['nonce'], self.audience, context=context)
        return self.http.request('/v1/messages', {'request': request, 'grant': self.grant,
            'public_key': encode(public_bytes(self.key.public_key())), 'nonce': challenge['nonce'], 'proof': proof})

    def queue(self, text, *, recipient=None, reply_to=None):
        with self.lock:
            mid = secrets.token_hex(16)
            token = make_message(self.key, self.owner, self.group, self.audience, text, mid,
                                 recipient=recipient, reply_to=reply_to, now=int(self.clock()))
            with self.db:
                self.db.execute('INSERT INTO message_outbox(message_id,token,state) VALUES(?,?,?)', (mid, token, 'pending'))
            return {'message_id': mid, 'state': 'pending'}

    def flush(self, limit=20):
        if type(limit) is not int or not 1 <= limit <= 20:
            raise ValueError('flush limit must be 1..20')
        with self.lock:
            rows = self.db.execute("SELECT message_id,token FROM message_outbox WHERE state='pending' ORDER BY position LIMIT ?", (limit,)).fetchall()
            results = []
            for mid, token in rows:
                result = self._request({'operation': 'send', 'message': token})
                if (not isinstance(result, dict) or set(result) != {'state', 'message_id', 'sequence', 'message_hash'} or
                        result['state'] != 'stored' or result['message_id'] != mid or result['message_hash'] != digest(token) or
                        type(result['sequence']) is not int or not 1 <= result['sequence'] <= MAX_COUNTER):
                    raise ValueError('invalid storage acknowledgment')
                with self.db:
                    self.db.execute("UPDATE message_outbox SET state='stored',receipt=? WHERE message_id=?", (json.dumps(result), mid))
                results.append(result)
            return results

    def _conversation(self, scope, peer):
        # Reuse strict scope/peer validation even for local history.
        validate_request({'operation': 'read', 'scope': scope, 'peer': peer, 'after': 0, 'limit': 20})
        return conversation_id(identity_id(self.owner), self.group, self.subject, peer)

    def sync(self, scope='group', *, peer=None, limit=20):
        with self.lock:
            conversation = self._conversation(scope, peer)
            row = self.db.execute('SELECT after FROM message_cursors WHERE conversation=?', (conversation,)).fetchone()
            after = 0 if row is None else row[0]
            request = {'operation': 'read', 'scope': scope, 'peer': peer, 'after': after, 'limit': limit}
            page = self._request(request)
            entries = self._validate_page(page, request, conversation)
            with self.db:
                for entry, claim in entries:
                    existing = self.db.execute('SELECT entry FROM message_inbox WHERE sequence=? OR message_id=?', (entry['sequence'], claim['message_id'])).fetchall()
                    serialized = json.dumps(entry, sort_keys=True)
                    if existing and (len(existing) != 1 or existing[0][0] != serialized):
                        raise ValueError('conflicting saved message')
                    self.db.execute('INSERT OR IGNORE INTO message_inbox VALUES(?,?,?,?)', (entry['sequence'], claim['message_id'], conversation, serialized))
                self.db.execute('INSERT INTO message_cursors VALUES(?,?) ON CONFLICT(conversation) DO UPDATE SET after=excluded.after', (conversation, page['next_after']))
            return {'messages': [claim | {'sequence': entry['sequence'], 'stored_at': entry['stored_at']} for entry, claim in entries],
                    'next_after': page['next_after'], 'has_more': page['has_more']}

    def _validate_page(self, page, request, conversation):
        if (not isinstance(page, dict) or set(page) != {'owner', 'group_id', 'audience', 'conversation_id', 'after', 'next_after', 'has_more', 'messages'} or
                page['owner'] != identity_id(self.owner) or page['group_id'] != self.group or
                page['audience'] != self.audience or page['conversation_id'] != conversation or
                type(page['after']) is not int or page['after'] != request['after'] or
                type(page['next_after']) is not int or type(page['has_more']) is not bool or
                not isinstance(page['messages'], list) or len(page['messages']) > request['limit']):
            raise ValueError('invalid history page context')
        entries, seen, previous = [], set(), request['after']
        for entry in page['messages']:
            if (not isinstance(entry, dict) or set(entry) != {'sequence', 'message', 'public_key', 'stored_at'} or
                    type(entry['sequence']) is not int or not previous < entry['sequence'] <= MAX_COUNTER or
                    type(entry['stored_at']) not in (int, float) or not math.isfinite(entry['stored_at']) or entry['stored_at'] < 0):
                raise ValueError('invalid history entry')
            key = Ed25519PublicKey.from_public_bytes(decode(entry['public_key']))
            claim = verify_message(entry['message'], key, self.owner, self.group, self.audience)
            if (claim['conversation_id'] != conversation or claim['message_id'] in seen or
                    (request['scope'] == 'direct' and self.subject not in (claim['sender'], claim['recipient']))):
                raise ValueError('wrong history conversation or participant')
            seen.add(claim['message_id'])
            entries.append((entry, claim))
            previous = entry['sequence']
        if page['next_after'] != previous or (page['has_more'] and len(entries) != request['limit']):
            raise ValueError('invalid history cursor')
        return entries

    def history(self, scope='group', *, peer=None):
        with self.lock:
            conversation = self._conversation(scope, peer)
            entries = self.db.execute('SELECT entry FROM message_inbox WHERE conversation=? ORDER BY sequence DESC LIMIT 100', (conversation,)).fetchall()
            result = []
            for row in reversed(entries):
                entry = json.loads(row[0])
                key = Ed25519PublicKey.from_public_bytes(decode(entry['public_key']))
                claim = verify_message(entry['message'], key, self.owner, self.group, self.audience)
                result.append(claim | {'sequence': entry['sequence'], 'stored_at': entry['stored_at']})
            return result

    def status(self):
        with self.lock:
            return dict(self.db.execute('SELECT state,COUNT(*) FROM message_outbox GROUP BY state'))

    def close(self):
        with self.lock:
            if self.db is not None:
                self.db.close()
                self.db = None
            if self.descriptor is not None:
                os.close(self.descriptor)
                self.descriptor = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--agent-key', required=True)
    parser.add_argument('--authority-public-key', required=True)
    parser.add_argument('--grant-file', required=True)
    parser.add_argument('--group-id', required=True)
    parser.add_argument('--audience', required=True)
    parser.add_argument('--state', required=True, help='private messaging SQLite file; distinct from heartbeat state')
    parser.add_argument('--ca-cert')
    sub = parser.add_subparsers(dest='command', required=True)
    queue = sub.add_parser('queue', help='persist text without any network request')
    queue.add_argument('--text-file', required=True)
    queue.add_argument('--recipient', help='Agent public-key identity; omit for group chat')
    queue.add_argument('--reply-to')
    flush = sub.add_parser('flush', help='retry pending messages only at the original service')
    flush.add_argument('--limit', type=int, default=20)
    for name in ('sync', 'history'):
        command = sub.add_parser(name)
        command.add_argument('--scope', choices=('group', 'direct'), default='group')
        command.add_argument('--peer', help='required for a direct conversation')
        if name == 'sync':command.add_argument('--limit', type=int, default=20)
    sub.add_parser('status')
    args = parser.parse_args()
    client = None
    try:
        owner = Ed25519PublicKey.from_public_bytes(decode(Path(args.authority_public_key).read_text().strip()))
        client = MessageClient(args.url, load_identity(args.agent_key), owner, Path(args.grant_file).read_text().strip(),
                               args.group_id, args.audience, args.state, ca_file=args.ca_cert)
        if args.command == 'queue':
            with Path(args.text_file).open() as source:text = source.read(4097)
            result = client.queue(text, recipient=args.recipient, reply_to=args.reply_to)
        elif args.command == 'flush':result = client.flush(args.limit)
        elif args.command == 'sync':result = client.sync(args.scope, peer=args.peer, limit=args.limit)
        elif args.command == 'history':result = client.history(args.scope, peer=args.peer)
        else:result = client.status()
    except (ValueError, TypeError, KeyError, OSError, URLError, sqlite3.Error):
        parser.exit(1, 'Messaging failed; retain original identity/group/service/state. Pending messages and catch-up cursor are preserved; check authorization, conflicts and connectivity.\n')
    finally:
        if client is not None:client.close()
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
