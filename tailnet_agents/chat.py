"""Persistent multi-human chat demo with simulated agents, not a mesh chat service."""
import json
import sqlite3
import threading
import time
from pathlib import Path

AGENTS = {'moderator': 'Moderator', 'coder': 'Coder', 'researcher': 'Researcher'}


class ChatStore:
    def __init__(self, database=':memory:'):
        if database != ':memory:':
            Path(database).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(database, check_same_thread=False)
        if database != ':memory:':
            Path(database).chmod(0o600)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, conversation TEXT NOT NULL, sender TEXT NOT NULL, text TEXT NOT NULL, created REAL NOT NULL)')
        columns = {row[1] for row in self.db.execute('PRAGMA table_info(messages)')}
        if 'owner' not in columns:
            self.db.execute("ALTER TABLE messages ADD COLUMN owner TEXT NOT NULL DEFAULT 'demo-owner'")
        self.db.execute('CREATE TABLE IF NOT EXISTS submissions (request_id TEXT PRIMARY KEY, payload TEXT NOT NULL, result TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS user_submissions (owner TEXT NOT NULL, request_id TEXT NOT NULL, payload TEXT NOT NULL, result TEXT NOT NULL, PRIMARY KEY(owner, request_id))')
        # Legacy single-user conversations belong exclusively to demo-owner.
        self.db.execute("INSERT OR IGNORE INTO user_submissions SELECT 'demo-owner',request_id,payload,result FROM submissions")
        self.db.execute('CREATE INDEX IF NOT EXISTS messages_scope ON messages(conversation,owner,id)')
        self.db.commit()
        self.lock = threading.Lock()
        self.online = set(AGENTS)

    @staticmethod
    def conversation(value):
        if value != 'group' and value not in {'dm:' + agent for agent in AGENTS}:
            raise ValueError('unknown conversation')
        return value

    def page(self, conversation, principal="demo-owner", *, after=None, before=None, limit=100):
        self.conversation(conversation)
        if after is not None and before is not None:
            raise ValueError('after and before are mutually exclusive')
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError('limit must be 1..200')
        if any(value is not None and (type(value) is not int or not 0 <= value <= 2**63-1)
               for value in (after, before)):
            raise ValueError('invalid message cursor')
        clauses, values = ['conversation=?'], [conversation]
        if conversation != 'group':
            clauses.append('owner=?')
            values.append(principal)
        if after is not None:
            clauses.append('id > ?')
            values.append(after)
        if before is not None:
            clauses.append('id < ?')
            values.append(before)
        order = 'ASC' if after is not None else 'DESC'
        values.append(limit + 1)
        with self.lock:
            rows = self.db.execute('SELECT id,sender,text,created,owner FROM messages WHERE '
                                   + ' AND '.join(clauses) + ' ORDER BY id ' + order + ' LIMIT ?', values).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        if after is None:
            rows.reverse()
        return {'messages': [{'id': r[0], 'sender': r[1], 'text': r[2], 'created': r[3],
                              'author': r[4] if r[1] == 'human' else r[1]} for r in rows],
                'has_more': has_more}

    def history(self, conversation, principal="demo-owner"):
        return self.page(conversation, principal, limit=200)['messages']

    def members(self):
        with self.lock:
            return [{'id': k, 'name': v, 'online': k in self.online, 'simulated': True} for k, v in AGENTS.items()]

    def set_online(self, agent, online):
        if agent not in AGENTS or type(online) is not bool:
            raise ValueError('invalid member update')
        with self.lock:
            if online:
                self.online.add(agent)
            else:
                self.online.discard(agent)

    def send(self, payload, principal="demo-owner"):
        if set(payload) - {'conversation', 'text', 'request_id', 'targets'}:
            raise ValueError('unknown message fields')
        conversation = self.conversation(payload.get('conversation'))
        text, request_id = payload.get('text'), payload.get('request_id')
        targets = payload.get('targets', [])
        if not isinstance(text, str) or not 1 <= len(text.strip()) <= 8000:
            raise ValueError('message must contain 1..8000 characters')
        if not isinstance(request_id, str) or not 1 <= len(request_id) <= 128:
            raise ValueError('invalid request id')
        if not isinstance(targets, list) or len(targets) > len(AGENTS) or any(t not in AGENTS for t in targets):
            raise ValueError('invalid recipients')
        if conversation.startswith('dm:'):
            targets = [conversation[3:]]
        else:
            targets = sorted(set(targets)) or ['moderator']
        canonical = json.dumps({'conversation': conversation, 'text': text, 'targets': targets}, sort_keys=True)
        with self.lock, self.db:
            self.db.execute('BEGIN IMMEDIATE')
            old = self.db.execute('SELECT payload,result FROM user_submissions WHERE owner=? AND request_id=?', (principal, request_id)).fetchone()
            if old:
                if old[0] != canonical:
                    raise FileExistsError('request id reused with changed message')
                return json.loads(old[1])
            created = time.time()
            cursor = self.db.execute('INSERT INTO messages(conversation,sender,text,created,owner) VALUES(?,?,?,?,?)', (conversation, 'human', text, created, principal))
            replies, skipped = [], []
            for target in targets:
                if target not in self.online:
                    skipped.append(target)
                    continue
                # Exactly one deterministic reply; agent replies never trigger other agents.
                reply = f'[{AGENTS[target]} · simulated] Received: {text}'
                row = self.db.execute('INSERT INTO messages(conversation,sender,text,created,owner) VALUES(?,?,?,?,?)', (conversation, target, reply, created, principal))
                replies.append(row.lastrowid)
            result = {'message_id': cursor.lastrowid, 'reply_ids': replies, 'offline_targets': skipped}
            self.db.execute('INSERT INTO user_submissions VALUES(?,?,?,?)', (principal, request_id, canonical, json.dumps(result)))
            return result

    def close(self):
        with self.lock:
            self.db.close()
