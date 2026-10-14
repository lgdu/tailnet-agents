"""Persistent multi-human chat demo with simulated agents, not a mesh chat service."""
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path

AGENTS = {'moderator': 'Moderator', 'coder': 'Coder', 'researcher': 'Researcher'}


class ChatStore:
    def __init__(self, database=':memory:', *, policy_authority=None):
        if database != ':memory:':
            Path(database).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(database, check_same_thread=False)
        if database != ':memory:':
            Path(database).chmod(0o600)
        self.db.execute('PRAGMA journal_mode=WAL')
        had_messages = self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='messages'").fetchone() is not None
        self.db.execute('CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, conversation TEXT NOT NULL, sender TEXT NOT NULL, text TEXT NOT NULL, created REAL NOT NULL)')
        columns = {row[1] for row in self.db.execute('PRAGMA table_info(messages)')}
        if 'owner' not in columns:
            self.db.execute("ALTER TABLE messages ADD COLUMN owner TEXT NOT NULL DEFAULT 'demo-owner'")
        self.db.execute('CREATE TABLE IF NOT EXISTS submissions (request_id TEXT PRIMARY KEY, payload TEXT NOT NULL, result TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS user_submissions (owner TEXT NOT NULL, request_id TEXT NOT NULL, payload TEXT NOT NULL, result TEXT NOT NULL, PRIMARY KEY(owner, request_id))')
        # Legacy single-user conversations belong exclusively to demo-owner.
        self.db.execute("INSERT OR IGNORE INTO user_submissions SELECT 'demo-owner',request_id,payload,result FROM submissions")
        columns = {row[1] for row in self.db.execute('PRAGMA table_info(messages)')}
        if 'group_id' not in columns:
            self.db.execute("ALTER TABLE messages ADD COLUMN group_id TEXT NOT NULL DEFAULT 'legacy'")
        self.db.execute('CREATE TABLE IF NOT EXISTS chat_groups (id TEXT PRIMARY KEY, name TEXT NOT NULL, creator TEXT NOT NULL, created REAL NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS group_humans (group_id TEXT NOT NULL, principal TEXT NOT NULL, PRIMARY KEY(group_id,principal))')
        self.db.execute('CREATE TABLE IF NOT EXISTS group_submissions (group_id TEXT NOT NULL, owner TEXT NOT NULL, request_id TEXT NOT NULL, payload TEXT NOT NULL, result TEXT NOT NULL, PRIMARY KEY(group_id,owner,request_id))')
        self.db.execute("INSERT OR IGNORE INTO group_submissions SELECT 'legacy',owner,request_id,payload,result FROM user_submissions")
        self.db.execute('CREATE TABLE IF NOT EXISTS migrations (name TEXT PRIMARY KEY)')
        legacy_done = self.db.execute("SELECT 1 FROM migrations WHERE name='legacy-group-import'").fetchone()
        # Restore existing predefined-group history; a fresh installation has NO groups.
        if not legacy_done and had_messages and self.db.execute("SELECT 1 FROM messages WHERE group_id='legacy' LIMIT 1").fetchone():
            self.db.execute("INSERT OR IGNORE INTO chat_groups VALUES('legacy','旧版协作组','demo-owner',0)")
            self.db.execute("INSERT OR IGNORE INTO group_humans SELECT 'legacy',owner FROM messages WHERE group_id='legacy'")
            self.db.execute("INSERT OR IGNORE INTO group_humans VALUES('legacy','demo-owner')")
        self.db.execute("INSERT OR IGNORE INTO migrations VALUES('legacy-group-import')")
        columns = {r[1] for r in self.db.execute('PRAGMA table_info(chat_groups)')}
        if 'dissolved' not in columns:
            self.db.execute('ALTER TABLE chat_groups ADD COLUMN dissolved INTEGER NOT NULL DEFAULT 0')
        self.db.execute('CREATE TABLE IF NOT EXISTS group_creations (creator TEXT NOT NULL, request_id TEXT NOT NULL, payload TEXT NOT NULL, group_id TEXT NOT NULL, PRIMARY KEY(creator,request_id))')
        self.db.execute('CREATE TABLE IF NOT EXISTS group_audit (id INTEGER PRIMARY KEY, group_id TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL, created REAL NOT NULL)')
        self.db.execute('CREATE INDEX IF NOT EXISTS messages_group_scope ON messages(group_id,conversation,owner,id)')
        self.policy_authority = policy_authority
        try:
            configured = self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ui_policy_authority'").fetchone()
            if configured and self.db.execute('SELECT 1 FROM ui_policy_authority').fetchone() and policy_authority is None:
                raise ValueError('restart requires the original policy authority configuration')
            if policy_authority is not None:
                policy_authority.bind(self.db)
            self.db.commit()
        except Exception:
            self.db.rollback()
            self.db.close()
            raise
        self.lock = threading.Lock()
        self.online = set(AGENTS)

    def audit(self, group_id, actor, action, subject):
        self.db.execute('INSERT INTO group_audit(group_id,actor,action,subject,created) VALUES(?,?,?,?,?)', (group_id,actor,action,subject,time.time()))

    def create_group(self, name, creator, humans, group_id=None, request_id=None, *, signed_policy=False):
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
            raise ValueError('group name must be 1..80 characters')
        if not isinstance(humans, list) or len(humans) > 100 or any(not isinstance(h, str) or not h for h in humans):
            raise ValueError('invalid human members')
        if request_id is not None and (not isinstance(request_id,str) or not 1 <= len(request_id) <= 128):
            raise ValueError('invalid creation request id')
        canonical=json.dumps({'name':name.strip(),'humans':sorted(set(humans+[creator]))},sort_keys=True)
        if type(signed_policy) is not bool:
            raise ValueError('signed_policy must be boolean')
        if signed_policy:
            if self.policy_authority is None:
                raise PermissionError('policy signing is disabled')
            self.policy_authority.require_actor(creator)
            if group_id is not None:
                raise ValueError('signed creation requires a new group instance')
            canonical = json.dumps({'creation': canonical, 'signed_policy': True}, sort_keys=True)
        with self.lock, self.db:
            self.db.execute('BEGIN IMMEDIATE')
            if request_id is not None:
                previous=self.db.execute('SELECT payload,group_id FROM group_creations WHERE creator=? AND request_id=?',(creator,request_id)).fetchone()
                if previous:
                    if previous[0]!=canonical:
                        raise FileExistsError('creation request id reused with changed payload')
                    return {'id':previous[1],'name':name.strip(),'creator':creator}
            group_id = self.policy_authority.create(self.db, name.strip()) if signed_policy else group_id or uuid.uuid4().hex
            self.db.execute('INSERT INTO chat_groups(id,name,creator,created) VALUES(?,?,?,?)', (group_id,name.strip(),creator,time.time()))
            self.db.executemany('INSERT INTO group_humans VALUES(?,?)', [(group_id,h) for h in sorted(set(humans+[creator]))])
            if request_id is not None:
                self.db.execute('INSERT INTO group_creations VALUES(?,?,?,?)',(creator,request_id,canonical,group_id))
            self.audit(group_id,creator,'create',group_id)
        return {'id':group_id,'name':name.strip(),'creator':creator}

    def groups(self, principal):
        with self.lock:
            rows=self.db.execute('SELECT g.id,g.name,g.creator,g.dissolved FROM chat_groups g JOIN group_humans h ON h.group_id=g.id WHERE h.principal=? ORDER BY g.created,g.id',(principal,)).fetchall()
        return [{'id':r[0],'name':r[1],'creator':r[2],'dissolved':bool(r[3])} for r in rows]

    def _require_group(self, principal, group_id, active=False):
        row=self.db.execute('SELECT g.creator,g.name,g.dissolved FROM chat_groups g JOIN group_humans h ON h.group_id=g.id WHERE h.principal=? AND g.id=?',(principal,group_id)).fetchone()
        if row is None or (active and row[2]):
            raise PermissionError('group access denied or dissolved')
        return row

    def require_group(self, principal, group_id, active=False):
        with self.lock:
            return self._require_group(principal,group_id,active)

    def group_info(self, principal, group_id):
        with self.lock:
            creator,name,dissolved=self._require_group(principal,group_id)
            humans=[r[0] for r in self.db.execute('SELECT principal FROM group_humans WHERE group_id=? ORDER BY principal',(group_id,))]
            events=self.db.execute('SELECT actor,action,subject,created FROM group_audit WHERE group_id=? ORDER BY id DESC LIMIT 50',(group_id,)).fetchall()
            return {'id':group_id,'name':name,'creator':creator,'dissolved':bool(dissolved),'humans':humans,
                    'audit':[dict(zip(('actor','action','subject','created'),r)) for r in reversed(events)]}

    def update_member(self, actor, group_id, subject, operation):
        if operation not in ('add','remove'):
            raise ValueError('invalid membership operation')
        with self.lock,self.db:
            self.db.execute('BEGIN IMMEDIATE')
            creator,_,_=self._require_group(actor,group_id,active=True)
            if actor!=creator:
                raise PermissionError('group creator required')
            if operation=='remove' and subject==creator:
                raise ValueError('creator cannot be removed')
            if operation=='add':
                self.db.execute('INSERT OR IGNORE INTO group_humans VALUES(?,?)',(group_id,subject))
            else:
                self.db.execute('DELETE FROM group_humans WHERE group_id=? AND principal=?',(group_id,subject))
            self.audit(group_id,actor,operation,subject)
        return {'updated':True}

    def dissolve_group(self, actor, group_id, confirm_name):
        with self.lock,self.db:
            self.db.execute('BEGIN IMMEDIATE')
            creator,name,dissolved=self._require_group(actor,group_id)
            if actor!=creator:
                raise PermissionError('group creator required')
            if confirm_name!=name:
                raise ValueError('group name confirmation does not match')
            if not dissolved:
                if self.policy_authority is not None and self.db.execute('SELECT 1 FROM ui_group_policies WHERE group_id=?', (group_id,)).fetchone():
                    self.policy_authority.require_actor(actor)
                    self.policy_authority.dissolve(self.db, group_id)
                self.db.execute('UPDATE chat_groups SET dissolved=1 WHERE id=?',(group_id,))
                self.audit(group_id,actor,'dissolve',group_id)
        return {'dissolved':True}

    def _require_policy_admin(self, actor, group_id):
        creator, _, _ = self._require_group(actor, group_id)
        if actor != creator or self.policy_authority is None:
            raise PermissionError('group creator and policy authority required')
        self.policy_authority.require_actor(actor)

    def policy_export(self, actor, group_id):
        with self.lock:
            self._require_policy_admin(actor, group_id)
            return self.policy_authority.export(self.db, group_id)

    def policy_preview(self, actor, group_id, grant):
        with self.lock:
            self._require_policy_admin(actor, group_id)
            return self.policy_authority.preview(self.db, group_id, grant)

    def policy_change(self, actor, group_id, operation, payload):
        with self.lock, self.db:
            self.db.execute('BEGIN IMMEDIATE')
            self._require_policy_admin(actor, group_id)
            self._require_group(actor, group_id, active=True)
            return self.policy_authority.change(self.db, group_id, operation, payload)

    @staticmethod
    def conversation(value):
        if value != 'group' and value not in {'dm:' + agent for agent in AGENTS}:
            raise ValueError('unknown conversation')
        return value

    def page(self, conversation, principal="demo-owner", *, after=None, before=None, limit=100, group_id="legacy", enforce_access=False):
        self.conversation(conversation)
        if after is not None and before is not None:
            raise ValueError('after and before are mutually exclusive')
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError('limit must be 1..200')
        if any(value is not None and (type(value) is not int or not 0 <= value <= 2**63-1)
               for value in (after, before)):
            raise ValueError('invalid message cursor')
        clauses, values = ['conversation=?','group_id=?'], [conversation,group_id]
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
            if enforce_access:
                self._require_group(principal,group_id)
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

    def send(self, payload, principal="demo-owner", group_id="legacy", enforce_access=False):
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
            if enforce_access:
                self._require_group(principal,group_id,active=True)
            old = self.db.execute('SELECT payload,result FROM group_submissions WHERE group_id=? AND owner=? AND request_id=?', (group_id, principal, request_id)).fetchone()
            if old:
                if old[0] != canonical:
                    raise FileExistsError('request id reused with changed message')
                return json.loads(old[1])
            created = time.time()
            cursor = self.db.execute('INSERT INTO messages(conversation,sender,text,created,owner,group_id) VALUES(?,?,?,?,?,?)', (conversation, 'human', text, created, principal, group_id))
            replies, skipped = [], []
            for target in targets:
                if target not in self.online:
                    skipped.append(target)
                    continue
                # Exactly one deterministic reply; agent replies never trigger other agents.
                reply = f'[{AGENTS[target]} · simulated] Received: {text}'
                row = self.db.execute('INSERT INTO messages(conversation,sender,text,created,owner,group_id) VALUES(?,?,?,?,?,?)', (conversation, target, reply, created, principal, group_id))
                replies.append(row.lastrowid)
            result = {'message_id': cursor.lastrowid, 'reply_ids': replies, 'offline_targets': skipped}
            self.db.execute('INSERT INTO group_submissions VALUES(?,?,?,?,?)', (group_id, principal, request_id, canonical, json.dumps(result)))
            return result

    def close(self):
        with self.lock:
            self.db.close()
