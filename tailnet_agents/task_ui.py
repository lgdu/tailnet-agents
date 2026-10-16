"""Explicit human consent on the trusted loopback gateway for signed Echo tasks."""
import hashlib
import json
import math
from pathlib import Path
import re
import threading
import time

from .task_mcp import Backend, load_config, read_file, unique_object


def identifier(value):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{32}', value) is not None


class TaskBridge:
    def __init__(self, store, bindings, *, clock=time.time):
        self.store, self.clock, self.lock = store, clock, threading.Lock()
        self.bindings = {}
        try:
            for name, human, backend in bindings:
                if (not isinstance(name, str) or not re.fullmatch('[a-zA-Z0-9_.-]{1,64}', name)
                        or name in self.bindings):
                    raise ValueError('unique explicit task binding IDs required')
                self.bindings[name] = (human, backend.client)
            if not 1 <= len(self.bindings) <= 16:raise ValueError('one to sixteen task bindings required')
            with store.lock, store.db:
                store.db.execute('CREATE TABLE IF NOT EXISTS ui_task_bindings (id TEXT PRIMARY KEY,context TEXT NOT NULL)')
                store.db.execute('CREATE TABLE IF NOT EXISTS ui_task_consents (id TEXT PRIMARY KEY,binding TEXT NOT NULL,actor TEXT NOT NULL,payload TEXT NOT NULL,preview TEXT NOT NULL,policy_hash TEXT NOT NULL,issued REAL NOT NULL,expires REAL NOT NULL,state TEXT NOT NULL,result TEXT)')
                previous = dict(store.db.execute('SELECT id,context FROM ui_task_bindings'))
                if set(previous) - set(self.bindings):raise ValueError('restore all original task bindings')
                for name, (human, client) in self.bindings.items():
                    self._access(human, name)
                    original = client.db.execute('SELECT context FROM task_caller_context WHERE id=1').fetchone()[0]
                    state = client.db.execute('PRAGMA database_list').fetchone()[2]
                    context = json.dumps([human, original, state])
                    if name in previous and previous[name] != context:
                        raise ValueError('cannot replace original human/task binding or caller state')
                    store.db.execute('INSERT OR IGNORE INTO ui_task_bindings VALUES(?,?)', (name, context))
        except Exception:
            self.close()
            raise

    @classmethod
    def from_file(cls, store, users, path):
        if not isinstance(path, str) or not Path(path).is_absolute():raise ValueError('absolute task bindings path required')
        entries = json.loads(read_file(path, private=True), object_pairs_hook=unique_object)
        if not isinstance(entries, list) or not 1 <= len(entries) <= 16:raise ValueError('bounded explicit task bindings required')
        bindings = []
        try:
            names = set()
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {'id', 'human', 'config_file'}:
                    raise ValueError('exact task binding fields required')
                human = entry['human']
                name = entry['id']
                if not isinstance(name, str) or not re.fullmatch('[a-zA-Z0-9_.-]{1,64}', name) or name in names:
                    raise ValueError('unique explicit task binding IDs required')
                names.add(name)
                if not isinstance(human, str) or users.get(human, {}).get('role') != 'admin':
                    raise ValueError('configured admin human required')
                config = load_config(entry['config_file'])
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                from .identity import decode, identity_id
                owner = Ed25519PublicKey.from_public_bytes(decode(read_file(config['authority_public_key']).decode().strip()))
                with store.lock:
                    store._require_policy_admin(human, config['group_id'])
                    store.policy_authority.current(store.db, config['group_id'])
                    if identity_id(owner) != store.policy_authority.owner:raise PermissionError('task owner pin mismatch')
                bindings.append((entry['id'], human, Backend.from_config(entry['config_file'])))
            return cls(store, bindings)
        except Exception:
            for _, _, backend in bindings:backend.close()
            raise

    def _access(self, actor, binding, *, active=False):
        from .identity import identity_id
        if not isinstance(binding, str) or binding not in self.bindings:raise PermissionError('configured task binding required')
        human, client = self.bindings[binding]
        if actor != human:raise PermissionError('configured task human required')
        self.store._require_policy_admin(actor, client.group)
        self.store._require_group(actor, client.group, active=active)
        token, _ = self.store.policy_authority.current(self.store.db, client.group)
        if identity_id(client.owner) != self.store.policy_authority.owner:
            raise PermissionError('task owner and signed UI group must match')
        return client, hashlib.sha256(token.encode()).hexdigest()

    def catalog(self, actor, group):
        with self.lock, self.store.lock:
            result = []
            for name, (human, client) in self.bindings.items():
                if human != actor or client.group != group:continue
                self._access(actor, name)
                result.append({'id': name, 'group_id': client.group, 'caller': client.subject,
                               'executor': client.executor, 'url': client.http.url})
            return {'bindings': result}

    def read(self, actor, group, payload):
        with self.lock:
            with self.store.lock:client, _ = self._access(actor, payload.get('binding_id'))
            if client.group != group:raise PermissionError('task group mismatch')
            operation = payload.get('operation')
            fields = {'binding_id', 'operation'}
            if operation == 'list':
                if set(payload) - fields - {'after', 'limit'}:raise ValueError('invalid task page fields')
                return client.list_tasks(after=payload.get('after', 0), limit=payload.get('limit', 20))
            if operation == 'show' and set(payload) == fields | {'task_id'}:return client.show(payload['task_id'])
            if operation == 'history' and set(payload) - fields - {'after', 'limit'} == set():
                after, limit = payload.get('after', 0), payload.get('limit', 20)
                if type(after) is not int or not 0 <= after <= 2**53-1 or type(limit) is not int or not 1 <= limit <= 100:
                    raise ValueError('invalid consent history page')
                with self.store.lock:
                    rows = self.store.db.execute('SELECT rowid,id,preview,state,issued,expires FROM ui_task_consents WHERE binding=? AND actor=? AND rowid>? ORDER BY rowid LIMIT ?',
                        (payload['binding_id'], actor, after, limit+1)).fetchall()
                return {'consents': [{'position': r[0], 'consent_id': r[1], 'preview': json.loads(r[2]),
                    'state': r[3], 'issued_at': r[4], 'expires_at': r[5]} for r in rows[:limit]],
                    'next_after': rows[min(len(rows),limit)-1][0] if rows else after, 'has_more': len(rows)>limit}
            raise ValueError('explicit local task read required')

    def _now(self):
        now = self.clock()
        if type(now) not in (int, float) or not math.isfinite(now) or now < 0:raise ValueError('trusted clock required')
        return now

    def preview(self, actor, group, payload):
        from .durable_tasks import bounded_text
        with self.lock:
            with self.store.lock:
                client, policy = self._access(actor, payload.get('binding_id'), active=True)
            if client.group != group:raise PermissionError('task group mismatch')
            operation, mid, cid = payload.get('operation'), payload.get('task_id'), payload.get('request_id')
            fields = {'binding_id', 'operation', 'task_id', 'request_id'}
            if (operation not in ('queue','submit','cancel','archive','refresh') or not identifier(mid) or not identifier(cid)
                    or set(payload) != fields | ({'input'} if operation == 'queue' else set())):
                raise ValueError('exact task preview fields required')
            if operation == 'queue' and not bounded_text(payload['input']):raise ValueError('bounded Echo input required')
            saved = json.dumps(payload, sort_keys=True)
            with self.store.lock:
                row = self.store.db.execute('SELECT binding,actor,payload,preview,issued,expires,state FROM ui_task_consents WHERE id=?', (cid,)).fetchone()
            if row:
                if row[:3] != (payload['binding_id'], actor, saved):raise FileExistsError('consent ID already binds another request')
                return json.loads(row[3]) | {'consent_id': cid, 'issued_at': row[4], 'expires_at': row[5], 'consent_state': row[6]}
            if operation == 'queue':detail = {'operation': operation, 'task_id': mid, 'input': payload['input'], 'eligible': True}
            elif operation == 'refresh':detail = {'operation': operation, 'task_id': mid, 'observed': client.show(mid), 'eligible': True}
            else:detail = getattr(client, {'submit':'submit_preview','cancel':'cancel_preview','archive':'archive_preview'}[operation])(mid)
            if operation != 'queue':
                from .task_operations import local
                with client.lock:detail['input'] = local(client, mid)[1]['input']
            detail |= {'binding_id':payload['binding_id'], 'group_id':group, 'caller':client.subject, 'executor':client.executor,
                       'url':client.http.url, 'human':actor, 'policy_hash':policy, 'network':operation != 'queue'}
            now = self._now()
            with self.store.lock, self.store.db:
                _, latest = self._access(actor, payload['binding_id'], active=True)
                if latest != policy:raise FileExistsError('group policy changed; preview again')
                self.store.db.execute('INSERT INTO ui_task_consents VALUES(?,?,?,?,?,?,?,?,?,NULL)',
                    (cid,payload['binding_id'],actor,saved,json.dumps(detail),policy,now,now+60,'preview'))
            return detail | {'consent_id':cid, 'issued_at':now, 'expires_at':now+60, 'consent_state':'preview'}

    def confirm(self, actor, group, payload):
        if (set(payload) != {'binding_id','consent_id','confirm_task_id'} or
                not identifier(payload.get('consent_id')) or not identifier(payload.get('confirm_task_id'))):
            raise ValueError('confirm one original consent and task ID')
        with self.lock:
            with self.store.lock:
                client, policy = self._access(actor, payload['binding_id'])
                if client.group != group:raise PermissionError('task group mismatch')
                row = self.store.db.execute('SELECT binding,actor,payload,preview,policy_hash,issued,expires,state,result FROM ui_task_consents WHERE id=?', (payload['consent_id'],)).fetchone()
                if row is None or row[:2] != (payload['binding_id'],actor):raise PermissionError('original human consent required')
                request, preview = json.loads(row[2]), json.loads(row[3])
                if request['task_id'] != payload['confirm_task_id']:raise ValueError('original task confirmation required')
                if row[7] == 'done':return json.loads(row[8])
                self._access(actor, payload['binding_id'], active=True)
                if row[7] == 'expired':raise FileExistsError('consent expired; preview original task again')
                if row[7] == 'preview':
                    now = self._now()
                    if not row[5] <= now < row[6] or policy != row[4]:
                        with self.store.db:self.store.db.execute("UPDATE ui_task_consents SET state='expired' WHERE id=?", (payload['consent_id'],))
                        raise FileExistsError('consent expired or policy changed; preview original task again')
                    if not preview['eligible']:raise FileExistsError('original task is ineligible')
                    with self.store.db:self.store.db.execute("UPDATE ui_task_consents SET state='started' WHERE id=?", (payload['consent_id'],))
            # Durable human authorization precedes caller mutation/network I/O. A
            # started retry uses this same intent; it never starts on its own.
            mid, operation = request['task_id'], request['operation']
            if operation == 'queue':result = client.queue_once(mid, request['input'])
            elif operation == 'refresh':result = client.refresh(mid)
            elif operation == 'archive':result = client.archive(mid, preview['request_hash'], preview['receipt_hash'], mid)
            else:result = getattr(client, operation)(mid, preview['request_hash'], mid)
            with self.store.lock, self.store.db:
                self._access(actor, payload['binding_id'])
                self.store.db.execute("UPDATE ui_task_consents SET state='done',result=? WHERE id=?", (json.dumps(result),payload['consent_id']))
            return result

    def close(self):
        for _, client in self.bindings.values():client.close()
