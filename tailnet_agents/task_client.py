"""Synthetic signed-task caller; preserve original task and executor on recovery."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time
from urllib.error import URLError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .client import Client
from .discovery import origin
from .durable_tasks import (TERMINAL, digest, make_task, task_id, validate_request, verify_receipt, verify_task)
from .identity import (AdmissionError, GRANT_TYPE, decode, encode, identity_id, load_identity,
                       prove_possession, public_bytes, verify, verify_grant)


class TaskClient:
    def __init__(self, url, key, owner, grant, group, audience, executor_key, state, *, ca_file=None, clock=time.time):
        if not isinstance(audience, str) or not 1 <= len(audience) <= 128:raise ValueError('explicit task audience required')
        saved = verify(grant, owner, GRANT_TYPE)
        if type(saved.get('iat')) is not int:raise AdmissionError('invalid saved caller grant')
        saved = verify_grant(grant, owner, group, 'task.echo', now=saved['iat'])
        self.subject, self.executor = identity_id(key.public_key()), identity_id(executor_key)
        if saved['sub'] != self.subject or self.subject == identity_id(owner) or self.executor == identity_id(owner):
            raise AdmissionError('existing Agent identities required')
        self.http = Client(origin(url), '', ca_file=ca_file, timeout=5)
        self.key, self.owner, self.grant, self.group, self.audience = key, owner, grant, group, audience
        self.executor_key, self.clock = executor_key, clock
        self.lock = threading.Lock()
        self.db = self.descriptor = None
        path = Path(state);path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(self.descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError('caller state must be an owned private regular file')
            fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.db = sqlite3.connect(path, check_same_thread=False)
            self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
            ca_hash = None if ca_file is None else digest(Path(ca_file).read_text())
            context = json.dumps([identity_id(owner), group, self.subject, self.executor, self.http.url, audience, ca_hash])
            with self.db:
                self.db.execute('CREATE TABLE IF NOT EXISTS task_caller_context (id INTEGER PRIMARY KEY CHECK(id=1),context TEXT NOT NULL)')
                previous = self.db.execute('SELECT context FROM task_caller_context WHERE id=1').fetchone()
                if previous and previous[0] != context:raise AdmissionError('cannot replace original caller/group/executor/service/CA')
                self.db.execute('INSERT OR IGNORE INTO task_caller_context VALUES(1,?)', (context,))
                self.db.execute('CREATE TABLE IF NOT EXISTS task_outbox (position INTEGER PRIMARY KEY AUTOINCREMENT,task_id TEXT UNIQUE NOT NULL,token TEXT NOT NULL,state TEXT NOT NULL,receipt TEXT)')
        except BaseException:
            self.close();raise

    def _request(self, request):
        context = validate_request(request)
        verify_grant(self.grant, self.owner, self.group, 'task.echo', now=self.clock())
        challenge = self.http.request('/v1/task-challenges', {'request': request})
        if (not isinstance(challenge, dict) or set(challenge) != {'nonce', 'context'} or
                not isinstance(challenge['nonce'], str) or not 1 <= len(challenge['nonce']) <= 128 or challenge['context'] != context):
            raise ValueError('challenge does not bind this task operation')
        proof = prove_possession(self.key, self.grant, challenge['nonce'], self.audience, context=context)
        return self.http.request('/v1/agent-tasks', {'request': request, 'grant': self.grant,
            'public_key': encode(public_bytes(self.key.public_key())), 'nonce': challenge['nonce'], 'proof': proof})

    def queue(self, text):
        with self.lock:
            token = make_task(self.key, self.owner, self.group, self.audience, self.executor, text, now=int(self.clock()))
            claim = verify_task(token, self.key.public_key(), self.owner, self.group, self.audience, self.executor)
            with self.db:self.db.execute('INSERT INTO task_outbox(task_id,token,state) VALUES(?,?,?)', (claim['task_id'], token, 'pending'))
            return {'task_id': claim['task_id'], 'state': 'pending', 'executor': self.executor}

    def _save(self, row, response):
        mid, token, previous, old_receipt = row
        if not isinstance(response, dict) or set(response) != {'receipt'}:raise ValueError('invalid task response')
        original = verify_task(token, self.key.public_key(), self.owner, self.group, self.audience, self.executor)
        claim = verify_receipt(response['receipt'], self.executor_key, self.owner, self.group, self.audience,
                               original | {'request_hash': digest(token)})
        if (previous in TERMINAL and response['receipt'] != old_receipt or
                previous == 'running' and claim['status'] == 'queued'):
            raise ValueError('conflicting or older executor receipt; preserve original state')
        with self.db:self.db.execute('UPDATE task_outbox SET state=?,receipt=? WHERE task_id=?', (claim['status'], response['receipt'], mid))
        return claim

    def flush(self, limit=20):
        if type(limit) is not int or not 1 <= limit <= 20:raise ValueError('flush limit must be 1..20')
        with self.lock:
            rows = self.db.execute("SELECT task_id,token,state,receipt FROM task_outbox WHERE state IN ('pending','queued') ORDER BY position LIMIT ?", (limit,)).fetchall()
            result = []
            for row in rows:result.append(self._save(row, self._request({'operation': 'submit', 'task': row[1]})))
            return result

    def refresh(self, mid):
        if not task_id(mid):raise ValueError('invalid task id')
        with self.lock:
            row = self.db.execute('SELECT task_id,token,state,receipt FROM task_outbox WHERE task_id=?', (mid,)).fetchone()
            if row is None:raise KeyError('unknown local task; retain original caller state')
            return self._save(row, self._request({'operation': 'get', 'task_id': mid}))

    def show(self, mid):
        if not task_id(mid):raise ValueError('invalid task id')
        with self.lock:
            row = self.db.execute('SELECT token,state,receipt FROM task_outbox WHERE task_id=?', (mid,)).fetchone()
            if row is None:raise KeyError('unknown local task')
            if row[2] is None:return {'task_id': mid, 'state': row[1], 'executor': self.executor}
            original = verify_task(row[0], self.key.public_key(), self.owner, self.group, self.audience, self.executor)
            return verify_receipt(row[2], self.executor_key, self.owner, self.group, self.audience, original | {'request_hash': digest(row[0])})

    def list_tasks(self, *, after=0, limit=20):
        if type(after) is not int or not 0 <= after <= 2**53 - 1 or type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('invalid local task page')
        with self.lock:
            rows = self.db.execute('SELECT position,task_id,state FROM task_outbox WHERE position>? ORDER BY position LIMIT ?', (after, limit + 1)).fetchall()
            entries = [dict(zip(('position', 'task_id', 'state'), row)) | {'executor': self.executor} for row in rows[:limit]]
            return {'tasks': entries, 'next_after': entries[-1]['position'] if entries else after, 'has_more': len(rows) > limit}

    def status(self):
        with self.lock:return dict(self.db.execute('SELECT state,COUNT(*) FROM task_outbox GROUP BY state'))

    def close(self):
        with self.lock:
            if self.db is not None:self.db.close();self.db = None
            if self.descriptor is not None:os.close(self.descriptor);self.descriptor = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('url', 'agent-key', 'authority-public-key', 'grant-file', 'group-id', 'audience', 'executor-public-key', 'state'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--ca-cert')
    sub = parser.add_subparsers(dest='command', required=True)
    queue = sub.add_parser('queue', help='save a new explicit task locally without network I/O')
    queue.add_argument('--input-file', required=True)
    flush = sub.add_parser('flush', help='retry pending/unstarted tasks at their original executor only')
    flush.add_argument('--limit', type=int, default=20)
    for name in ('refresh', 'show'):sub.add_parser(name).add_argument('--task-id', required=True)
    listing = sub.add_parser('list', help='page saved task IDs/status locally, without contacting the executor')
    listing.add_argument('--after', type=int, default=0)
    listing.add_argument('--limit', type=int, default=20)
    sub.add_parser('status')
    args = parser.parse_args();client = None
    try:
        owner = Ed25519PublicKey.from_public_bytes(decode(Path(args.authority_public_key).read_text().strip()))
        executor = Ed25519PublicKey.from_public_bytes(decode(Path(args.executor_public_key).read_text().strip()))
        client = TaskClient(args.url, load_identity(args.agent_key), owner, Path(args.grant_file).read_text().strip(),
            args.group_id, args.audience, executor, args.state, ca_file=args.ca_cert)
        if args.command == 'queue':
            with Path(args.input_file).open() as source:text = source.read(2049)
            result = client.queue(text)
        elif args.command == 'flush':result = client.flush(args.limit)
        elif args.command == 'refresh':result = client.refresh(args.task_id)
        elif args.command == 'show':result = client.show(args.task_id)
        elif args.command == 'list':result = client.list_tasks(after=args.after, limit=args.limit)
        else:result = client.status()
    except (ValueError, TypeError, KeyError, OSError, URLError, sqlite3.Error):
        parser.exit(1, 'Task request failed; preserve original task IDs, executor, identity/group and state. Check authorization, result conflicts and connectivity; never migrate uncertain work.\n')
    finally:
        if client is not None:client.close()
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':main()
