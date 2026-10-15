"""Explicit signed Echo tasks with durable, conservative execution recovery."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import threading
import time

from .identity import (AdmissionError, GRANT_TYPE, identity_id, sign, verify, verify_grant)

TASK_TYPE = 'tailnet-agent-task+jwt'
RESULT_TYPE = 'tailnet-agent-task-result+jwt'
TERMINAL = frozenset({'completed', 'failed', 'uncertain'})
STATES = TERMINAL | {'queued', 'running'}
MAX_COUNTER = 2**53 - 1


class TaskUnavailable(RuntimeError):
    pass


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def task_id(value):
    return isinstance(value, str) and re.fullmatch(r'[a-f0-9]{32}', value) is not None


def bounded_text(value):
    return isinstance(value, str) and 1 <= len(value.encode('utf-8')) <= 2048


def verify_task(token, key, owner, group, audience, executor, *, now=None):
    claim = verify(token, key, TASK_TYPE)
    if (set(claim) != {'version', 'owner', 'group_id', 'audience', 'caller', 'executor', 'task_id', 'kind', 'input', 'created_at'} or
            type(claim['version']) is not int or claim['version'] != 1 or
            claim['owner'] != identity_id(owner) or claim['group_id'] != group or claim['audience'] != audience or
            claim['caller'] != identity_id(key) or claim['executor'] != executor or
            not task_id(claim['task_id']) or claim['kind'] != 'echo' or not bounded_text(claim['input']) or
            type(claim['created_at']) is not int or not 0 <= claim['created_at'] <= MAX_COUNTER or
            (now is not None and claim['created_at'] > now + 30)):
        raise AdmissionError('invalid signed task context or schema')
    return claim


def make_task(key, owner, group, audience, executor, text, *, identifier=None, now=None):
    claim = {'version': 1, 'owner': identity_id(owner), 'group_id': group, 'audience': audience,
             'caller': identity_id(key.public_key()), 'executor': executor, 'task_id': secrets.token_hex(16) if identifier is None else identifier,
             'kind': 'echo', 'input': text, 'created_at': int(time.time()) if now is None else now}
    token = sign(key, claim, TASK_TYPE)
    verify_task(token, key.public_key(), owner, group, audience, executor)
    return token


def validate_request(request):
    if not isinstance(request, dict):raise ValueError('task operation required')
    if request.get('operation') == 'submit':
        if set(request) != {'operation', 'task'} or not isinstance(request['task'], str) or len(request['task']) > 16384:
            raise ValueError('invalid task submission')
    elif request.get('operation') == 'get':
        if set(request) != {'operation', 'task_id'} or not task_id(request['task_id']):
            raise ValueError('invalid task query')
    else:raise ValueError('unknown task operation')
    return 'tasks-v1:' + digest(json.dumps(request, sort_keys=True, separators=(',', ':'), allow_nan=False))


def verify_receipt(token, executor_key, owner, group, audience, original):
    claim = verify(token, executor_key, RESULT_TYPE)
    expected = {'version', 'owner', 'group_id', 'audience', 'executor', 'caller', 'task_id', 'request_hash',
                'status', 'output', 'error', 'issued_at'}
    if (set(claim) != expected or type(claim['version']) is not int or claim['version'] != 1 or
            claim['owner'] != identity_id(owner) or claim['group_id'] != group or claim['audience'] != audience or
            claim['executor'] != identity_id(executor_key) or claim['caller'] != original['caller'] or
            claim['task_id'] != original['task_id'] or claim['request_hash'] != original['request_hash'] or
            not isinstance(claim['status'], str) or claim['status'] not in STATES or
            type(claim['issued_at']) is not int or not 0 <= claim['issued_at'] <= MAX_COUNTER):
        raise AdmissionError('invalid signed task receipt')
    status = claim['status']
    if (status == 'completed' and (not bounded_text(claim['output']) or claim['error'] is not None) or
            status != 'completed' and claim['output'] is not None or
            claim['error'] != {'failed': 'execution_failed', 'uncertain': 'execution_interrupted'}.get(status)):
        raise AdmissionError('invalid task result state')
    return claim


class TaskExecutor:
    """No startup execution, no retry of uncertain work, no real adapter by CLI.

    Calls are synchronous but execution runs outside the directory lock. Queued
    rows require an explicit fresh authorized submission; running rows become
    terminal uncertain on restart. One POSIX-locked executor owns the database.
    """
    def __init__(self, directory, key, grant, *, adapter=None, capacity=256):
        if not directory.require_policy:raise ValueError('tasks require signed policy mode')
        if type(capacity) is not int or not 1 <= capacity <= 10000:raise ValueError('invalid task capacity')
        saved = verify(grant, directory.owner_key, GRANT_TYPE)
        if type(saved.get('iat')) is not int:raise AdmissionError('invalid executor grant')
        saved = verify_grant(grant, directory.owner_key, directory.group_id, 'task.echo', now=saved['iat'])
        self.subject = identity_id(key.public_key())
        if saved['sub'] != self.subject or self.subject == identity_id(directory.owner_key):
            raise AdmissionError('existing executor key must match grant and differ from owner')
        self.directory, self.key, self.grant = directory, key, grant
        self.db, self.capacity = directory._registry.db, capacity
        self.adapter = (lambda text: text) if adapter is None else adapter
        self.condition, self.active, self.closing = threading.Condition(), 0, False
        self.descriptor = None
        try:
            with directory.lock:
                if getattr(directory, '_task_executor', None) is not None:raise TaskUnavailable('executor already open')
                path = self.db.execute('PRAGMA database_list').fetchone()[2]
                if path:
                    self.descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
                    info = os.fstat(self.descriptor)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                        raise ValueError('executor database must be an owned private regular file')
                    fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.db.execute('PRAGMA synchronous=FULL')
                with self.db:
                    self.db.execute('CREATE TABLE IF NOT EXISTS task_executor_context (id INTEGER PRIMARY KEY CHECK(id=1),executor TEXT NOT NULL,audience TEXT NOT NULL,adapter TEXT NOT NULL)')
                    context = (self.subject, directory._admission.audience, 'echo-v1')
                    previous = self.db.execute('SELECT executor,audience,adapter FROM task_executor_context WHERE id=1').fetchone()
                    if previous and previous != context:raise AdmissionError('cannot replace original executor/audience/adapter')
                    self.db.execute('INSERT OR IGNORE INTO task_executor_context VALUES(1,?,?,?)', context)
                    self.db.execute('CREATE TABLE IF NOT EXISTS durable_tasks (task_id TEXT PRIMARY KEY,caller TEXT NOT NULL,token TEXT NOT NULL,status TEXT NOT NULL,receipt TEXT)')
                    for mid, caller, token in self.db.execute("SELECT task_id,caller,token FROM durable_tasks WHERE status='running'").fetchall():
                        receipt = self._receipt(mid, caller, token, 'uncertain')
                        self.db.execute("UPDATE durable_tasks SET status='uncertain',receipt=? WHERE task_id=?", (receipt, mid))
                directory._task_executor = self
        except BaseException:
            if self.descriptor is not None:os.close(self.descriptor);self.descriptor = None
            raise

    @contextmanager
    def _live(self):
        with self.condition:
            if self.closing:raise TaskUnavailable('executor stopping')
            self.active += 1
        try:yield
        finally:
            with self.condition:self.active -= 1;self.condition.notify_all()

    def challenge(self, request):
        context = validate_request(request)
        with self._live(), self.directory.lock:
            return {'nonce': self.directory._admission.challenge(context), 'context': context}

    def _authorize(self, grant, subject):
        directory = self.directory
        claim = verify_grant(grant, directory.owner_key, directory.group_id, 'task.echo',
                             now=directory.clock(), revoked=directory._admission.revoked)
        if claim['sub'] != subject:raise AdmissionError('wrong task principal')
        directory._policy.authorize(claim)
        return claim

    def _receipt(self, mid, caller, token, status, output=None):
        directory = self.directory
        return sign(self.key, {'version': 1, 'owner': identity_id(directory.owner_key), 'group_id': directory.group_id,
            'audience': directory._admission.audience, 'executor': self.subject, 'caller': caller, 'task_id': mid,
            'request_hash': digest(token), 'status': status, 'output': output,
            'error': {'failed': 'execution_failed', 'uncertain': 'execution_interrupted'}.get(status),
            'issued_at': int(directory.clock())}, RESULT_TYPE)

    def _result(self, row):
        mid, caller, token, status, receipt = row
        return {'receipt': receipt if receipt is not None else self._receipt(mid, caller, token, status)}

    def execute(self, request, grant, key, proof, nonce):
        context = validate_request(request)
        directory = self.directory
        caller = identity_id(key)
        with self._live():
            with directory.lock:
                self._authorize(grant, caller);self._authorize(self.grant, self.subject)
                directory._admission.admit(grant, key, proof, nonce, permission='task.echo', context=context)
                if request['operation'] == 'get':
                    row = self.db.execute('SELECT * FROM durable_tasks WHERE task_id=? AND caller=?', (request['task_id'], caller)).fetchone()
                    if row is None:raise KeyError('task not found')
                    return self._result(row)
                claim = verify_task(request['task'], key, directory.owner_key, directory.group_id,
                                    directory._admission.audience, self.subject, now=directory.clock())
                mid = claim['task_id']
                row = self.db.execute('SELECT * FROM durable_tasks WHERE task_id=?', (mid,)).fetchone()
                if row:
                    if row[1] != caller or row[2] != request['task']:raise FileExistsError('task id conflict')
                    if row[3] != 'queued':return self._result(row)
                else:
                    if self.db.execute('SELECT COUNT(*) FROM durable_tasks').fetchone()[0] >= self.capacity:
                        raise OverflowError('task capacity reached')
                    with self.db:self.db.execute('INSERT INTO durable_tasks VALUES(?,?,?,?,NULL)', (mid, caller, request['task'], 'queued'))
            return self._run(mid, claim, grant)

    def _run(self, mid, claim, grant):
        directory = self.directory
        with directory.lock:
            self._authorize(grant, claim['caller']);self._authorize(self.grant, self.subject)
            row = self.db.execute('SELECT * FROM durable_tasks WHERE task_id=?', (mid,)).fetchone()
            if row[3] != 'queued':return self._result(row)
            with self.db:self.db.execute("UPDATE durable_tasks SET status='running' WHERE task_id=?", (mid,))
        # Durable running marker precedes any adapter invocation. Never hold the
        # policy/SQLite lock across model, tool or simulated adapter work.
        try:
            output = self.adapter(claim['input'])
            if not bounded_text(output):raise ValueError('invalid adapter result')
            status = 'completed'
        except Exception:
            output, status = None, 'failed'
        with directory.lock:
            receipt = self._receipt(mid, claim['caller'], row[2], status, output)
            with self.db:
                changed = self.db.execute("UPDATE durable_tasks SET status=?,receipt=? WHERE task_id=? AND status='running'", (status, receipt, mid)).rowcount
                if changed != 1:raise TaskUnavailable('execution state changed')
            self._authorize(grant, claim['caller']);self._authorize(self.grant, self.subject)
            return {'receipt': receipt}

    def close(self):
        with self.condition:
            self.closing = True
            self.condition.notify_all()
            while self.active:self.condition.wait()
        with self.directory.lock:
            if getattr(self.directory, '_task_executor', None) is self:self.directory._task_executor = None
            if self.descriptor is not None:os.close(self.descriptor);self.descriptor = None
