"""Explicit cancellation intent and caller-signed, advisory uncertainty reviews."""
import math

from .durable_tasks import (MAX_COUNTER, bounded_text, digest, task_id, verify_receipt, verify_task)
from .identity import AdmissionError, identity_id, sign, verify

REVIEW_TYPE = 'tailnet-agent-task-review+jwt'
DECISIONS = ('effect_observed', 'no_effect_observed', 'unresolved')
CALLER_FORMAT = 'task-operations-v1'


def bind(db):
    db.execute('CREATE TABLE IF NOT EXISTS task_cancellations (task_id TEXT PRIMARY KEY,request_hash TEXT NOT NULL,created REAL NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS task_reviews (position INTEGER PRIMARY KEY AUTOINCREMENT,request_id TEXT UNIQUE NOT NULL,task_id TEXT NOT NULL,token TEXT NOT NULL)')


def requested(client, mid):
    return client.db.execute('SELECT 1 FROM task_cancellations WHERE task_id=?', (mid,)).fetchone() is not None


def decorate(client, result, mid):
    return result | {'cancellation_requested': True} if requested(client, mid) else result


def local(client, mid):
    if not task_id(mid):raise ValueError('invalid task id')
    row = client.db.execute('SELECT task_id,token,state,receipt FROM task_outbox WHERE task_id=?', (mid,)).fetchone()
    if row is None:raise KeyError('unknown local task')
    original = verify_task(row[1], client.key.public_key(), client.owner, client.group, client.audience, client.executor)
    claim = None if row[3] is None else verify_receipt(row[3], client.executor_key, client.owner, client.group,
        client.audience, original | {'request_hash': digest(row[1])})
    if row[2] != ('pending' if claim is None else claim['status']):raise AdmissionError('local task state disagrees with signed receipt')
    return row, original, claim


def cancel_preview(client, mid):
    row, _, _ = local(client, mid)
    return {'operation': 'cancel', 'task_id': mid, 'executor': client.executor, 'request_hash': digest(row[1]),
            'observed_state': row[2], 'eligible': row[2] in ('pending', 'queued', 'cancelled'),
            'cancellation_requested': requested(client, mid), 'sends_original_task': True}


def archive_preview(client, mid):
    from .task_history import ARCHIVABLE
    row, _, _ = local(client, mid)
    return {'operation': 'archive', 'task_id': mid, 'executor': client.executor,
            'request_hash': digest(row[1]), 'receipt_hash': None if row[3] is None else digest(row[3]),
            'observed_state': row[2], 'eligible': row[2] in ARCHIVABLE,
            'payload_retained': True, 'remote_state_checked': False}


def archive(client, mid, expected_hash, receipt_hash, confirmation):
    preview = archive_preview(client, mid)
    if (confirmation != mid or expected_hash != preview['request_hash'] or receipt_hash != preview['receipt_hash']):
        raise ValueError('confirm original task id, request and terminal receipt hashes')
    if not preview['eligible']:raise FileExistsError('only completed, failed or cancelled tasks may be archived')
    row, _, _ = local(client, mid)
    response = client._request({'operation': 'archive', 'task': row[1], 'receipt_hash': receipt_hash})
    if not isinstance(response, dict) or set(response) != {'receipt', 'archived'} or response['archived'] is not True:
        raise ValueError('invalid archive acknowledgment')
    result = client._save(row, {'receipt': response['receipt']})
    return result | {'archived': True, 'payload_retained': True}


def cancel(client, mid, expected_hash, confirmation):
    row, _, claim = local(client, mid)
    if confirmation != mid or expected_hash != digest(row[1]):raise ValueError('confirm original task id and request hash')
    if row[2] == 'cancelled':return decorate(client, claim, mid)
    if row[2] not in ('pending', 'queued'):raise FileExistsError('task may have run; cancellation is not a stop acknowledgment')
    # Commit the local barrier before I/O. Even a failed cancel/refresh cannot
    # make flush resubmit this task. Retain it across process restart.
    with client.db:client.db.execute('INSERT OR IGNORE INTO task_cancellations VALUES(?,?,?)', (mid, expected_hash, client.clock()))
    return client._save(row, client._request({'operation': 'cancel', 'task': row[1]}), expected_state='cancelled')


def review_preview(client, mid):
    row, _, claim = local(client, mid)
    if claim is None or claim['status'] != 'uncertain':raise ValueError('verified uncertain receipt required')
    return {'operation': 'review', 'task_id': mid, 'executor': client.executor, 'request_hash': digest(row[1]),
            'receipt_hash': digest(row[3]), 'receipt_issued_at': claim['issued_at'], 'decisions': list(DECISIONS), 'task_status': 'uncertain',
            'effect': 'advisory_local_record_only'}


def verify_review(client, token, mid):
    row, _, receipt = local(client, mid)
    if row[2] != 'uncertain':raise ValueError('uncertain receipt required')
    claim = verify(token, client.key.public_key(), REVIEW_TYPE)
    expected = {'version', 'owner', 'group_id', 'audience', 'caller', 'executor', 'task_id', 'request_hash',
                'receipt_hash', 'decision', 'note', 'request_id', 'issued_at', 'task_status', 'effect'}
    if (set(claim) != expected or type(claim['version']) is not int or claim['version'] != 1 or
            claim['owner'] != identity_id(client.owner) or claim['group_id'] != client.group or
            claim['audience'] != client.audience or claim['caller'] != client.subject or claim['executor'] != client.executor or
            claim['task_id'] != mid or claim['request_hash'] != digest(row[1]) or claim['receipt_hash'] != digest(row[3]) or
            claim['task_status'] != 'uncertain' or claim['effect'] != 'advisory_local_record_only' or
            not isinstance(claim['decision'], str) or claim['decision'] not in DECISIONS or not bounded_text(claim['note']) or
            not task_id(claim['request_id']) or type(claim['issued_at']) is not int or
            not receipt['issued_at'] <= claim['issued_at'] <= MAX_COUNTER):
        raise AdmissionError('invalid uncertainty review binding')
    return claim


def review(client, mid, receipt_hash, decision, note, request_id, confirmation):
    preview = review_preview(client, mid)
    if (confirmation != mid or receipt_hash != preview['receipt_hash'] or
            not isinstance(decision, str) or decision not in DECISIONS or not bounded_text(note) or not task_id(request_id)):
        raise ValueError('explicit original uncertain receipt and bounded review required')
    previous = client.db.execute('SELECT task_id,token FROM task_reviews WHERE request_id=?', (request_id,)).fetchone()
    if previous:
        old = verify_review(client, previous[1], previous[0])
        if old['request_id'] != request_id:raise AdmissionError('persisted review request id mismatch')
        if (previous[0] != mid or old['receipt_hash'] != receipt_hash or old['decision'] != decision or old['note'] != note):
            raise FileExistsError('review request id reused with changed contents')
        return old
    now = client.clock()
    if type(now) not in (int, float) or not math.isfinite(now) or not preview['receipt_issued_at'] <= now <= MAX_COUNTER:
        raise ValueError('invalid review clock')
    now = int(now)
    token = sign(client.key, {'version': 1, 'owner': identity_id(client.owner), 'group_id': client.group,
        'audience': client.audience, 'caller': client.subject, 'executor': client.executor, 'task_id': mid,
        'request_hash': preview['request_hash'], 'receipt_hash': receipt_hash, 'decision': decision, 'note': note,
        'request_id': request_id, 'issued_at': now, 'task_status': 'uncertain', 'effect': 'advisory_local_record_only'}, REVIEW_TYPE)
    checked = verify_review(client, token, mid)
    with client.db:client.db.execute('INSERT INTO task_reviews(request_id,task_id,token) VALUES(?,?,?)', (request_id, mid, token))
    return checked


def reviews(client, mid, after=0, limit=20):
    review_preview(client, mid)
    if type(after) is not int or not 0 <= after <= MAX_COUNTER or type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError('invalid review page')
    rows = client.db.execute('SELECT position,request_id,token FROM task_reviews WHERE task_id=? AND position>? ORDER BY position LIMIT ?',
                             (mid, after, limit + 1)).fetchall()
    entries = []
    for pos, request_id, token in rows[:limit]:
        claim = verify_review(client, token, mid)
        if claim['request_id'] != request_id:raise AdmissionError('persisted review request id mismatch')
        entries.append({'position': pos, 'review': claim})
    return {'reviews': entries, 'next_after': entries[-1]['position'] if entries else after, 'has_more': len(rows) > limit,
            'task_status': 'uncertain', 'effect': 'advisory_local_record_only'}
