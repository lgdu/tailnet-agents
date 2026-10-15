"""Explicit terminal-record archival; never discard durable deduplication history."""
from .adapters import CONTRACT_ID
from .identity import AdmissionError

EXECUTOR_FORMAT = CONTRACT_ID + '/task-history-v1'
ARCHIVABLE = frozenset({'completed', 'failed', 'cancelled'})


def quotas(capacity, history_capacity, caller_capacity, caller_history_capacity):
    values = {'capacity': capacity, 'history_capacity': history_capacity,
              'caller_capacity': caller_capacity, 'caller_history_capacity': caller_history_capacity}
    for name, value in values.items():
        if name.startswith('caller_') and value is None:continue
        maximum = 100000 if 'history' in name else 10000
        if type(value) is not int or not 1 <= value <= maximum:raise ValueError('invalid task ' + name)
    if caller_capacity is None:values['caller_capacity'] = min(64, capacity)
    if caller_history_capacity is None:values['caller_history_capacity'] = min(1000, history_capacity)
    return values


def verify_record(executor, row):
    from .durable_tasks import digest, verify_receipt
    mid, caller, token, state, receipt = row
    if state not in ARCHIVABLE or receipt is None:raise AdmissionError('invalid archived task state')
    claim = verify_receipt(receipt, executor.key.public_key(), executor.directory.owner_key,
        executor.directory.group_id, executor.directory._admission.audience,
        {'caller': caller, 'task_id': mid, 'request_hash': digest(token)})
    if claim['status'] != state:raise AdmissionError('archive disagrees with signed task receipt')


def bind(executor):
    db = executor.db
    db.execute('CREATE TABLE IF NOT EXISTS archived_tasks (task_id TEXT PRIMARY KEY,caller TEXT NOT NULL,token TEXT NOT NULL,status TEXT NOT NULL,receipt TEXT NOT NULL)')
    db.execute('CREATE INDEX IF NOT EXISTS task_caller_index ON durable_tasks(caller)')
    db.execute('CREATE INDEX IF NOT EXISTS archive_caller_index ON archived_tasks(caller)')
    if db.execute('SELECT 1 FROM durable_tasks JOIN archived_tasks USING(task_id) LIMIT 1').fetchone():
        raise AdmissionError('overlapping active and archived task history')
    for row in db.execute('SELECT * FROM archived_tasks'):verify_record(executor, row)


def find(executor, mid):
    row = executor.db.execute('SELECT * FROM durable_tasks WHERE task_id=?', (mid,)).fetchone()
    archived = executor.db.execute('SELECT * FROM archived_tasks WHERE task_id=?', (mid,)).fetchone()
    if row is not None and archived is not None:raise AdmissionError('overlapping task history')
    if archived is not None:verify_record(executor, archived)
    return (row, False) if row is not None else (archived, archived is not None)


def admit(executor, caller):
    db = executor.db
    active = db.execute('SELECT COUNT(*) FROM durable_tasks').fetchone()[0]
    own_active = db.execute('SELECT COUNT(*) FROM durable_tasks WHERE caller=?', (caller,)).fetchone()[0]
    archived = db.execute('SELECT COUNT(*) FROM archived_tasks').fetchone()[0]
    own_archived = db.execute('SELECT COUNT(*) FROM archived_tasks WHERE caller=?', (caller,)).fetchone()[0]
    if (active >= executor.capacity or own_active >= executor.caller_capacity or
            active + archived >= executor.history_capacity or own_active + own_archived >= executor.caller_history_capacity):
        raise OverflowError('task capacity reached')


def archive(executor, row, receipt_hash, already_archived):
    from .durable_tasks import digest, TaskUnavailable
    if row is None:raise KeyError('task not found')
    if row[3] not in ARCHIVABLE:raise FileExistsError('only completed, failed or cancelled tasks may be archived')
    verify_record(executor, row)
    if digest(row[4]) != receipt_hash:raise FileExistsError('confirm the original terminal receipt')
    if not already_archived:
        # Both tables use the same SQLite transaction and directory lock. No
        # committed state can lose the original ID, input or signed result.
        with executor.db:
            executor.db.execute('INSERT INTO archived_tasks VALUES(?,?,?,?,?)', row)
            changed = executor.db.execute('DELETE FROM durable_tasks WHERE task_id=?', (row[0],)).rowcount
            if changed != 1:raise TaskUnavailable('task archive source changed')
    return executor._result(row) | {'archived': True}
