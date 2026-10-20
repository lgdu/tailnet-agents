"""Local admission budgets; retain history and reserve room for recovery writes."""

RECEIPT_RESERVE = 16384  # Existing signed-token verification limit.
TASK_RESERVE = RECEIPT_RESERVE + 256  # Receipt, task ID and cancellation metadata.
CONSENT_RESERVE = 32768 + 512  # Bounded Echo result and consent metadata.
CALLER_DEFAULTS = {'capacity': 256, 'history_capacity': 10000,
                   'byte_capacity': 256 * 1024 * 1024, 'review_capacity': 10000}
CONSENT_DEFAULTS = {'capacity': 10000, 'byte_capacity': 64 * 1024 * 1024}


class StorageFull(ValueError):
    """New local records denied; original history/recovery must be retained."""


def limits(values, *, consent=False):
    defaults = CONSENT_DEFAULTS if consent else CALLER_DEFAULTS
    if not isinstance(values, dict) or set(values) - set(defaults):raise ValueError('invalid local storage limit names')
    result = defaults | values
    for name, value in result.items():
        maximum = 1024**3 if name == 'byte_capacity' else 100000
        if type(value) is not int or not 1 <= value <= maximum:raise ValueError('invalid local storage ' + name)
    return result


def size(text):
    return 0 if text is None else len(text.encode('utf-8'))


def caller_usage(db):
    tasks, active, charged = db.execute("SELECT COUNT(*),COALESCE(SUM(state NOT IN ('completed','failed','cancelled')),0),COALESCE(SUM(length(CAST(token AS BLOB))+?+MAX(0,COALESCE(length(CAST(receipt AS BLOB)),0)-?)),0) FROM task_outbox",
                                      (TASK_RESERVE, RECEIPT_RESERVE)).fetchone()
    reviews, review_bytes = db.execute('SELECT COUNT(*),COALESCE(SUM(length(CAST(token AS BLOB))+64),0) FROM task_reviews').fetchone()
    return {'tasks': tasks, 'active': active, 'reviews': reviews, 'charged_bytes': charged + review_bytes}


def admit_task(db, configured, token):
    usage = caller_usage(db)
    if (usage['active'] >= configured['capacity'] or usage['tasks'] >= configured['history_capacity'] or
            usage['charged_bytes'] + size(token) + TASK_RESERVE > configured['byte_capacity']):
        raise StorageFull('Caller storage admission full; retain original tasks/state. Existing reads, cancellation and retries remain available.')


def admit_review(db, configured, token):
    usage = caller_usage(db)
    if usage['reviews'] >= configured['review_capacity'] or usage['charged_bytes'] + size(token) + 64 > configured['byte_capacity']:
        raise StorageFull('Caller review admission full; retain original notes/tasks and retry existing request IDs.')


def consent_usage(db, binding, actor):
    count, charged = db.execute('SELECT COUNT(*),COALESCE(SUM(length(CAST(payload AS BLOB))+length(CAST(preview AS BLOB))+?+MAX(0,COALESCE(length(CAST(result AS BLOB)),0)-32768)),0) FROM ui_task_consents WHERE binding=? AND actor=?',
                               (CONSENT_RESERVE, binding, actor)).fetchone()
    return {'consents': count, 'charged_bytes': charged}


def admit_consent(db, configured, binding, actor, payload, preview):
    usage = consent_usage(db, binding, actor)
    if (usage['consents'] >= configured['capacity'] or
            usage['charged_bytes'] + size(payload) + size(preview) + CONSENT_RESERVE > configured['byte_capacity']):
        raise StorageFull('Human consent admission full; read history and retry saved confirmations. Increase configured limits to create another preview; never clear state.')
