"""Explicit source comparison and durable owner-signed history evidence."""
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPException
import hashlib
import json

from .group_policy import POLICY_FUTURE_SKEW, verify_policy
from .identity import AdmissionError
from .policy_delivery import policy_hash


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def bind(db, owner):
    db.execute('CREATE TABLE IF NOT EXISTS ui_policy_evidence (group_id TEXT NOT NULL,revision INTEGER NOT NULL,semantic_hash TEXT NOT NULL,token TEXT NOT NULL,source TEXT NOT NULL,observed REAL NOT NULL,PRIMARY KEY(group_id,revision,semantic_hash))')
    for group, revision, fingerprint, token in db.execute('SELECT group_id,revision,semantic_hash,token FROM ui_policy_evidence'):
        claim = verify_policy(token, owner, group)
        if claim['revision'] != revision or digest(claim) != fingerprint:
            raise AdmissionError('invalid persisted policy evidence')


def remember(db, owner, group, token, source, now):
    claim = verify_policy(token, owner, group)
    db.execute('INSERT OR IGNORE INTO ui_policy_evidence VALUES(?,?,?,?,?,?)',
               (group, claim['revision'], digest(claim), token, source, now))


def evidence(db, owner, group, local_token):
    local = verify_policy(local_token, owner, group)
    rows = db.execute('SELECT revision,semantic_hash,token FROM ui_policy_evidence WHERE group_id=? ORDER BY revision,semantic_hash', (group,)).fetchall()
    facts = [(revision, fingerprint, verify_policy(token, owner, group)) for revision, fingerprint, token in rows]
    reasons, grouped = [], {}
    for revision, fingerprint, claim in facts:grouped.setdefault(revision, []).append(claim)
    latest_time, terminal_revision = -1, None
    for revision, claims in grouped.items():
        if len(claims) > 1:reasons.append('equivocation')
        if any(claim['issued_at'] < latest_time for claim in claims):reasons.append('time_rollback')
        if terminal_revision is not None:reasons.append('after_dissolution')
        latest_time = max([latest_time] + [claim['issued_at'] for claim in claims])
        if any(claim['state'] == 'dissolved' for claim in claims):terminal_revision = revision
    head = max([local['revision']] + [revision for revision, _, _ in facts])
    if head > local['revision']:reasons.append('remote_ahead')
    if terminal_revision is not None and local['state'] != 'dissolved':reasons.append('known_dissolution')
    reasons = sorted(set(reasons))
    return {'head_revision': head, 'conflicts': reasons, 'terminal_known': terminal_revision is not None,
            'can_renew': local['state'] == 'active' and not reasons,
            'digest': digest([(revision, fingerprint) for revision, fingerprint, _ in facts]),
            'statements': len(facts)}


def require_safe(db, owner, group, token):
    status = evidence(db, owner, group, token)
    if status['conflicts']:
        raise FileExistsError('已知签名策略存在更高版本、冲突或终止证据；请恢复权威历史后再签名。')
    return status


def summary(token, claim):
    return {'revision': claim['revision'], 'policy_hash': policy_hash(token),
            'semantic_hash': digest(claim), 'issued_at': claim['issued_at'], 'state': claim['state']}


def read_source(target, owner, local_token, clock):
    tokens = []
    result = {'target': target.public(), 'state': 'error', 'policy': None, 'freshness': None,
              'relation': 'unknown', 'checked_at': None}
    def read():
        token, claim = target._read(owner)
        if token is not None:tokens.append(token)
        return token, claim
    try:
        token, claim = read()
        response = target.client.request('/v1/policy-sync')
        status = response.get('policy') if isinstance(response, dict) else None
        if (not isinstance(status, dict) or set(status) != {'state', 'revision', 'issued_at', 'expires_at', 'max_age'} or
                type(status['max_age']) is not int or not 1 <= status['max_age'] <= 86400):
            raise ValueError('invalid policy freshness')
        latest, latest_claim = read()
        if latest != token:
            result.update(state='changing', policy=None if latest is None else summary(latest, latest_claim))
            return result, tokens
        if claim is None:
            if status != {'state': 'missing', 'revision': None, 'issued_at': None, 'expires_at': None, 'max_age': status['max_age']}:
                raise ValueError('invalid missing policy')
            result.update(state='missing', relation='missing', freshness=status)
        else:
            if (type(status['revision']) is not int or status['revision'] != claim['revision'] or
                    type(status['issued_at']) is not int or status['issued_at'] != claim['issued_at'] or
                    type(status['expires_at']) is not int or status['expires_at'] != claim['issued_at'] + status['max_age'] or
                    status['state'] not in ('fresh', 'stale', 'future', 'dissolved') or
                    (status['state'] == 'dissolved') != (claim['state'] == 'dissolved')):
                raise ValueError('freshness does not match signed policy')
            now = clock()
            conservative = ('dissolved' if claim['state'] == 'dissolved' else
                            'future' if claim['issued_at'] > now + POLICY_FUTURE_SKEW else
                            'stale' if now >= status['expires_at'] else 'fresh')
            state = conservative if conservative != 'fresh' else status['state']
            local = verify_policy(local_token, owner, target.group_id)
            relation = ('same' if token == local_token else 'equivalent' if claim == local else
                        'ahead' if claim['revision'] > local['revision'] else
                        'behind' if claim['revision'] < local['revision'] else 'conflict')
            result.update(state='read', policy=summary(token, claim), freshness=status | {'state': state}, relation=relation)
    except (ValueError, TypeError, KeyError, OSError, HTTPException):
        result['error'] = '读取失败；请核对来源配置、授权与证书。'
    finally:result['checked_at'] = clock()
    return result, tokens


def read_sources(targets, owner, local_token, clock):
    if not targets:return []
    with ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
        futures = [pool.submit(read_source, target, owner, local_token, clock) for target in targets]
        return [future.result() for future in futures]


def targets_digest(targets):
    return digest([target.public() for target in targets])


def preview(authority, db, group, targets):
    token, claim = authority.current(db, group)
    status = require_safe(db, authority.key.public_key(), group, token)
    if claim['state'] != 'active':raise PermissionError('群组已终止，不能续期。')
    now = int(authority.clock())
    if now < claim['issued_at']:raise ValueError('本机时钟早于当前策略，不能续期。')
    consent = {'group_id': group, 'owner': authority.owner, 'expected_revision': claim['revision'],
               'policy_hash': policy_hash(token), 'issued_at': now, 'preview_expires_at': now + 60,
               'evidence_hash': status['digest'], 'targets_fingerprint': targets_digest(targets)}
    return consent | {'consent_hash': digest(consent)}


def confirm(authority, db, group, payload, targets):
    expected = {'request_id', 'expected_revision', 'policy_hash', 'issued_at', 'preview_expires_at',
                'evidence_hash', 'targets_fingerprint', 'consent_hash'}
    if (not isinstance(payload, dict) or set(payload) != expected or
            not isinstance(payload['request_id'], str) or not 1 <= len(payload['request_id']) <= 128 or
            any(type(payload[field]) is not int for field in ('expected_revision', 'issued_at', 'preview_expires_at')) or
            any(not isinstance(payload[field], str) or len(payload[field]) != 64 or
                any(c not in '0123456789abcdef' for c in payload[field])
                for field in ('policy_hash', 'evidence_hash', 'targets_fingerprint', 'consent_hash'))):
        raise ValueError('invalid renewal consent')
    canonical = json.dumps(payload | {'operation': 'renew-reviewed'}, sort_keys=True)
    previous = db.execute('SELECT payload,result FROM ui_policy_requests WHERE group_id=? AND request_id=?', (group, payload['request_id'])).fetchone()
    if previous:
        if previous[0] != canonical:raise FileExistsError('续期请求 ID 已用于另一组确认内容。')
        return json.loads(previous[1])
    token, claim = authority.current(db, group)
    status = require_safe(db, authority.key.public_key(), group, token)
    if claim['state'] != 'active':raise PermissionError('群组已终止，不能续期。')
    consent = {field: payload[field] for field in expected - {'request_id', 'consent_hash'}}
    consent |= {'owner': authority.owner, 'group_id': group}
    if (payload['expected_revision'] != claim['revision'] or payload['policy_hash'] != policy_hash(token) or
            payload['evidence_hash'] != status['digest'] or payload['targets_fingerprint'] != targets_digest(targets) or
            payload['consent_hash'] != digest(consent)):
        raise FileExistsError('策略、证据或来源配置已变化，请重新核对并预览。')
    if (not claim['issued_at'] <= payload['issued_at'] <= authority.clock() < payload['preview_expires_at'] or
            payload['preview_expires_at'] != payload['issued_at'] + 60):
        raise ValueError('续期预览已失效或本机时钟回退，请重新预览。')
    from .group_policy import revise_policy
    updated = revise_policy(authority.key, token, claim['members'], now=payload['issued_at'])
    result = authority._save(db, group, updated, 'renew', group)
    db.execute('INSERT INTO ui_policy_requests VALUES(?,?,?,?)', (group, payload['request_id'], canonical, json.dumps(result)))
    return result
