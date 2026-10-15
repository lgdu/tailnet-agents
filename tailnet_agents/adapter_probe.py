"""Nonce-bound metadata from an explicitly pinned synthetic executor; no task calls."""
import math
import re
import secrets
import time

from .adapters import echo_contract, validate_contract, contract_hash
from .client import Client
from .discovery import origin
from .identity import AdmissionError, identity_id, sign, verify

DESCRIPTOR_TYPE = 'tailnet-agent-adapter-descriptor+jwt'
PROBE_LIFETIME = 15
FUTURE_SKEW = 5


def nonce_valid(value):
    return isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value) is not None


def context_valid(group, audience):
    return all(isinstance(value, str) and 1 <= len(value) <= 128 for value in (group, audience))


def signed_descriptor(executor, nonce, source):
    if not nonce_valid(nonce):raise ValueError('invalid probe nonce')
    directory = executor.directory
    grant = executor._authorize(executor.grant, executor.subject)
    policy = directory._policy.current()
    now = directory.clock()
    expires = min(now + PROBE_LIFETIME, grant['exp'], policy['issued_at'] + directory.policy_max_age)
    if type(now) not in (int, float) or not math.isfinite(now) or not 0 <= now < expires <= 2**53 - 1:
        raise AdmissionError('metadata interval unavailable')
    return sign(executor.key, {'version': 1, 'owner': identity_id(directory.owner_key), 'group_id': directory.group_id,
        'audience': directory._admission.audience, 'executor': executor.subject, 'source': origin(source),
        'nonce': nonce, 'issued_at': now, 'expires_at': expires, 'contract': echo_contract()}, DESCRIPTOR_TYPE)


def verify_descriptor(token, key, owner, group, audience, source, nonce, *, now):
    if (not context_valid(group, audience) or not nonce_valid(nonce) or type(now) not in (int, float) or
            not math.isfinite(now) or not 0 <= now <= 2**53 - 1):raise ValueError('invalid probe context')
    claim = verify(token, key, DESCRIPTOR_TYPE)
    expected = {'version', 'owner', 'group_id', 'audience', 'executor', 'source', 'nonce', 'issued_at', 'expires_at', 'contract'}
    if (set(claim) != expected or type(claim['version']) is not int or claim['version'] != 1 or
            claim['owner'] != identity_id(owner) or claim['group_id'] != group or claim['audience'] != audience or
            claim['executor'] != identity_id(key) or claim['source'] != origin(source) or claim['nonce'] != nonce or
            any(type(claim[field]) not in (int, float) or not math.isfinite(claim[field]) or not 0 <= claim[field] <= 2**53 - 1
                for field in ('issued_at', 'expires_at')) or
            not 0 < claim['expires_at'] - claim['issued_at'] <= PROBE_LIFETIME or
            claim['issued_at'] > now + FUTURE_SKEW or now >= claim['expires_at']):
        raise AdmissionError('invalid, mismatched or expired adapter descriptor')
    validate_contract(claim['contract'])
    return claim


def probe(url, token, owner, group, audience, executor_key, *, ca_file=None, clock=time.time):
    if (not context_valid(group, audience) or identity_id(owner) == identity_id(executor_key) or
            not isinstance(token, str) or len(token) < 32 or any(not 33 <= ord(c) <= 126 for c in token)):
        raise ValueError('explicit pins, context and read credential required')
    source, nonce = origin(url), secrets.token_hex(32)
    response = Client(source, token, timeout=2, ca_file=ca_file).request('/v1/task-adapter-probe', {'nonce': nonce})
    if not isinstance(response, dict) or set(response) != {'descriptor'}:raise ValueError('invalid adapter probe response')
    checked = clock()
    if type(checked) not in (int, float) or not math.isfinite(checked) or not 0 <= checked <= 2**53 - 1:
        raise ValueError('invalid local clock')
    claim = verify_descriptor(response['descriptor'], executor_key, owner, group, audience, source, nonce, now=checked)
    return {'source': source, 'owner': claim['owner'], 'group_id': group, 'audience': audience, 'executor': claim['executor'],
            'status': 'compatible_metadata', 'contract': claim['contract'], 'contract_hash': contract_hash(claim['contract']),
            'checked_at': checked, 'valid_until': claim['expires_at'], 'execution': 'not_attempted',
            'execution_authorization': 'not_checked', 'product_integration': 'simulation_only'}
