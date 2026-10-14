"""Explicit delivery to administrator-configured origins; never discover recipients."""
import hashlib
import json
import os
from pathlib import Path
import re

from .client import Client
from .discovery import origin
from .group_policy import POLICY_FUTURE_SKEW, verify_policy
from .identity import unique_object


def policy_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


class PolicyTarget:
    def __init__(self, target_id, url, group_id, token, ca_file=None):
        if (not isinstance(target_id, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', target_id) or
                not isinstance(group_id, str) or not 1 <= len(group_id) <= 128 or
                not isinstance(token, str) or len(token) < 32 or any(not 33 <= ord(c) <= 126 for c in token)):
            raise ValueError('invalid configured policy recipient or credential')
        self.id, self.url, self.group_id = target_id, origin(url), group_id
        ca_hash = None if ca_file is None else hashlib.sha256(Path(ca_file).read_bytes()).hexdigest()
        self.fingerprint = policy_hash(json.dumps([self.id, self.url, self.group_id, ca_hash]))
        self.client = Client(self.url, token, timeout=2, ca_file=ca_file)

    def public(self):
        return {'id': self.id, 'url': self.url, 'group_id': self.group_id, 'fingerprint': self.fingerprint}

    def _read(self, owner):
        response = self.client.request('/v1/policies')
        if not isinstance(response, dict) or set(response) != {'policy'}:
            raise ValueError('invalid recipient policy response')
        token = response['policy']
        return token, None if token is None else verify_policy(token, owner, self.group_id)

    def deliver(self, token, owner, clock, guard):
        claims = verify_policy(token, owner, self.group_id)
        previous, remote = self._read(owner)
        if previous != token:
            if remote is not None and (remote['state'] == 'dissolved' or remote['revision'] >= claims['revision'] or remote['issued_at'] > claims['issued_at']):
                raise FileExistsError('接收方已有更新或冲突策略，请核对双方版本。')
            guard()  # Recheck local consent after preflight, outside network I/O.
            ack = self.client.request('/v1/policies', {'policy': token})
            if (not isinstance(ack, dict) or type(ack.get('revision')) is not int or
                    ack != {'group_id': self.group_id, 'revision': claims['revision'], 'state': claims['state']}):
                raise ValueError('invalid recipient acknowledgment')
        observed, _ = self._read(owner)
        if observed != token:
            raise FileExistsError('接收方策略已变化，请核对后重新预览。')
        response = self.client.request('/v1/policy-sync')
        freshness = response.get('policy') if isinstance(response, dict) else None
        if (not isinstance(freshness, dict) or set(freshness) != {'state', 'revision', 'issued_at', 'expires_at', 'max_age'} or
                type(freshness['max_age']) is not int or not 1 <= freshness['max_age'] <= 86400 or
                type(freshness['revision']) is not int or freshness['revision'] != claims['revision'] or
                type(freshness['issued_at']) is not int or freshness['issued_at'] != claims['issued_at'] or
                type(freshness['expires_at']) is not int or freshness['expires_at'] != claims['issued_at'] + freshness['max_age'] or
                freshness['state'] not in ('fresh', 'stale', 'future', 'dissolved') or
                (freshness['state'] == 'dissolved') != (claims['state'] == 'dissolved')):
            raise ValueError('invalid recipient freshness response')
        now = clock()
        local_state = ('dissolved' if claims['state'] == 'dissolved' else
                       'future' if claims['issued_at'] > now + POLICY_FUTURE_SKEW else
                       'stale' if now >= freshness['expires_at'] else 'fresh')
        state = local_state if local_state != 'fresh' else freshness['state']
        return {'target': self.public(), 'group_id': self.group_id,
                'revision': claims['revision'], 'policy_hash': policy_hash(token),
                'policy_state': claims['state'], 'authorization_state': state,
                'expires_at': freshness['expires_at'], 'max_age': freshness['max_age'],
                'checked_at': now}


def load_policy_targets(path):
    data = Path(path).read_bytes()
    if len(data) > 16384:
        raise ValueError('policy recipient configuration exceeds 16 KiB')
    entries = json.loads(data, object_pairs_hook=unique_object)
    if not isinstance(entries, list) or not 1 <= len(entries) <= 8:
        raise ValueError('configure 1..8 explicit policy recipients')
    targets = []
    for entry in entries:
        if (not isinstance(entry, dict) or not {'id', 'url', 'group_id', 'token_env'} <= set(entry) or
                set(entry) - {'id', 'url', 'group_id', 'token_env', 'ca_cert'} or
                not isinstance(entry['token_env'], str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', entry['token_env'])):
            raise ValueError('invalid policy recipient configuration')
        ca = entry.get('ca_cert')
        if ca is not None:
            if not isinstance(ca, str) or not ca:
                raise ValueError('invalid recipient CA path')
            ca = str(Path(path).parent / ca)
        target = PolicyTarget(entry['id'], entry['url'], entry['group_id'], os.environ.get(entry['token_env'], ''), ca)
        if any(target.id == other.id or target.url == other.url for other in targets):
            raise ValueError('duplicate policy recipient')
        targets.append(target)
    return targets
