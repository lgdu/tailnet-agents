"""Pull owner-signed policy from an explicitly configured HTTP/TLS peer."""
import argparse
import os
import re
from pathlib import Path
import threading
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .client import Client
from .group_policy import verify_policy
from .verified_directory import REVOCATION_TYPE
from .identity import AdmissionError, decode, verify


def fetch_policy(client, owner_key, group_id):
    response = client.request('/v1/policies')
    if not isinstance(response, dict) or set(response) != {'policy'}:
        raise AdmissionError('invalid policy response')
    token = response['policy']
    if token is not None:
        verify_policy(token, owner_key, group_id)
    return token


def pull_revocations(source, owner_key, group_id, apply, checkpoint, max_pages=10):
    """Bounded incremental pull. Records are signed; cursors are only routing hints.

    Callback returns False when shutting down. Cursor advances only after apply.
    A new source database generation restarts scanning from zero.
    """
    if checkpoint.get('scan_complete'):
        checkpoint.update(after=0,scan_complete=False)
    for _ in range(max_pages):
        after = checkpoint['after']
        page = source.request('/v1/revocations?after='+str(after)+'&limit=100')
        if (not isinstance(page, dict) or set(page) != {'generation','entries','next_cursor','has_more'} or
                not isinstance(page['generation'], str) or not re.fullmatch(r'[a-f0-9]{32}',page['generation']) or
                not isinstance(page['entries'], list) or len(page['entries']) > 100 or
                type(page['next_cursor']) is not int or not 0 <= page['next_cursor'] <= 2**53-1 or
                type(page['has_more']) is not bool):
            raise AdmissionError('invalid revocation page')
        if checkpoint['generation'] != page['generation']:
            checkpoint.update(generation=page['generation'], after=0)
            if after != 0:
                continue  # Refetch the new generation from its beginning.
        cursor = checkpoint['after']
        for entry in page['entries']:
            if (not isinstance(entry, dict) or set(entry) != {'sequence','revocation'} or
                    type(entry['sequence']) is not int or not cursor < entry['sequence'] <= 2**53-1):
                raise AdmissionError('invalid revocation entry')
            cursor = entry['sequence']
        if page['next_cursor'] != cursor or (page['has_more'] and not page['entries']):
            raise AdmissionError('revocation cursor did not advance')
        for entry in page['entries']:
            claims = verify(entry['revocation'], owner_key, REVOCATION_TYPE)
            if (set(claims) != {'group_id','jti'} or claims['group_id'] != group_id or
                    not isinstance(claims['jti'],str) or not re.fullmatch(r'[a-f0-9]{32}',claims['jti'])):
                raise AdmissionError('invalid signed revocation scope')
            if apply(entry['revocation']) is False:
                return False
            checkpoint['after'] = entry['sequence']
        if not page['has_more']:
            checkpoint['scan_complete'] = True
            return True
    return False


def sync_remote(source, target, owner_key, group_id):
    token = fetch_policy(source, owner_key, group_id)
    if token is None:
        return None
    claims = verify_policy(token, owner_key, group_id)
    result = target.request('/v1/policies', {'policy': token})
    expected = {k: claims[k] for k in ('group_id', 'revision', 'state')}
    if result != expected:
        raise AdmissionError('unexpected target response')
    checkpoint = {'generation': None, 'after': 0}
    def relay(proof):
        response = target.request('/v1/revocations', {'revocation': proof})
        if not isinstance(response, dict) or set(response) != {'revoked'} or response['revoked'] is not True:
            raise AdmissionError('unexpected revocation acknowledgment')
    complete = pull_revocations(source, owner_key, group_id, relay, checkpoint, max_pages=100)
    return result | {'revocations_complete': complete}


class PolicySynchronizer:
    """Single configured source, periodic full snapshots, no discovery/election.

    Failures retain the last accepted policy. No policy-freshness guarantee exists.
    Never hold a directory lock during network I/O. stop() blocks future applies.
    """
    def __init__(self, directory, client, interval=10, clock=time.time):
        if not directory.require_policy:
            raise AdmissionError('policy mode required for synchronization')
        if type(interval) not in (int, float) or not 1 <= interval <= 3600:
            raise ValueError('policy interval must be 1..3600 seconds')
        self.directory, self.client, self.interval, self.clock = directory, client, interval, clock
        self._stopped = threading.Event()
        self._apply_lock = threading.Lock()
        self._attempt_lock = threading.Lock()
        self._thread = None
        self._revocations = {'generation': None, 'after': 0}
        self._status = {'state': 'idle', 'last_attempt': None, 'last_success': None, 'revision': None, 'revocation_cursor': 0}

    def status(self):
        with self._apply_lock:
            return dict(self._status)

    def sync_once(self):
        with self._attempt_lock:
            with self._apply_lock:
                if self._stopped.is_set():
                    return dict(self._status)
                self._status['last_attempt'] = self.clock()
            try:
                token = fetch_policy(self.client, self.directory.owner_key, self.directory.group_id)
                with self._apply_lock:
                    if self._stopped.is_set():
                        return dict(self._status)
                    if token is not None:
                        result = self.directory.apply_policy(token)
                        self._status['revision'] = result['revision']
                def apply_revocation(proof):
                    with self._apply_lock:
                        if self._stopped.is_set():
                            return False
                        self.directory.revoke(proof)
                complete = pull_revocations(self.client, self.directory.owner_key,
                    self.directory.group_id, apply_revocation, self._revocations)
                with self._apply_lock:
                    if not self._stopped.is_set():
                        self._status['revocation_cursor'] = self._revocations['after']
                        self._status['state'] = 'catching_up' if not complete else ('waiting' if token is None else 'synced')
                        if complete and token is not None:
                            self._status['last_success'] = self.clock()
                    return dict(self._status)
            except Exception:
                with self._apply_lock:
                    if not self._stopped.is_set():
                        self._status['state'] = 'error'
                raise

    def _run(self):
        while not self._stopped.is_set():
            try:
                self.sync_once()
            except Exception:
                # Status reports failure without logging tokens or transport details.
                pass
            self._stopped.wait(self.interval)

    def start(self):
        with self._apply_lock:
            if self._stopped.is_set() or self._thread is not None:
                raise RuntimeError('synchronizer cannot be started twice or after stop')
            self._thread = threading.Thread(target=self._run, daemon=True, name='policy-sync')
            self._thread.start()

    def stop(self):
        self._stopped.set()
        with self._apply_lock:
            self._status['state'] = 'stopped'
        # Even if a slow network call outlives this join, it cannot touch the DB.
        if self._thread is not None:
            self._thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-url', required=True)
    parser.add_argument('--target-url', required=True)
    parser.add_argument('--authority-public-key', required=True)
    parser.add_argument('--group-id', required=True)
    parser.add_argument('--source-ca-cert')
    parser.add_argument('--target-ca-cert')
    args = parser.parse_args()
    try:
        source_token = os.environ.get('TAILNET_POLICY_PEER_TOKEN', '')
        target_token = os.environ.get('TAILNET_VERIFIED_READ_TOKEN', '')
        if any(len(t) < 32 or not t.isascii() for t in (source_token, target_token)):
            raise ValueError('source and target read tokens required')
        owner = Ed25519PublicKey.from_public_bytes(decode(Path(args.authority_public_key).read_text().strip()))
        source = Client(args.source_url, source_token, ca_file=args.source_ca_cert)
        target = Client(args.target_url, target_token, ca_file=args.target_ca_cert)
        result = sync_remote(source, target, owner, args.group_id)
        if result is not None and not result['revocations_complete']:
            parser.exit(1, 'Policy applied; revocation scan incomplete. Use periodic service sync for large histories.\n')
        if result is None:
            parser.exit(1, 'Source has no policy; no target changes made.\n')
    except (ValueError, OSError):
        parser.exit(1, 'Policy sync failed; check pinned authority, group, credentials and connectivity.\n')
    import json
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
