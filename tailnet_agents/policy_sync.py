"""Pull owner-signed policy from an explicitly configured HTTP/TLS peer."""
import argparse
import os
from pathlib import Path
import threading
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .client import Client
from .group_policy import verify_policy
from .identity import AdmissionError, decode


def fetch_policy(client, owner_key, group_id):
    response = client.request('/v1/policies')
    if not isinstance(response, dict) or set(response) != {'policy'}:
        raise AdmissionError('invalid policy response')
    token = response['policy']
    if token is not None:
        verify_policy(token, owner_key, group_id)
    return token


def sync_remote(source, target, owner_key, group_id):
    token = fetch_policy(source, owner_key, group_id)
    if token is None:
        return None
    claims = verify_policy(token, owner_key, group_id)
    result = target.request('/v1/policies', {'policy': token})
    expected = {k: claims[k] for k in ('group_id', 'revision', 'state')}
    if result != expected:
        raise AdmissionError('unexpected target response')
    return result


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
        self._status = {'state': 'idle', 'last_attempt': None, 'last_success': None, 'revision': None}

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
                    if token is None:
                        self._status['state'] = 'waiting'
                    else:
                        result = self.directory.apply_policy(token)
                        self._status.update(state='synced', last_success=self.clock(), revision=result['revision'])
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
        if result is None:
            parser.exit(1, 'Source has no policy; no target changes made.\n')
    except (ValueError, OSError):
        parser.exit(1, 'Policy sync failed; check pinned authority, group, credentials and connectivity.\n')
    import json
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
