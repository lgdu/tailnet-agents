"""Opt-in simulated heartbeat runtime; restore existing keys, grants and group."""
import argparse
import fcntl
import json
import math
import os
from pathlib import Path
import secrets
import signal
import sqlite3
import stat
import threading
import time
from urllib.error import HTTPError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .discovery import origin
from .identity import AdmissionError, GRANT_TYPE, decode, identity_id, load_identity, verify, verify_grant
from .presence import MAX_COUNTER, canonical_record, make_presence
from .verified_client import VerifiedClient


class RuntimeState:
    """One private, exclusively locked SQLite file per independent Agent runtime."""
    def __init__(self, path, owner, subject, group_id):
        self.db = self.descriptor = None
        self.lock = threading.Lock()
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(self.descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError('runtime state must be an owned regular private file')
            fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.db = sqlite3.connect(path, check_same_thread=False)
            with self.db:
                self.db.execute('CREATE TABLE IF NOT EXISTS runtime_context (id INTEGER PRIMARY KEY CHECK(id=1),owner TEXT NOT NULL,subject TEXT NOT NULL,group_id TEXT NOT NULL,generation INTEGER NOT NULL,sequence INTEGER NOT NULL)')
                self.db.execute('BEGIN IMMEDIATE')
                row = self.db.execute('SELECT owner,subject,group_id,generation FROM runtime_context WHERE id=1').fetchone()
                expected = (owner, subject, group_id)
                if row is not None and row[:3] != expected:
                    raise AdmissionError('cannot replace original runtime identity, owner or group')
                if row is not None and (type(row[3]) is not int or not 1 <= row[3] < MAX_COUNTER):
                    raise ValueError('invalid/exhausted saved runtime generation; preserve original state')
                self.generation = 1 if row is None else row[3] + 1
                if not 1 <= self.generation <= MAX_COUNTER:
                    raise ValueError('runtime generation exhausted; do not reset identity/state')
                self.db.execute('INSERT INTO runtime_context VALUES(1,?,?,?,?,0) ON CONFLICT(id) DO UPDATE SET generation=excluded.generation,sequence=0', (*expected, self.generation))
            self.boot_id = secrets.token_hex(16)
            self.sequence = 0
        except BaseException:
            self.close()
            raise

    def next_sequence(self):
        with self.lock:
            with self.db:
                if self.sequence >= MAX_COUNTER:
                    raise ValueError('runtime sequence exhausted')
                sequence = self.sequence + 1
                self.db.execute('UPDATE runtime_context SET sequence=? WHERE id=1', (sequence,))
            self.sequence = sequence  # Commit before signing/sending; skipped numbers are safe.
            return sequence

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None


class AgentRuntime:
    def __init__(self, url, key, owner, grant, group_id, audience, state_path, record, *, interval=5, ca_file=None, clock=time.time, stop=None):
        if not isinstance(audience, str) or not 1 <= len(audience) <= 128:
            raise ValueError('explicit directory audience required')
        self.record = canonical_record({'name': 'Simulated Agent', 'protocol': 'simulation-runtime', 'ttl_seconds': 30} | record)
        if type(interval) not in (int, float) or not math.isfinite(interval) or not 1 <= interval <= 60 or interval >= self.record['ttl_seconds']:
            raise ValueError('runtime interval must be 1..60 seconds and below lease TTL')
        claims = verify(grant, owner, GRANT_TYPE)
        if type(claims.get('iat')) is not int:
            raise AdmissionError('invalid saved grant')
        verify_grant(grant, owner, group_id, now=claims['iat'])
        subject = identity_id(key.public_key())
        if claims['sub'] != subject or subject == identity_id(owner):
            raise AdmissionError('existing Agent identity must match grant and differ from owner')
        self.client = VerifiedClient(origin(url), key, grant, audience, ca_file=ca_file, timeout=2)
        self.key, self.owner, self.grant, self.group_id = key, owner, grant, group_id
        self.clock, self.interval = clock, interval
        self.stop = threading.Event() if stop is None else stop
        self.lock = threading.Lock()
        self.state = RuntimeState(state_path, identity_id(owner), subject, group_id)
        self.subject = subject

    def guard(self):
        if self.stop.is_set():
            raise InterruptedError('runtime stopping')

    def step(self, *, offline=False):
        with self.lock:
            result = {'subject': self.subject, 'group_id': self.group_id, 'generation': self.state.generation,
                      'boot_id': self.state.boot_id, 'sequence': self.state.sequence, 'state': 'waiting', 'expires_at': None}
            if self.state.db is None:
                return result | {'state': 'stopped'}
            try:
                if not offline:self.guard()
                claims = verify_grant(self.grant, self.owner, self.group_id, now=self.clock())
                sequence = self.state.next_sequence()
                result['sequence'] = sequence
                now = self.clock()
                token = make_presence(self.key, self.owner, self.group_id, self.record, self.state.generation,
                                      self.state.boot_id, sequence, state='offline' if offline else 'online', now=now,
                                      expires_at=min(now + self.record['ttl_seconds'], claims['exp']))
                acknowledgment = self.client.register(self.record, presence=token, guard=None if offline else self.guard)
                if not offline:self.guard()
                expected = {'generation': self.state.generation, 'boot_id': self.state.boot_id, 'sequence': sequence,
                            'state': 'offline' if offline else 'online'}
                observed = acknowledgment.get('presence') if isinstance(acknowledgment, dict) else None
                ttl = acknowledgment.get('ttl_seconds') if isinstance(acknowledgment, dict) else None
                if (not isinstance(acknowledgment, dict) or set(acknowledgment) != {'id', 'ttl_seconds', 'presence'} or
                        acknowledgment['id'] != 'agent-' + self.subject.split(':')[1] or type(ttl) is not int or
                        not (ttl == 0 if offline else 1 <= ttl <= self.record['ttl_seconds']) or
                        not isinstance(observed, dict) or set(observed) != set(expected) | {'expires_at'} or
                        any(type(observed[field]) is not int for field in ('generation', 'sequence')) or
                        any(observed[field] != value for field, value in expected.items()) or
                        type(observed['expires_at']) not in (int, float) or not math.isfinite(observed['expires_at']) or
                        not 0 <= observed['expires_at'] <= min(now + self.record['ttl_seconds'], claims['exp']) or
                        (not offline and self.clock() >= observed['expires_at'])):
                    raise ValueError('invalid runtime acknowledgment')
                return result | {'state': 'offline' if offline else 'registered', 'expires_at': observed['expires_at'], 'lease_seconds': ttl}
            except InterruptedError:
                return result | {'state': 'stopped'}
            except AdmissionError:
                return result | {'state': 'waiting_authorization'}
            except HTTPError as error:
                return result | {'state': 'conflict' if error.code == 409 else 'waiting_authorization' if error.code == 403 else 'waiting'}
            except (ValueError, OSError, sqlite3.Error):
                return result

    def run(self, emit):
        try:
            while not self.stop.is_set():
                result = self.step()
                emit(result)
                delay = min(self.interval, max(1, result.get('lease_seconds', self.record['ttl_seconds']) / 3))
                self.stop.wait(delay)
        finally:
            emit(self.step(offline=True))  # Best effort; denied/unreachable recipients expire the old lease.

    def close(self):
        self.stop.set()
        with self.lock:
            self.state.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True, help='explicit trusted directory origin, never from discovery')
    parser.add_argument('--agent-key', required=True)
    parser.add_argument('--authority-public-key', required=True)
    parser.add_argument('--grant-file', required=True)
    parser.add_argument('--group-id', required=True)
    parser.add_argument('--audience', required=True)
    parser.add_argument('--state', required=True, help='private persistent SQLite file for this Agent only')
    parser.add_argument('--record-file', required=True, help='simulation metadata; no executor is started')
    parser.add_argument('--ca-cert')
    parser.add_argument('--interval', type=float, default=5)
    parser.add_argument('--once', action='store_true', help='one heartbeat; its lease expires normally')
    args = parser.parse_args()
    try:
        owner = Ed25519PublicKey.from_public_bytes(decode(Path(args.authority_public_key).read_text().strip()))
        runtime = AgentRuntime(args.url, load_identity(args.agent_key), owner, Path(args.grant_file).read_text().strip(),
                               args.group_id, args.audience, args.state, json.loads(Path(args.record_file).read_text()),
                               interval=args.interval, ca_file=args.ca_cert)
    except (ValueError, TypeError, OSError, sqlite3.Error):
        parser.exit(1, 'Runtime configuration failed; retain original keys/group/state and check grant, private file and TLS configuration.\n')
    emit = lambda result: print(json.dumps(result), flush=True)
    try:
        emit({'state': 'restoring_original_group', 'subject': runtime.subject, 'group_id': runtime.group_id,
              'generation': runtime.state.generation, 'boot_id': runtime.state.boot_id})
        if args.once:
            result = runtime.step()
            emit(result)
            if result['state'] != 'registered':return_code = 1
            else:return_code = 0
        else:
            previous = {name: signal.signal(name, lambda *_: runtime.stop.set()) for name in (signal.SIGINT, signal.SIGTERM)}
            try:runtime.run(emit)
            finally:
                for name, value in previous.items():signal.signal(name, value)
            return_code = 0
    finally:
        runtime.close()
    if return_code:raise SystemExit(return_code)


if __name__ == '__main__':
    main()
