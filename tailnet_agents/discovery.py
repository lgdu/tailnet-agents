"""Credential-free candidate discovery; never enroll peers or create groups."""
import argparse
from contextlib import closing
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import struct
import sys
import threading
import time
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .client import NoRedirect, validate_url
from .group_policy import POLICY_FUTURE_SKEW, verify_policy
from .identity import (AdmissionError, REVOCATION_TYPE, decode, encode, identity_id, public_bytes,
                       sign, unique_object, verify)

ANNOUNCEMENT_TYPE = 'tailnet-discovery+jwt'
MULTICAST_GROUP = '239.255.77.77'
DISCOVERY_PORT = 8773
MAX_PACKET = 4096
MAX_PACKETS = 128  # Signature-verification attempts per one-second LAN window.


def origin(url):
    if (not isinstance(url, str) or len(url) > 1024 or
            any(ord(c) <= 32 or ord(c) >= 127 for c in url) or '?' in url or '#' in url):
        raise ValueError('an explicit HTTP/TLS origin is required')
    parsed = validate_url(url)
    if (parsed.path not in ('', '/') or
            not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', parsed.hostname) or
            (parsed.port is not None and not 1 <= parsed.port <= 65535)):
        raise ValueError('invalid discovery origin')
    port = parsed.port
    if port == (443 if parsed.scheme == 'https' else 80):
        port = None
    return parsed.scheme + '://' + parsed.hostname.lower() + (':' + str(port) if port else '')


def fresh_policy(token, owner, group_id, now, max_age=300):
    if type(max_age) is not int or not 1 <= max_age <= 86400:
        raise ValueError('policy maximum age must be 1..86400 seconds')
    policy = verify_policy(token, owner, group_id)
    if (policy['state'] != 'active' or policy['issued_at'] > now + POLICY_FUTURE_SKEW or
            now >= policy['issued_at'] + max_age):
        raise AdmissionError('fresh active group policy required for discovery')
    return policy


def make_announcement(key, policy_token, owner, group_id, endpoint, audience, *,
                      now=None, max_age=300, revoked=()):
    now = int(time.time()) if now is None else now
    if type(now) is not int or not isinstance(audience, str) or not 1 <= len(audience) <= 128:
        raise ValueError('invalid discovery timestamp or audience')
    policy = fresh_policy(policy_token, owner, group_id, now, max_age)
    subject = identity_id(key.public_key())
    member = policy['members'].get(subject)
    if member is None or not set(member['grant_ids']) - set(revoked):
        raise AdmissionError('existing policy-approved identity required')
    claims = {'version': 1, 'group_id': group_id, 'subject': subject,
              'policy_hash': hashlib.sha256(policy_token.encode()).hexdigest(),
              'endpoint': origin(endpoint), 'audience': audience,
              'issued_at': now, 'expires_at': min(now + 30, policy['issued_at'] + max_age)}
    envelope = {'public_key': encode(public_bytes(key.public_key())),
                'announcement': sign(key, claims, ANNOUNCEMENT_TYPE)}
    pack(envelope)
    return envelope


def verify_announcement(envelope, policy_token, owner, group_id, *, now=None, max_age=300, revoked=()):
    now = time.time() if now is None else now
    policy = fresh_policy(policy_token, owner, group_id, now, max_age)
    if not isinstance(envelope, dict) or set(envelope) != {'public_key', 'announcement'}:
        raise AdmissionError('invalid discovery envelope')
    pack(envelope)  # Enforce the same envelope size limit on both transports.
    key = Ed25519PublicKey.from_public_bytes(decode(envelope['public_key']))
    claims = verify(envelope['announcement'], key, ANNOUNCEMENT_TYPE)
    if (set(claims) != {'version', 'group_id', 'subject', 'policy_hash', 'endpoint', 'audience', 'issued_at', 'expires_at'} or
            type(claims['version']) is not int or claims['version'] != 1 or
            claims['group_id'] != group_id or claims['subject'] != identity_id(key) or
            claims['policy_hash'] != hashlib.sha256(policy_token.encode()).hexdigest() or
            type(claims['issued_at']) is not int or type(claims['expires_at']) is not int or
            not 0 < claims['expires_at'] - claims['issued_at'] <= 30 or
            claims['issued_at'] > now + 5 or now >= claims['expires_at'] or
            claims['expires_at'] > policy['issued_at'] + max_age or
            not isinstance(claims['audience'], str) or not 1 <= len(claims['audience']) <= 128):
        raise AdmissionError('invalid discovery scope or lifetime')
    member = policy['members'].get(claims['subject'])
    if member is None or not set(member['grant_ids']) - set(revoked):
        raise AdmissionError('identity is not a local policy candidate')
    if origin(claims['endpoint']) != claims['endpoint']:
        raise AdmissionError('noncanonical discovery endpoint')
    return claims


def pack(value):
    data = json.dumps(value, separators=(',', ':'), allow_nan=False).encode()
    if len(data) > MAX_PACKET:
        raise AdmissionError('discovery message exceeds 4096 bytes')
    return data


def unpack(data):
    if len(data) > MAX_PACKET:
        raise AdmissionError('discovery message exceeds 4096 bytes')
    return json.loads(data, object_pairs_hook=unique_object)


class Candidates:
    """Bounded scan-local results; signatures identify candidates, not admitted peers."""
    def __init__(self, policy_token, owner, group_id, *, max_age=300, clock=time.time, revoked=()):
        self.policy, self.owner, self.group_id = policy_token, owner, group_id
        self.max_age, self.clock, self.revoked = max_age, clock, frozenset(revoked)
        fresh_policy(policy_token, owner, group_id, clock(), max_age)
        self._records = {}
        self._conflicts = set()
        self._snapshot = None

    @classmethod
    def from_directory(cls, path, owner, group_id, *, max_age=None, clock=time.time):
        """Read synchronized state without opening Registry or resetting leases."""
        def snapshot():
            return directory_snapshot(path, owner, group_id, now=clock(), max_age=max_age)
        token, bound, revoked = snapshot()
        result = cls(token, owner, group_id, max_age=bound, clock=clock, revoked=revoked)
        result._snapshot = snapshot
        return result

    def add(self, envelope, source):
        now = self.clock()
        claims = verify_announcement(envelope, self.policy, self.owner, self.group_id,
                                     now=now, max_age=self.max_age, revoked=self.revoked)
        # Several independently approved subjects may share one host or origin.
        records = self._records.setdefault(claims['subject'], {})
        locator = (claims['endpoint'], claims['audience'])
        if records and locator not in records:
            self._conflicts.add(claims['subject'])
        if locator not in records and len(records) >= 2:
            return  # Two conflicting locators already suppress this identity.
        if locator not in records or claims['issued_at'] > records[locator][0]['issued_at']:
            records[locator] = (claims, {source})
        elif claims == records[locator][0]:
            records[locator][1].add(source)

    def result(self):
        if self._snapshot is not None:
            token, bound, revoked = self._snapshot()
            if token != self.policy:
                raise AdmissionError('directory policy changed during scan; retry')
            self.max_age = min(self.max_age, bound)
            self.revoked = self.revoked | revoked
        now = self.clock()
        policy = fresh_policy(self.policy, self.owner, self.group_id, now, self.max_age)
        candidates, conflicts = [], []
        for subject, locators in sorted(self._records.items()):
            if not set(policy['members'][subject]['grant_ids']) - self.revoked:
                continue
            live = [value for value in locators.values()
                    if value[0]['issued_at'] <= now + 5 and now < value[0]['expires_at'] <= policy['issued_at'] + self.max_age]
            if subject in self._conflicts:
                conflicts.append(subject)
            elif live:
                claims, sources = live[0]
                candidates.append(claims | {'sources': sorted(sources), 'admission': 'not_checked'})
        return {'candidates': candidates, 'conflicts': conflicts}


def directory_snapshot(path, owner, group_id, *, now, max_age=None):
    """Transactional, read-only view; relevant revocation proofs remain owner-pinned."""
    uri = Path(path).resolve(strict=True).as_uri() + '?mode=ro'
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=2)) as db:
            with db:
                db.execute('BEGIN')
                context = db.execute('SELECT owner_id,group_id FROM admission_context WHERE id=1').fetchone()
                mode = db.execute('SELECT required FROM admission_policy_mode WHERE id=1').fetchone()
                age = db.execute('SELECT max_age FROM admission_policy_freshness WHERE id=1').fetchone()
                row = db.execute('SELECT token FROM group_policy WHERE id=1').fetchone()
                if context != (identity_id(owner), group_id) or mode != (1,) or age is None or row is None:
                    raise AdmissionError('existing pinned policy-mode directory required')
                bound = age[0]
                if type(bound) is not int or not 1 <= bound <= 86400:
                    raise AdmissionError('invalid persisted policy maximum age')
                if max_age is not None:
                    if type(max_age) is not int or not 1 <= max_age <= bound:
                        raise AdmissionError('scanner may only tighten directory policy maximum age')
                    bound = max_age
                policy = fresh_policy(row[0], owner, group_id, now, bound)
                grants = sorted({jti for member in policy['members'].values() for jti in member['grant_ids']})
                revoked = set()
                if grants:
                    query = 'SELECT jti,proof FROM admission_revocations WHERE jti IN (' + ','.join('?' for _ in grants) + ')'
                    for jti, proof in db.execute(query, grants):
                        claims = verify(proof, owner, REVOCATION_TYPE)
                        if claims != {'group_id': group_id, 'jti': jti}:
                            raise AdmissionError('invalid persisted revocation proof')
                        revoked.add(jti)
                return row[0], bound, frozenset(revoked)
    except sqlite3.Error as error:
        raise AdmissionError('cannot read synchronized directory state') from error


class Seed:
    """Only explicit seed origins are contacted; no Authorization header or redirects."""
    def __init__(self, url, ca_file=None):
        self.url = origin(url)
        context = ssl.create_default_context(cafile=ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=context))

    def fetch(self):
        request = Request(self.url + '/v1/discovery', headers={'Accept': 'application/json'})
        with self.opener.open(request, timeout=2) as response:
            payload = unpack(response.read(MAX_PACKET + 1))
        if not isinstance(payload, dict) or set(payload) != {'announcement'}:
            raise AdmissionError('invalid seed response')
        return payload['announcement']


def load_seeds(path):
    entries = unpack(Path(path).read_bytes())
    if not isinstance(entries, list) or not 1 <= len(entries) <= 8:
        raise ValueError('configure 1..8 explicit seeds')
    seeds = []
    for entry in entries:
        if (not isinstance(entry, dict) or 'url' not in entry or set(entry) - {'url', 'ca_cert'} or
                ('ca_cert' in entry and (not isinstance(entry['ca_cert'], str) or not entry['ca_cert']))):
            raise ValueError('seed configuration must contain no credentials')
        ca = str(Path(path).parent / entry['ca_cert']) if 'ca_cert' in entry else None
        seed = Seed(entry['url'], ca)
        if any(previous.url == seed.url for previous in seeds):
            raise ValueError('duplicate seed origin')
        seeds.append(seed)
    return seeds


def lan_config(interface, port):
    address = ipaddress.IPv4Address(interface)
    if address.is_unspecified or address.is_multicast or str(address) == '255.255.255.255':
        raise ValueError('select an explicit local IPv4 interface address')
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('discovery port must be 1..65535')
    return socket.inet_aton(str(address))


def lan_interface_index(interface):
    if not sys.platform.startswith('linux') or not hasattr(socket.socket, 'recvmsg'):
        raise ValueError('LAN receive filtering requires Linux IP_PKTINFO; use explicit seeds')
    import fcntl
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        for index, name in socket.if_nameindex():
            try:
                data = fcntl.ioctl(probe, 0x8915, struct.pack('256s', name.encode()))  # SIOCGIFADDR
            except OSError:
                continue
            if socket.inet_ntoa(data[20:24]) == interface:
                return index
    raise ValueError('LAN interface must be a local primary IPv4 address')


class LanReceiver:
    """Accept only the selected ingress interface and multicast destination."""
    def __init__(self, connection, interface_index):
        self.connection, self.interface_index = connection, interface_index
        self.timeout = 1

    def settimeout(self, timeout):
        self.timeout = timeout

    def recvfrom(self, size):
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout()
            self.connection.settimeout(remaining)
            data, metadata, flags, source = self.connection.recvmsg(size, socket.CMSG_SPACE(12))
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                continue
            for level, kind, value in metadata:
                if level == socket.IPPROTO_IP and kind == getattr(socket, 'IP_PKTINFO', 8) and len(value) == 12:
                    index, _, destination = struct.unpack('=I4s4s', value)
                    if index == self.interface_index and destination == socket.inet_aton(MULTICAST_GROUP):
                        return data, source

    def close(self):
        self.connection.close()


def lan_receiver(interface, port=DISCOVERY_PORT):
    address = lan_config(interface, port)
    index = lan_interface_index(interface)
    connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        connection.bind((MULTICAST_GROUP, port))
        connection.setsockopt(socket.IPPROTO_IP, getattr(socket, 'IP_PKTINFO', 8), 1)
        connection.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                              socket.inet_aton(MULTICAST_GROUP) + address)
        # Linux UAPI <linux/in.h>: Python does not always expose option 49.
        connection.setsockopt(socket.IPPROTO_IP, getattr(socket, 'IP_MULTICAST_ALL', 49), 0)
        return LanReceiver(connection, index)
    except Exception:
        connection.close()
        raise


class LanBroadcaster:
    def __init__(self, provider, interface, port=DISCOVERY_PORT):
        address = lan_config(interface, port)
        self.provider, self.port = provider, port
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            self.connection.settimeout(1)
            self.connection.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, address)
            self.connection.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            self.connection.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        except Exception:
            self.connection.close()
            raise
        self._stopped, self._thread = threading.Event(), None

    def send_once(self):
        self.connection.sendto(pack(self.provider()), (MULTICAST_GROUP, self.port))

    def start(self):
        if self._thread is not None or self._stopped.is_set():
            raise RuntimeError('broadcaster cannot restart')
        def run():
            while not self._stopped.is_set():
                try:
                    self.send_once()
                except (ValueError, OSError):
                    pass  # Missing/stale policy suppresses beacons; never create one.
                self._stopped.wait(5)
        self._thread = threading.Thread(target=run, daemon=True, name='lan-discovery')
        self._thread.start()

    def stop(self):
        self._stopped.set()
        if self._thread is not None:
            self._thread.join()  # Provider/DB remains open until this completes.
        self.connection.close()


def scan(candidates, *, seeds=(), interface=None, port=DISCOVERY_PORT, duration=6):
    seeds = tuple(seeds)
    if len(seeds) > 8 or (not seeds and interface is None):
        raise ValueError('select explicit seeds and/or a LAN interface')
    if type(duration) not in (int, float) or not 0.1 <= duration <= 10:
        raise ValueError('LAN scan duration must be 0.1..10 seconds')
    connection = lan_receiver(interface, port) if interface is not None else None
    statuses = []
    try:
        for index, seed in enumerate(seeds):
            try:
                candidates.add(seed.fetch(), 'seed:' + str(index))
                statuses.append('ok')
            except (ValueError, OSError):
                statuses.append('error')
        if connection is not None:
            deadline = time.monotonic() + duration
            window, attempts = time.monotonic(), 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if time.monotonic() >= window + 1:
                    window, attempts = time.monotonic(), 0
                if attempts >= MAX_PACKETS:
                    time.sleep(min(remaining, max(0, window + 1 - time.monotonic())))
                    continue
                connection.settimeout(remaining)
                try:
                    data, _ = connection.recvfrom(MAX_PACKET + 1)
                except socket.timeout:
                    break
                attempts += 1
                try:
                    candidates.add(unpack(data), 'lan')
                except (ValueError, UnicodeError, TypeError):
                    continue
        return candidates.result() | {'seeds': statuses}
    finally:
        if connection is not None:
            connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authority-public-key', required=True)
    parser.add_argument('--group-id', required=True, help='existing human-created group ID')
    parser.add_argument('--directory-database', required=True, help='existing synchronized directory database (read-only)')
    parser.add_argument('--policy-max-age', type=int, help='optionally tighten the persisted directory maximum age')
    parser.add_argument('--seeds-file', help='trusted JSON array of url and optional ca_cert; no tokens')
    parser.add_argument('--lan-interface', help='explicit local IPv4 address; no automatic NIC selection')
    parser.add_argument('--lan-port', type=int, default=DISCOVERY_PORT)
    parser.add_argument('--duration', type=float, default=6)
    args = parser.parse_args()
    try:
        owner = Ed25519PublicKey.from_public_bytes(decode(Path(args.authority_public_key).read_text().strip()))
        candidates = Candidates.from_directory(args.directory_database, owner, args.group_id, max_age=args.policy_max_age)
        seeds = load_seeds(args.seeds_file) if args.seeds_file else ()
        result = scan(candidates, seeds=seeds, interface=args.lan_interface, port=args.lan_port, duration=args.duration)
    except (ValueError, OSError, TypeError):
        parser.exit(1, 'Discovery failed; check existing group/policy, explicit interfaces, seeds and trust settings.\n')
    print(json.dumps(result, indent=2))
    if not result['candidates']:
        parser.exit(1)


if __name__ == '__main__':
    main()
