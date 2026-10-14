import json
import os
from pathlib import Path
import selectors
import signal
import struct
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tailnet_agents.identity import (AdmissionError, encode, generate_identity, identity_id,
                                        issue_grant, load_identity, public_bytes, sign, verify, verify_grant)
    from tailnet_agents.group_policy import create_policy, revise_policy, POLICY_TYPE
    from tailnet_agents.verified_directory import VerifiedDirectory, issue_revocation
    from tailnet_agents.admission_server import AdmissionHTTPServer, handler, transport_config
    from tailnet_agents.client import Client
    from tailnet_agents.verified_client import VerifiedClient
    from tailnet_agents.discovery import (ANNOUNCEMENT_TYPE, Candidates, DISCOVERY_PORT,
        LanBroadcaster, LanReceiver, MAX_PACKET, MAX_PACKETS, MULTICAST_GROUP, Seed, lan_config, lan_receiver,
        load_seeds, make_announcement, origin, pack, scan, unpack, verify_announcement)
    from tests.test_admission_tls import certificates
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class DiscoveryFixture(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.owner = Ed25519PrivateKey.generate()
        self.agent_path = self.root / 'agent.pem'
        self.agent = generate_identity(self.agent_path)
        self.subject = identity_id(self.agent.public_key())
        initial = create_policy(self.owner, 'Explicit human test group', {}, now=100)
        self.group = verify(initial, self.owner.public_key(), POLICY_TYPE)['group_id']
        self.grant = issue_grant(self.owner, self.agent.public_key(), self.group, ['join'], now=100)
        self.jti = verify_grant(self.grant, self.owner.public_key(), self.group, now=110)['jti']
        self.members = {self.subject: {'permissions': ['join'], 'grant_ids': [self.jti]}}
        self.policy = revise_policy(self.owner, initial, self.members, now=101)
        self.now = 110
        self.endpoint, self.audience = 'https://candidate.example:8771', 'directory-a'

    def announcement(self, **options):
        return make_announcement(self.agent, self.policy, self.owner.public_key(), self.group,
                                 self.endpoint, self.audience, now=self.now, **options)

    def candidates(self):
        return Candidates(self.policy, self.owner.public_key(), self.group, clock=lambda: self.now)

    def directory(self, **options):
        node = VerifiedDirectory(self.owner.public_key(), self.group, self.audience,
                                 clock=lambda: self.now, require_policy=True, **options)
        self.addCleanup(node.close)
        node.apply_policy(self.policy)
        return node

    def serve(self, node, *, enabled=True, tls=None):
        allowed, context = (None, None) if tls is None else transport_config(
            '127.0.0.1', tls['cert'], tls['key'], ['localhost', '127.0.0.1'])
        scheme = 'http' if tls is None else 'https'
        provider = (lambda: node.discovery_announcement(self.agent, self.endpoint, self.audience)) if enabled else None
        server = AdmissionHTTPServer(('127.0.0.1', 0), handler(node, 'r'*32, allowed, scheme, discovery=provider), context)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def cleanup():
            server.shutdown(); server.server_close(); thread.join()
        self.addCleanup(cleanup)
        hostname = '127.0.0.1' if tls is None else 'localhost'
        return f'{scheme}://{hostname}:{server.server_port}'


@unittest.skipUnless(HAS_CRYPTO, 'install identity extra')
class AnnouncementTests(DiscoveryFixture):
    def verify(self, envelope):
        return verify_announcement(envelope, self.policy, self.owner.public_key(), self.group, now=self.now)

    def test_signed_candidate_contains_no_credentials_or_membership_grant(self):
        envelope = self.announcement()
        claims = self.verify(envelope)
        self.assertEqual(claims['subject'], self.subject)
        self.assertEqual(claims['group_id'], self.group)
        self.assertEqual(claims['expires_at'], 140)
        self.assertEqual(set(claims), {'version', 'subject', 'group_id', 'policy_hash', 'endpoint', 'audience', 'issued_at', 'expires_at'})
        self.assertNotIn(self.grant, pack(envelope).decode())
        self.assertNotIn(self.jti, json.dumps(claims))
        self.assertLessEqual(len(pack(envelope)), MAX_PACKET)

    def test_public_key_substitution_and_cross_type_signature_rejected(self):
        envelope = self.announcement()
        other = Ed25519PrivateKey.generate()
        for bad in [envelope | {'public_key': encode(public_bytes(other.public_key()))},
                    envelope | {'announcement': self.grant}, envelope | {'announcement': 'bad'}]:
            with self.subTest(bad=bad), self.assertRaises(AdmissionError): self.verify(bad)

    def test_foreign_group_policy_fingerprint_and_unknown_identity_rejected(self):
        envelope = self.announcement()
        claims = self.verify(envelope)
        for change in [{'group_id': 'foreign'}, {'policy_hash': 'f'*64}, {'subject': 'ed25519:'+'f'*64}, {'version': True}]:
            changed = envelope | {'announcement': sign(self.agent, claims | change, ANNOUNCEMENT_TYPE)}
            with self.subTest(change=change), self.assertRaises(AdmissionError): self.verify(changed)
        unknown = Ed25519PrivateKey.generate()
        changed = {'public_key': encode(public_bytes(unknown.public_key())),
                   'announcement': sign(unknown, claims | {'subject': identity_id(unknown.public_key())}, ANNOUNCEMENT_TYPE)}
        with self.assertRaises(AdmissionError): self.verify(changed)

    def test_advertisement_and_local_policy_expire_without_replay_refresh(self):
        envelope = self.announcement()
        candidates = self.candidates()
        candidates.add(envelope, 'lan')
        self.now = 139
        candidates.add(envelope, 'seed:0')
        self.assertEqual(candidates.result()['candidates'][0]['expires_at'], 140)
        self.now = 140
        self.assertEqual(candidates.result()['candidates'], [])
        with self.assertRaises(AdmissionError): self.verify(envelope)
        self.now = 401
        with self.assertRaises(AdmissionError): self.candidates()
        with self.assertRaises(AdmissionError): self.announcement()

    def test_future_timestamps_extended_lifetimes_and_extra_fields_rejected(self):
        envelope = self.announcement()
        claims = self.verify(envelope)
        for change in [{'issued_at': 116, 'expires_at': 140}, {'expires_at': 141},
                       {'issued_at': True}, {'expires_at': 110}, {'token': 's'*32},
                       {'endpoint': 'http://192.168.1.1'}, {'endpoint': 'https://user:pass@host.example'},
                       {'endpoint': 'https://candidate.example/secret'}, {'audience': []}]:
            changed = envelope | {'announcement': sign(self.agent, claims | change, ANNOUNCEMENT_TYPE)}
            with self.subTest(change=change), self.assertRaises(ValueError): self.verify(changed)

    def test_removal_revocation_and_dissolution_suppress_publishing(self):
        node = self.directory()
        node.revoke(issue_revocation(self.owner, self.group, self.jti))
        with self.assertRaises(AdmissionError): node.discovery_announcement(self.agent, self.endpoint, self.audience)
        with self.assertRaises(AdmissionError):
            verify_announcement(self.announcement(), self.policy, self.owner.public_key(), self.group,
                                now=self.now, revoked={self.jti})
        node.apply_policy(revise_policy(self.owner, self.policy, {}, now=102))
        with self.assertRaises(AdmissionError): node.discovery_announcement(self.agent, self.endpoint, self.audience)
        terminal = revise_policy(self.owner, self.policy, {}, dissolve=True, now=103)
        with self.assertRaises(AdmissionError):
            make_announcement(self.agent, terminal, self.owner.public_key(), self.group, self.endpoint, self.audience, now=110)

    def test_same_identity_merges_providers_but_conflicting_addresses_are_withheld(self):
        candidates = self.candidates()
        candidates.add(self.announcement(), 'lan')
        candidates.add(self.announcement(), 'seed:0')
        result = candidates.result()
        self.assertEqual(len(result['candidates']), 1)
        self.assertEqual(result['candidates'][0]['sources'], ['lan', 'seed:0'])
        self.assertEqual(result['candidates'][0]['admission'], 'not_checked')
        changed = make_announcement(self.agent, self.policy, self.owner.public_key(), self.group,
                                    'https://other.example', self.audience, now=111)
        candidates.add(changed, 'seed:1')
        self.assertEqual(candidates.result(), {'candidates': [], 'conflicts': [self.subject]})

    def test_original_identity_and_group_survive_key_reload_and_directory_restart(self):
        path = str(self.root / 'directory.sqlite3')
        node = self.directory(database=path)
        before = node.discovery_announcement(self.agent, self.endpoint, self.audience)
        node.close()
        restored = VerifiedDirectory(self.owner.public_key(), self.group, self.audience,
                                     database=path, clock=lambda: self.now, require_policy=True)
        self.addCleanup(restored.close)
        after = restored.discovery_announcement(load_identity(self.agent_path), self.endpoint, self.audience)
        self.assertEqual(before, after)
        self.assertEqual(restored.discover(), [])  # Candidate discovery never registers an Agent.
        self.assertEqual(restored.export_policy(), {'policy': self.policy})

    def test_packet_size_duplicate_fields_and_origin_controls(self):
        for packet in [b'x'*(MAX_PACKET+1), b'{"public_key":"a","public_key":"b"}', b'\xff']:
            with self.subTest(packet=packet[:30]), self.assertRaises(ValueError): unpack(packet)
        for url in ['https://host.example/a', 'https://host.example?', 'https://host.example#',
                    'https://host.example:0', 'http://192.168.1.20', 'https://host.example\n']:
            with self.subTest(url=url), self.assertRaises(ValueError): origin(url)

    def test_results_drop_future_records_after_clock_rollback(self):
        candidates = self.candidates()
        candidates.add(self.announcement(), 'lan')
        self.now = 104
        self.assertEqual(candidates.result()['candidates'], [])

    def test_conflicts_remain_sticky_after_expiry_and_third_locator(self):
        candidates = self.candidates()
        original = self.announcement()
        candidates.add(original, 'lan')
        changed = make_announcement(self.agent, self.policy, self.owner.public_key(), self.group,
                                    'https://other.example', self.audience, now=110)
        candidates.add(changed, 'seed:0')
        self.assertEqual(candidates.result()['conflicts'], [self.subject])
        # A short-lived decoy must not let another locator win this scan.
        self.now = 139
        latest = make_announcement(self.agent, self.policy, self.owner.public_key(), self.group,
                                   'https://new.example', self.audience, now=self.now)
        candidates.add(latest, 'seed:1')
        self.now = 141
        self.assertEqual(candidates.result(), {'candidates': [], 'conflicts': [self.subject]})
        next_scan = self.candidates()
        next_scan.add(latest, 'seed:1')
        self.assertEqual(next_scan.result()['candidates'][0]['endpoint'], 'https://new.example')

    def test_sources_describe_only_the_retained_announcement_version(self):
        candidates = self.candidates()
        old = self.announcement()
        candidates.add(old, 'lan')
        self.now = 115
        latest = self.announcement()
        candidates.add(latest, 'seed:0')
        candidates.add(old, 'seed:1')
        claims = self.verify(latest)
        changed = latest | {'announcement': sign(self.agent, claims | {'expires_at': 144}, ANNOUNCEMENT_TYPE)}
        candidates.add(changed, 'seed:2')
        self.assertEqual(candidates.result()['candidates'][0]['sources'], ['seed:0'])
        candidates.add(latest, 'lan')
        self.assertEqual(candidates.result()['candidates'][0]['sources'], ['lan', 'seed:0'])

    def test_expiring_decoy_cannot_select_evil_over_discarded_good_locator(self):
        candidates = self.candidates()
        envelope = self.announcement()
        claims = self.verify(envelope)
        for endpoint, expiry in [('https://decoy.example', 111), ('https://evil.example', 140),
                                 ('https://good.example', 140)]:
            packet = envelope | {'announcement': sign(self.agent, claims | {
                'endpoint': endpoint, 'expires_at': expiry}, ANNOUNCEMENT_TYPE)}
            candidates.add(packet, 'lan')
        self.now = 112
        self.assertEqual(candidates.result(), {'candidates': [], 'conflicts': [self.subject]})


@unittest.skipUnless(HAS_CRYPTO, 'install identity extra')
class DirectorySnapshotTests(DiscoveryFixture):
    def setUp(self):
        super().setUp()
        self.database = self.root/'directory.sqlite3'
        self.node = self.directory(database=str(self.database), policy_max_age=30)

    def scanner(self, **options):
        return Candidates.from_directory(self.database, self.owner.public_key(), self.group,
                                         clock=lambda: self.now, **options)

    def test_persisted_age_cannot_be_loosened_and_missing_database_is_not_created(self):
        self.assertEqual(self.scanner().max_age, 30)
        self.assertEqual(self.scanner(max_age=20).max_age, 20)
        with self.assertRaises(AdmissionError): self.scanner(max_age=31)
        self.now = 131
        with self.assertRaises(AdmissionError): self.scanner()
        missing = self.root/'missing.sqlite3'
        with self.assertRaises(OSError):
            Candidates.from_directory(missing, self.owner.public_key(), self.group)
        self.assertFalse(missing.exists())

    def test_snapshot_does_not_reset_leases_or_write_directory_state(self):
        db = self.node._registry.db
        with db:
            db.execute('INSERT INTO agents VALUES(?,?,?,?)', ('live', self.subject, 125, '{}'))
        before = '\n'.join(db.iterdump())
        scanner = self.scanner()
        scanner.add(self.announcement(max_age=30), 'lan')
        self.assertEqual(scanner.result()['candidates'][0]['subject'], self.subject)
        self.assertEqual('\n'.join(db.iterdump()), before)
        self.assertEqual(db.execute('SELECT expires FROM agents WHERE id=?', ('live',)).fetchone(), (125,))

    def test_revocation_learned_during_scan_suppresses_already_collected_candidate(self):
        scanner = self.scanner()
        scanner.add(self.announcement(max_age=30), 'lan')
        self.node.revoke(issue_revocation(self.owner, self.group, self.jti))
        self.assertEqual(scanner.result()['candidates'], [])
        with self.assertRaises(AdmissionError): scanner.add(self.announcement(max_age=30), 'seed:0')

    def test_policy_change_during_scan_requires_retry(self):
        scanner = self.scanner()
        scanner.add(self.announcement(max_age=30), 'lan')
        self.node.apply_policy(revise_policy(self.owner, self.policy, {}, now=111))
        with self.assertRaises(AdmissionError): scanner.result()

    def test_tightened_age_during_scan_applies_before_output(self):
        scanner = self.scanner()
        scanner.add(self.announcement(max_age=30), 'lan')
        with self.node._registry.db as db:
            db.execute('UPDATE admission_policy_freshness SET max_age=15 WHERE id=1')
        self.now = 116
        with self.assertRaises(AdmissionError): scanner.result()

    def test_foreign_context_disabled_policy_and_corrupt_revocations_fail_closed(self):
        with self.assertRaises(AdmissionError):
            Candidates.from_directory(self.database, self.owner.public_key(), 'foreign', clock=lambda: self.now)
        other = Ed25519PrivateKey.generate()
        with self.assertRaises(AdmissionError):
            Candidates.from_directory(self.database, other.public_key(), self.group, clock=lambda: self.now)
        db = self.node._registry.db
        with db:
            db.execute('UPDATE admission_policy_mode SET required=0 WHERE id=1')
        with self.assertRaises(AdmissionError): self.scanner()
        with db:
            db.execute('UPDATE admission_policy_mode SET required=1 WHERE id=1')
        for proof in [issue_revocation(other, self.group, self.jti),
                      issue_revocation(self.owner, 'foreign', self.jti),
                      issue_revocation(self.owner, self.group, 'f'*32)]:
            with db:
                db.execute('INSERT OR REPLACE INTO admission_revocations VALUES(?,?)', (self.jti, proof))
            with self.subTest(proof=proof), self.assertRaises(AdmissionError): self.scanner()


@unittest.skipUnless(HAS_CRYPTO, 'install identity extra')
class SeedDiscoveryTests(DiscoveryFixture):
    def test_public_seed_never_grants_registration_or_reveals_protected_routes(self):
        node = self.directory()
        url = self.serve(node)
        candidates = self.candidates()
        result = scan(candidates, seeds=[Seed(url)])
        self.assertEqual(result['seeds'], ['ok'])
        self.assertEqual(result['candidates'][0]['subject'], self.subject)
        self.assertEqual(node.discover(), [])
        self.assertEqual(node.export_policy(), {'policy': self.policy})
        envelope = Seed(url).fetch()
        with self.assertRaises(HTTPError) as error:
            VerifiedClient(url, self.agent, envelope['announcement'], self.audience).register({'endpoint': self.endpoint})
        self.assertEqual(error.exception.code, 403)  # An announcement cannot substitute for a scoped grant.
        self.assertEqual(node._registry.db.execute('SELECT COUNT(*) FROM agents').fetchone()[0], 0)
        for path in ['/v1/policies', '/v1/agents', '/v1/revocations']:
            with self.subTest(path=path), self.assertRaises(HTTPError) as error: urlopen(url + path)
            self.assertEqual(error.exception.code, 403)
        request = Request(url + '/v1/registrations', data=b'{}', headers={'Content-Type': 'application/json'})
        with self.assertRaises(HTTPError) as error: urlopen(request)
        self.assertEqual(error.exception.code, 400)

    def test_seed_route_is_opt_in_and_enforces_host_origin_and_queries(self):
        node = self.directory()
        disabled = self.serve(node, enabled=False)
        with self.assertRaises(HTTPError) as error: Seed(disabled).fetch()
        self.assertEqual(error.exception.code, 404)
        url = self.serve(node)
        for request, expected in [(Request(url+'/v1/discovery', headers={'Origin':'https://foreign.example'}), 403),
                                  (Request(url+'/v1/discovery', headers={'Host':'foreign.example'}), 403),
                                  (Request(url+'/v1/discovery?extra=1'), 400)]:
            with self.subTest(expected=expected), self.assertRaises(HTTPError) as error: urlopen(request)
            self.assertEqual(error.exception.code, expected)
        self.now = 401
        with self.assertRaises(HTTPError) as error: Seed(url).fetch()
        self.assertEqual(error.exception.code, 503)

    def test_tls_seed_checks_ca_hostname_and_continues_to_valid_seed(self):
        node = self.directory()
        paths = certificates(self.folder.name)
        url = self.serve(node, tls=paths)
        valid = Seed(url, paths['ca'])
        bad_hostname = Seed(url.replace('localhost', '127.0.0.1'), paths['ca'])
        untrusted = Seed(url)
        result = scan(self.candidates(), seeds=[untrusted, bad_hostname, valid])
        self.assertEqual(result['seeds'], ['error', 'error', 'ok'])
        self.assertEqual(len(result['candidates']), 1)

    def test_seed_requests_carry_no_environment_credentials_and_refuse_redirects(self):
        headers = []
        calls = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(inner):
                headers.append(dict(inner.headers))
                calls.append(inner.path)
                if inner.path == '/v1/discovery':
                    inner.send_response(302)
                    inner.send_header('Location', '/credential-trap')
                    inner.end_headers()
                else:
                    inner.send_response(200); inner.end_headers()
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            with patch.dict(os.environ, TAILNET_REGISTRY_TOKEN='s'*32, TAILNET_VERIFIED_READ_TOKEN='v'*32,
                            HTTP_PROXY='http://127.0.0.1:1', HTTPS_PROXY='http://127.0.0.1:1',
                            http_proxy='http://127.0.0.1:1', https_proxy='http://127.0.0.1:1', NO_PROXY='', no_proxy=''):
                result = scan(self.candidates(), seeds=[Seed(f'http://127.0.0.1:{server.server_port}')])
            self.assertEqual(result['seeds'], ['error'])
            self.assertEqual(calls, ['/v1/discovery'])
            self.assertNotIn('Authorization', headers[0])
            self.assertNotIn('Cookie', headers[0])
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_seed_payload_limit_and_invalid_responses_are_rejected(self):
        class Response:
            def __init__(inner, data): inner.data = data
            def __enter__(inner): return inner
            def __exit__(inner, *args): pass
            def read(inner, limit): return inner.data[:limit]
        seed = Seed('https://seed.example')
        for body in [b'x'*(MAX_PACKET+1), b'{"announcement":null}', b'[]', b'{"announcement":{},"token":"bad"}']:
            with self.subTest(body=body[:30]), patch.object(seed.opener, 'open', return_value=Response(body)):
                result = scan(self.candidates(), seeds=[seed])
                self.assertEqual(result['candidates'], [])
                self.assertEqual(result['seeds'], ['error'])

    def test_trusted_seed_configuration_has_no_tokens_and_relative_ca(self):
        certificates(self.folder.name)
        config = self.root/'seeds.json'
        config.write_text(json.dumps([{'url':'https://lan.example:8771','ca_cert':'ca.pem'},
                                      {'url':'https://node.example.ts.net:8771'}]))
        seeds = load_seeds(config)
        self.assertEqual([seed.url for seed in seeds], ['https://lan.example:8771','https://node.example.ts.net:8771'])
        for entries in [[], [{}], [{'url':'https://seed.example','token':'s'*32}],
                        [{'url':'http://192.168.1.1'}], [{'url':'https://seed.example'}]*9,
                        [{'url':'https://seed.example'}, {'url':'https://seed.example/'}]]:
            config.write_text(json.dumps(entries))
            with self.subTest(entries=entries), self.assertRaises(ValueError): load_seeds(config)

    def test_scan_requires_explicit_provider_and_bounded_duration(self):
        for options in [{}, {'seeds':[object()]*9}, {'interface':'0.0.0.0'},
                        {'interface':'127.0.0.1','duration':0}, {'seeds':[object()],'duration':float('nan')}]:
            with self.subTest(options=options), self.assertRaises(ValueError): scan(self.candidates(), **options)


@unittest.skipUnless(HAS_CRYPTO, 'install identity extra')
class LanDiscoveryTests(DiscoveryFixture):
    def test_receiver_drops_unicast_to_the_discovery_port(self):
        port = self.port()
        receiver = lan_receiver('127.0.0.1', port)
        self.addCleanup(receiver.close)
        receiver.settimeout(0.15)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(b'unicast-not-multicast', ('127.0.0.1', port))
        with self.assertRaises(socket.timeout): receiver.recvfrom(MAX_PACKET + 1)

    def port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.bind(('127.0.0.1', 0))
            return connection.getsockname()[1]

    def test_actual_multicast_packet_uses_selected_interface_and_verifies_identity(self):
        port = self.port()
        receiver = lan_receiver('127.0.0.1', port)
        receiver.settimeout(2)
        broadcaster = LanBroadcaster(self.announcement, '127.0.0.1', port)
        try:
            broadcaster.send_once()
            data, _ = receiver.recvfrom(MAX_PACKET + 1)
            candidates = self.candidates()
            candidates.add(unpack(data), 'lan')
            self.assertEqual(candidates.result()['candidates'][0]['subject'], self.subject)
            self.assertEqual(broadcaster.connection.getsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL), 1)
        finally:
            receiver.close(); broadcaster.stop()

    def test_scan_collects_multicast_and_seed_once_per_verified_identity(self):
        port = self.port()
        broadcaster = LanBroadcaster(self.announcement, '127.0.0.1', port)
        self.addCleanup(broadcaster.stop)
        timer = threading.Timer(0.1, broadcaster.send_once)
        timer.start()
        class Source:
            def fetch(inner): return self.announcement()
        try:
            result = scan(self.candidates(), seeds=[Source()], interface='127.0.0.1', port=port, duration=0.4)
            self.assertEqual(len(result['candidates']), 1)
            self.assertEqual(result['candidates'][0]['sources'], ['lan', 'seed:0'])
        finally:
            timer.cancel(); timer.join()

    def test_packet_budget_resumes_next_second_without_ending_scan(self):
        envelope = pack(self.announcement())
        class Flood:
            count = 0
            closed = False
            def settimeout(inner, timeout): pass
            def recvfrom(inner, size):
                inner.count += 1
                if inner.count > MAX_PACKETS + 1: raise socket.timeout()
                return (b'{}' if inner.count <= MAX_PACKETS else envelope), ('127.0.0.1', 1234)
            def close(inner): inner.closed = True
        flood = Flood()
        started = time.monotonic()
        with patch('tailnet_agents.discovery.lan_receiver', return_value=flood):
            result = scan(self.candidates(), interface='127.0.0.1', duration=1.3)
        self.assertEqual(result['candidates'][0]['subject'], self.subject)
        self.assertGreaterEqual(time.monotonic() - started, 1)
        self.assertEqual(flood.count, MAX_PACKETS + 2)
        self.assertTrue(flood.closed)

    def test_receive_metadata_rejects_wrong_interface_destination_and_truncation(self):
        def packet(index=1, destination=MULTICAST_GROUP, flags=0, metadata=True):
            info = [(socket.IPPROTO_IP, 8, struct.pack('=I4s4s', index, b'\0'*4, socket.inet_aton(destination)))]
            return b'accepted', info if metadata else [], flags, ('127.0.0.1', 1234)
        frames = iter([packet(index=2), packet(destination='127.0.0.1'),
                       packet(flags=socket.MSG_TRUNC), packet(flags=socket.MSG_CTRUNC),
                       packet(metadata=False), packet()])
        class Connection:
            count = 0
            def settimeout(inner, timeout): pass
            def recvmsg(inner, *args):
                inner.count += 1
                return next(frames)
        connection = Connection()
        receiver = LanReceiver(connection, 1)
        self.assertEqual(receiver.recvfrom(MAX_PACKET)[0], b'accepted')
        self.assertEqual(connection.count, 6)

    def test_unicast_flood_does_not_spend_multicast_verification_budget(self):
        port = self.port()
        broadcaster = LanBroadcaster(self.announcement, '127.0.0.1', port)
        self.addCleanup(broadcaster.stop)
        def send():
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                for _ in range(MAX_PACKETS + 20):
                    sender.sendto(b'{}', ('127.0.0.1', port))
            broadcaster.send_once()
        timer = threading.Timer(0.1, send)
        timer.start()
        try:
            result = scan(self.candidates(), interface='127.0.0.1', port=port, duration=0.4)
            self.assertEqual(result['candidates'][0]['subject'], self.subject)
        finally:
            timer.cancel(); timer.join()

    def test_broadcaster_shutdown_waits_before_provider_database_closes(self):
        entered, release = threading.Event(), threading.Event()
        node = self.directory()
        def provider():
            entered.set()
            if not release.wait(3): raise RuntimeError('test timeout')
            return node.discovery_announcement(self.agent, self.endpoint, self.audience)
        broadcaster = LanBroadcaster(provider, '127.0.0.1', self.port())
        broadcaster.start()
        self.assertTrue(entered.wait(2))
        stopped = threading.Event()
        def stop(): broadcaster.stop(); stopped.set()
        thread = threading.Thread(target=stop); thread.start()
        try:
            self.assertFalse(stopped.wait(0.05))
            release.set(); thread.join(2)
            self.assertTrue(stopped.is_set())
            node.close()
            with self.assertRaises(RuntimeError): broadcaster.start()
        finally:
            release.set(); thread.join(3)

    def test_interface_and_port_validation_refuse_implicit_or_broadcast_addresses(self):
        for address, port in [('0.0.0.0',8773),('239.1.1.1',8773),('255.255.255.255',8773),
                              ('::1',8773),('localhost',8773),('127.0.0.1',0),('127.0.0.1',True)]:
            with self.subTest(address=address,port=port), self.assertRaises(ValueError): lan_config(address, port)


@unittest.skipUnless(HAS_CRYPTO, 'install identity extra')
class DiscoveryCLITests(DiscoveryFixture):
    def files(self):
        fresh = revise_policy(self.owner, self.policy, self.members, now=int(time.time()))
        owner = self.root/'owner.pub'
        policy = self.root/'group.policy'
        owner.write_text(encode(public_bytes(self.owner.public_key())))
        policy.write_text(fresh)
        return owner, policy, fresh

    def test_cli_suppresses_self_signed_seed_after_learned_revocation(self):
        owner, policy, fresh = self.files()
        self.now = int(time.time())
        database = self.root/'directory.sqlite3'
        node = self.directory(database=str(database))
        node.apply_policy(fresh)
        self.policy = fresh
        envelope = self.announcement()
        node.revoke(issue_revocation(self.owner, self.group, self.jti))
        # An identity holder can still sign its own announcement after revocation.
        with patch.object(node, 'discovery_announcement', return_value=envelope):
            url = self.serve(node)
            seeds = self.root/'seeds.json'
            seeds.write_text(json.dumps([{'url': url}]))
            result = subprocess.run([sys.executable, '-m', 'tailnet_agents.discovery',
                '--authority-public-key', str(owner), '--directory-database', str(database),
                '--group-id', self.group, '--seeds-file', str(seeds)],
                capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['candidates'], [])

    def test_cli_suppresses_self_signed_lan_after_learned_revocation(self):
        owner, _, fresh = self.files()
        self.now = int(time.time())
        database = self.root/'directory.sqlite3'
        node = self.directory(database=str(database))
        node.apply_policy(fresh)
        self.policy = fresh
        envelope = self.announcement()
        node.revoke(issue_revocation(self.owner, self.group, self.jti))
        with self.assertRaises(AdmissionError): node.discovery_announcement(self.agent, self.endpoint, self.audience)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        # Repeated attacker announcements cover subprocess startup without guessing a delay.
        stopped = threading.Event()
        broadcaster = LanBroadcaster(lambda: envelope, '127.0.0.1', port)
        def send():
            while not stopped.is_set():
                broadcaster.send_once()
                stopped.wait(0.05)
        sender = threading.Thread(target=send)
        sender.start()
        try:
            result = subprocess.run([sys.executable, '-m', 'tailnet_agents.discovery',
                '--authority-public-key', str(owner), '--directory-database', str(database),
                '--group-id', self.group, '--lan-interface', '127.0.0.1',
                '--lan-port', str(port), '--duration', '0.4'], capture_output=True, text=True, timeout=8)
        finally:
            stopped.set(); sender.join(); broadcaster.stop()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['candidates'], [])

    def test_real_service_restart_and_cli_scan_preserve_identity_group_and_empty_registry(self):
        owner, policy, fresh = self.files()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.bind(('127.0.0.1', 0))
            port = connection.getsockname()[1]
        receiver = lan_receiver('127.0.0.1', port)
        receiver.settimeout(3)
        self.addCleanup(receiver.close)
        database = self.root/'directory.sqlite3'
        env = os.environ | {'TAILNET_VERIFIED_READ_TOKEN': 'r'*32}
        common = [sys.executable, '-m', 'tailnet_agents.admission_server',
                  '--authority-public-key', str(owner), '--group-id', self.group,
                  '--audience', self.audience, '--database', str(database), '--port', '0',
                  '--require-policy', '--discovery-agent-key', str(self.agent_path),
                  '--discovery-endpoint', self.endpoint, '--discovery-lan-interface', '127.0.0.1',
                  '--discovery-lan-port', str(port)]
        subjects = []
        for restart in (False, True):
            command = common if restart else common + ['--policy-file', str(policy)]
            process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(timeout=5), 'service did not start')
                line = process.stdout.readline().strip()
                self.assertTrue(line.startswith('Verified directory: http://127.0.0.1:'), line)
                url = line.removeprefix('Verified directory: ')
                data, _ = receiver.recvfrom(MAX_PACKET + 1)
                claims = verify_announcement(unpack(data), fresh, self.owner.public_key(), self.group)
                self.assertEqual(claims['subject'], self.subject)
                seeds = self.root/'seeds.json'
                seeds.write_text(json.dumps([{'url': url}]))
                result = subprocess.run([sys.executable, '-m', 'tailnet_agents.discovery',
                    '--authority-public-key', str(owner), '--directory-database', str(database),
                    '--group-id', self.group, '--seeds-file', str(seeds)],
                    env=env, capture_output=True, text=True, timeout=8)
                self.assertEqual(result.returncode, 0, result.stderr)
                output = json.loads(result.stdout)
                subjects.append(output['candidates'][0]['subject'])
                self.assertEqual(output['candidates'][0]['group_id'], self.group)
                self.assertEqual(output['candidates'][0]['admission'], 'not_checked')
                self.assertNotIn('r'*32, result.stdout + result.stderr)
                reader = Client(url, 'r'*32)
                self.assertEqual(reader.request('/v1/agents'), {'agents': []})
                self.assertEqual(reader.request('/v1/policies'), {'policy': fresh})
                process.send_signal(signal.SIGINT)
                _, error = process.communicate(timeout=8)
                self.assertEqual(process.returncode, 0, error)
            finally:
                if process.poll() is None:
                    process.terminate(); process.communicate(timeout=8)
        self.assertEqual(subjects, [self.subject, self.subject])
        self.assertEqual(identity_id(load_identity(self.agent_path).public_key()), self.subject)

    def test_empty_scan_fails_without_creating_state_or_generating_keys(self):
        owner, policy, fresh = self.files()
        self.now = int(time.time())
        database = self.root/'directory.sqlite3'
        node = self.directory(database=str(database))
        node.apply_policy(fresh)
        url = self.serve(node, enabled=False)
        seeds = self.root/'seeds.json'
        seeds.write_text(json.dumps([{'url': url}]))
        before = {path.name for path in self.root.iterdir()}
        result = subprocess.run([sys.executable, '-m', 'tailnet_agents.discovery',
            '--authority-public-key', str(owner), '--directory-database', str(database),
            '--group-id', self.group, '--seeds-file', str(seeds)], capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)['candidates'], [])
        self.assertEqual({path.name for path in self.root.iterdir()}, before)
        missing_key = self.root/'must-not-be-created.pem'
        result = subprocess.run([sys.executable, '-m', 'tailnet_agents.admission_server',
            '--authority-public-key', str(owner), '--group-id', self.group, '--audience', self.audience,
            '--database', str(self.root/'must-not-be-created.sqlite3'), '--require-policy',
            '--discovery-agent-key', str(missing_key)],
            env=os.environ | {'TAILNET_VERIFIED_READ_TOKEN':'r'*32}, capture_output=True, text=True, timeout=8)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(missing_key.exists())
        self.assertFalse((self.root/'must-not-be-created.sqlite3').exists())
