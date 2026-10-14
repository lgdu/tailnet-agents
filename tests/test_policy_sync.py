import os
import subprocess
import selectors
import signal
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError, URLError
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tailnet_agents.admission_server import AdmissionHTTPServer, handler, transport_config
    from tailnet_agents.client import Client
    from tailnet_agents.group_policy import create_policy, revise_policy, POLICY_TYPE
    from tailnet_agents.identity import AdmissionError, identity_id, issue_grant, verify_grant, verify, sign, encode, public_bytes
    from tailnet_agents.policy_sync import PolicySynchronizer, fetch_policy, sync_remote
    from tailnet_agents.verified_directory import VerifiedDirectory
    from tailnet_agents.verified_client import VerifiedClient
    from tests.test_admission_tls import certificates
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class ResponseClient:
    def __init__(self, response): self.response = response
    def request(self, *args): return self.response


@unittest.skipUnless(HAS_CRYPTO, 'install identity extra')
class PolicySyncTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.owner, self.agent = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.initial = create_policy(self.owner, 'Human-created group', {}, now=100)
        self.group = verify(self.initial, self.owner.public_key(), POLICY_TYPE)['group_id']
        self.grant = issue_grant(self.owner, self.agent.public_key(), self.group, ['join'], now=100)
        jti = verify_grant(self.grant, self.owner.public_key(), self.group, now=110)['jti']
        self.members = {identity_id(self.agent.public_key()): {'permissions': ['join'], 'grant_ids': [jti]}}
        self.approved = revise_policy(self.owner, self.initial, self.members, now=101)
        self.nodes, self.servers, self.syncs = [], [], []
        self.a = self.directory('a')
        self.b = self.directory('b')
        self.a.apply_policy(self.approved)
        self.source = self.serve(self.a, 'a'*32)
        self.sync = PolicySynchronizer(self.b, self.source, interval=1)
        self.syncs.append(self.sync)
        self.target = self.serve(self.b, 'b'*32, self.sync)
        self.record = {'endpoint': 'https://agent.example', 'ttl_seconds': 60}

    def directory(self, name):
        node = VerifiedDirectory(self.owner.public_key(), self.group, 'receiver',
            database=str(Path(self.folder.name)/(name+'.sqlite3')), clock=lambda: 110, require_policy=True)
        self.nodes.append(node)
        return node

    def serve(self, node, token, synchronizer=None, tls=None):
        allowed, context = (None, None) if tls is None else transport_config(
            '127.0.0.1', tls['cert'], tls['key'], ['localhost'])
        scheme = 'http' if context is None else 'https'
        server = AdmissionHTTPServer(('127.0.0.1', 0), handler(node, token, allowed, scheme, synchronizer), context)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.servers.append((server, thread))
        hostname = '127.0.0.1' if tls is None else 'localhost'
        return Client(f'{scheme}://{hostname}:{server.server_port}', token, ca_file=None if tls is None else tls['ca'])

    def tearDown(self):
        for sync in self.syncs: sync.stop()
        for server, thread in self.servers:
            server.shutdown(); server.server_close(); thread.join()
        for node in self.nodes: node.close()
        self.folder.cleanup()

    def agent_client(self):
        return VerifiedClient(self.target.url, self.agent, self.grant, 'receiver')

    def test_two_http_nodes_replicate_membership_removal_and_dissolution(self):
        with self.assertRaises(HTTPError): self.agent_client().register(self.record)
        self.assertEqual(self.sync.sync_once()['revision'], 2)
        self.agent_client().register(self.record)
        self.assertEqual(len(self.target.request('/v1/agents')['agents']), 1)
        removed = revise_policy(self.owner, self.approved, {}, now=102)
        self.source.request('/v1/policies', {'policy': removed})
        self.sync.sync_once()
        self.assertEqual(self.target.request('/v1/agents')['agents'], [])
        with self.assertRaises(HTTPError): self.agent_client().register(self.record)
        dissolved = revise_policy(self.owner, removed, {}, dissolve=True, now=103)
        self.source.request('/v1/policies', {'policy': dissolved})
        self.sync.sync_once()
        self.assertEqual(self.b.export_policy(), {'policy': dissolved})
        self.sync.sync_once()  # repeated terminal snapshot is idempotent
        resurrection = sign(self.owner, verify(self.approved, self.owner.public_key(), POLICY_TYPE) | {'revision': 100}, POLICY_TYPE)
        with self.assertRaises(AdmissionError): self.b.apply_policy(resurrection)

    def test_export_and_status_require_read_token_and_reject_query(self):
        stranger = Client(self.source.url, 'wrong')
        for path in ['/v1/policies', '/v1/policy-sync']:
            with self.assertRaises(HTTPError) as error: stranger.request(path)
            self.assertEqual(error.exception.code, 403)
        with self.assertRaises(HTTPError) as error: self.source.request('/v1/policies?group=other')
        self.assertEqual(error.exception.code, 400)
        self.assertEqual(self.target.request('/v1/policy-sync')['state'], 'idle')
        self.sync.sync_once()
        self.assertEqual(self.target.request('/v1/policy-sync')['revision'], 2)

    def test_empty_source_does_not_create_policy_or_clear_existing_policy(self):
        empty = self.directory('empty')
        empty_client = self.serve(empty, 'e'*32)
        self.assertIsNone(fetch_policy(empty_client, self.owner.public_key(), self.group))
        sync = PolicySynchronizer(self.b, empty_client)
        self.syncs.append(sync)
        self.assertEqual(sync.sync_once()['state'], 'waiting')
        self.assertEqual(self.b.export_policy(), {'policy': None})
        self.sync.sync_once()
        sync.sync_once()
        self.assertEqual(self.b.export_policy(), {'policy': self.approved})

    def test_untrusted_responses_and_stale_or_conflicting_policy_do_not_mutate_target(self):
        self.sync.sync_once()
        conflicting = sign(self.owner, verify(self.approved, self.owner.public_key(), POLICY_TYPE) | {'members': {}}, POLICY_TYPE)
        foreign_owner = create_policy(Ed25519PrivateKey.generate(), 'Foreign', {}, now=100)
        foreign_group = create_policy(self.owner, 'Foreign group', {}, now=100)
        responses = [[], {}, {'policy': 'bad'}, {'policy': self.approved, 'extra': True},
                     {'policy': foreign_owner}, {'policy': foreign_group},
                     {'policy': self.initial}, {'policy': conflicting}]
        for response in responses:
            sync = PolicySynchronizer(self.b, ResponseClient(response))
            with self.subTest(response=response), self.assertRaises(AdmissionError): sync.sync_once()
            self.assertEqual(sync.status()['state'], 'error')
            self.assertEqual(self.b.export_policy(), {'policy': self.approved})

    def test_network_failure_retains_last_policy_and_background_poll_recovers(self):
        self.sync.sync_once()
        class FailingClient:
            def request(self, *args): raise URLError('simulated unreachable peer')
        saved = self.sync.client
        self.sync.client = FailingClient()
        with self.assertRaises(URLError): self.sync.sync_once()
        self.assertEqual(self.sync.status()['state'], 'error')
        self.assertEqual(self.b.export_policy(), {'policy': self.approved})
        self.sync.client = saved
        removed = revise_policy(self.owner, self.approved, {}, now=102)
        self.source.request('/v1/policies', {'policy': removed})
        self.sync.start()
        deadline = time.monotonic()+5
        while self.sync.status()['revision'] != 3 and time.monotonic() < deadline:
            threading.Event().wait(0.02)
        self.assertEqual(self.sync.status()['revision'], 3)
        self.assertEqual(self.sync.status()['state'], 'synced')

    def test_stop_prevents_late_network_result_from_touching_closed_database(self):
        entered, released = threading.Event(), threading.Event()
        class SlowClient:
            def request(inner, *args):
                entered.set()
                if not released.wait(5): raise RuntimeError('test timeout')
                return {'policy': self.approved}
        sync = PolicySynchronizer(self.b, SlowClient())
        errors = []
        def run():
            try: sync.sync_once()
            except Exception as error: errors.append(error)
        thread = threading.Thread(target=run)
        thread.start()
        try:
            self.assertTrue(entered.wait(2))
            sync.stop()
            self.b.close()
            self.nodes.remove(self.b)
            released.set()
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(sync.status()['state'], 'stopped')
        finally:
            released.set(); thread.join(2)

    def test_restart_restores_policy_before_peer_contact(self):
        self.sync.sync_once()
        self.sync.stop()
        self.b.close()
        self.nodes.remove(self.b)
        restored = self.directory('b')
        self.assertEqual(restored.export_policy(), {'policy': self.approved})
        with self.assertRaises(AdmissionError): restored.apply_policy(self.initial)

    def test_one_shot_cli_uses_two_authenticated_http_services(self):
        key_path = Path(self.folder.name)/'owner.pub'
        key_path.write_text(encode(public_bytes(self.owner.public_key())))
        env = os.environ | {'TAILNET_POLICY_PEER_TOKEN': 'a'*32, 'TAILNET_VERIFIED_READ_TOKEN': 'b'*32}
        result = subprocess.run([sys.executable, '-m', 'tailnet_agents.policy_sync',
            '--source-url', self.source.url, '--target-url', self.target.url,
            '--authority-public-key', str(key_path), '--group-id', self.group],
            env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.b.export_policy(), {'policy': self.approved})

    def test_two_tls_nodes_verify_certificates_and_replicate_signed_policy(self):
        paths = certificates(self.folder.name)
        source = self.serve(self.a, 'a'*32, tls=paths)
        target = self.serve(self.b, 'b'*32, tls=paths)
        result = sync_remote(source, target, self.owner.public_key(), self.group)
        self.assertEqual(result['revision'], 2)
        with self.assertRaises(URLError): fetch_policy(Client(source.url, 'a'*32), self.owner.public_key(), self.group)
        wrong_hostname = source.url.replace('localhost', '127.0.0.1')
        with self.assertRaises(URLError): fetch_policy(Client(wrong_hostname, 'a'*32, ca_file=paths['ca']), self.owner.public_key(), self.group)
        self.assertEqual(self.b.export_policy(), {'policy': self.approved})

    def test_service_cli_starts_periodic_pull_with_pinned_configuration(self):
        key_path = Path(self.folder.name)/'owner.pub'
        key_path.write_text(encode(public_bytes(self.owner.public_key())))
        env = os.environ | {'TAILNET_POLICY_PEER_TOKEN': 'a'*32, 'TAILNET_VERIFIED_READ_TOKEN': 'c'*32}
        process = subprocess.Popen([sys.executable, '-m', 'tailnet_agents.admission_server',
            '--authority-public-key', str(key_path), '--group-id', self.group,
            '--audience', 'receiver', '--database', str(Path(self.folder.name)/'c.sqlite3'),
            '--port', '0', '--require-policy', '--policy-peer', self.source.url,
            '--policy-sync-interval', '1'], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(timeout=5), 'service did not start')
            line = process.stdout.readline().strip()
            self.assertTrue(line.startswith('Verified directory: http://127.0.0.1:'), line)
            client = Client(line.removeprefix('Verified directory: '), 'c'*32)
            deadline = time.monotonic()+5
            while client.request('/v1/policy-sync')['state'] != 'synced' and time.monotonic() < deadline:
                threading.Event().wait(0.02)
            self.assertEqual(client.request('/v1/policies'), {'policy': self.approved})
            process.send_signal(signal.SIGINT)
            _, error = process.communicate(timeout=8)
            self.assertEqual(process.returncode, 0, error)
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=8)

    def test_invalid_poll_interval_and_grant_only_mode_rejected(self):
        for interval in [0, 3601, float('nan'), True]:
            with self.assertRaises(ValueError): PolicySynchronizer(self.b, self.source, interval)
        disabled = VerifiedDirectory(self.owner.public_key(), self.group, 'receiver')
        try:
            with self.assertRaises(AdmissionError): PolicySynchronizer(disabled, self.source)
            with self.assertRaises(AdmissionError): disabled.export_policy()
        finally: disabled.close()
