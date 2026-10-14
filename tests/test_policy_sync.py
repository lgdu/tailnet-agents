import os
import json
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
    from tailnet_agents.policy_sync import PolicySynchronizer, fetch_policy, sync_remote, pull_revocations
    from tailnet_agents.verified_directory import VerifiedDirectory, issue_revocation
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
        self.now = 110
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
            database=str(Path(self.folder.name)/(name+'.sqlite3')), clock=lambda: self.now, require_policy=True)
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
        # A real subprocess uses wall time: historical fixture policy must expire.
        live = VerifiedDirectory(self.owner.public_key(), self.group, 'receiver', require_policy=True)
        self.nodes.append(live)
        policy = revise_policy(self.owner, self.approved, self.members, now=int(time.time()))
        live.apply_policy(policy)
        source = self.serve(live, 'a'*32)
        key_path = Path(self.folder.name)/'owner.pub'
        key_path.write_text(encode(public_bytes(self.owner.public_key())))
        env = os.environ | {'TAILNET_POLICY_PEER_TOKEN': 'a'*32, 'TAILNET_VERIFIED_READ_TOKEN': 'c'*32}
        process = subprocess.Popen([sys.executable, '-m', 'tailnet_agents.admission_server',
            '--authority-public-key', str(key_path), '--group-id', self.group,
            '--audience', 'receiver', '--database', str(Path(self.folder.name)/'c.sqlite3'),
            '--port', '0', '--require-policy', '--policy-peer', source.url,
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
            self.assertEqual(client.request('/v1/policies'), {'policy': policy})
            process.send_signal(signal.SIGINT)
            _, error = process.communicate(timeout=8)
            self.assertEqual(process.returncode, 0, error)
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=8)

    def test_credential_revocation_replicates_and_survives_receiver_restart(self):
        self.sync.sync_once()
        self.agent_client().register(self.record)
        jti = verify_grant(self.grant, self.owner.public_key(), self.group, now=110)['jti']
        proof = issue_revocation(self.owner, self.group, jti)
        self.source.request('/v1/revocations', {'revocation': proof})
        self.sync.sync_once()
        self.assertEqual(self.target.request('/v1/agents')['agents'], [])
        with self.assertRaises(HTTPError): self.agent_client().register(self.record)
        self.sync.stop(); self.b.close(); self.nodes.remove(self.b)
        restored = self.directory('b')
        self.assertEqual(restored.export_revocations()['entries'][0]['revocation'], proof)
        restored.apply_policy(self.approved)  # policy approval cannot undo a learned revoke
        self.assertEqual(restored._admission.revoked, {jti})

    def test_multiple_pages_and_source_generation_change(self):
        for n in range(205): self.a.revoke(issue_revocation(self.owner, self.group, f'{n:032x}'))
        self.assertEqual(self.sync.sync_once()['revocation_cursor'], 205)
        self.assertEqual(len(self.b._admission.revoked), 205)
        fresh = self.directory('fresh-source')
        fresh.apply_policy(self.approved)
        jti = 'f'*32
        fresh.revoke(issue_revocation(self.owner, self.group, jti))
        self.sync.client = self.serve(fresh, 'f'*32)
        self.sync.sync_once()
        self.assertIn(jti, self.b._admission.revoked)
        self.assertEqual(len(self.b._admission.revoked), 206)
        self.assertEqual(self.sync.status()['revocation_cursor'], 1)

    def test_paginated_pull_resumes_after_budget_without_losing_entries(self):
        for n in range(105): self.a.revoke(issue_revocation(self.owner, self.group, f'{n:032x}'))
        checkpoint = {'generation': None, 'after': 0}
        self.assertFalse(pull_revocations(self.source, self.owner.public_key(), self.group,
            self.b.revoke, checkpoint, max_pages=1))
        self.assertEqual(checkpoint['after'], 100)
        self.assertTrue(pull_revocations(self.source, self.owner.public_key(), self.group,
            self.b.revoke, checkpoint, max_pages=1))
        self.assertEqual(checkpoint['after'], 105)
        self.assertEqual(len(self.b._admission.revoked), 105)

    def test_bad_signed_record_never_advances_past_last_verified_record(self):
        first = issue_revocation(self.owner, self.group, 'a'*32)
        invalid = issue_revocation(self.owner, 'another-group', 'b'*32)
        checkpoint = {'generation': None, 'after': 0}
        page = {'generation': 'c'*32, 'entries': [
            {'sequence': 1, 'revocation': first}, {'sequence': 2, 'revocation': invalid}],
            'next_cursor': 2, 'has_more': False}
        with self.assertRaises(AdmissionError): pull_revocations(ResponseClient(page),
            self.owner.public_key(), self.group, self.b.revoke, checkpoint)
        self.assertEqual(checkpoint['after'], 1)
        self.assertEqual(self.b._admission.revoked, {'a'*32})
        for bad in [page | {'entries': [], 'next_cursor': 1, 'has_more': True},
                    page | {'next_cursor': True}, page | {'generation': 'bad'}]:
            with self.assertRaises(AdmissionError): pull_revocations(ResponseClient(bad),
                self.owner.public_key(), self.group, self.b.revoke, checkpoint)

    def test_completed_scan_restarts_from_zero_to_catch_restored_source_history(self):
        checkpoint = {'generation': 'c'*32, 'after': 500, 'scan_complete': True}
        proof = issue_revocation(self.owner, self.group, 'd'*32)
        class RecordingClient:
            def request(inner, path):
                self.assertIn('after=0&', path)
                return {'generation': 'c'*32, 'entries': [{'sequence': 1, 'revocation': proof}],
                        'next_cursor': 1, 'has_more': False}
        self.assertTrue(pull_revocations(RecordingClient(), self.owner.public_key(), self.group,
            self.b.revoke, checkpoint))
        self.assertIn('d'*32, self.b._admission.revoked)

    def test_revocation_export_requires_reader_and_valid_page_parameters(self):
        with self.assertRaises(HTTPError) as error: Client(self.source.url, 'wrong').request('/v1/revocations')
        self.assertEqual(error.exception.code, 403)
        for query in ['after=-1', 'limit=101', 'limit=0', 'after=true', 'extra=1', 'after=1&after=2']:
            with self.assertRaises(HTTPError) as error: self.source.request('/v1/revocations?'+query)
            self.assertEqual(error.exception.code, 400)

    def test_one_shot_http_relay_includes_signed_credential_revocations(self):
        jti = verify_grant(self.grant, self.owner.public_key(), self.group, now=110)['jti']
        self.a.revoke(issue_revocation(self.owner, self.group, jti))
        result = sync_remote(self.source, self.target, self.owner.public_key(), self.group)
        self.assertTrue(result['revocations_complete'])
        with self.assertRaises(HTTPError): self.agent_client().register(self.record)

    def test_invalid_poll_interval_and_grant_only_mode_rejected(self):
        for interval in [0, 3601, float('nan'), True]:
            with self.assertRaises(ValueError): PolicySynchronizer(self.b, self.source, interval)
        disabled = VerifiedDirectory(self.owner.public_key(), self.group, 'receiver')
        try:
            with self.assertRaises(AdmissionError): PolicySynchronizer(disabled, self.source)
            with self.assertRaises(AdmissionError): disabled.export_policy()
        finally: disabled.close()

    def test_transport_failover_and_next_poll_failback(self):
        class Unreachable:
            def request(self, *args): raise URLError('offline')
        sync = PolicySynchronizer(self.b, Unreachable(), fallback_clients=[self.source])
        self.syncs.append(sync)
        status = sync.sync_once()
        self.assertEqual(status['state'], 'synced')
        self.assertEqual(status['active_source'], 1)
        self.assertEqual(status['sources'][0]['state'], 'error')
        sync.client = self.source
        self.assertEqual(sync.sync_once()['active_source'], 0)
        # External readers cannot mutate synchronizer diagnostics.
        status['sources'][0]['state'] = 'tampered'
        self.assertEqual(sync.status()['sources'][0]['state'], 'synced')

    def test_expired_source_fails_over_without_clearing_learned_revocations(self):
        self.now = 401
        backup = self.directory('backup')
        fresh = revise_policy(self.owner, self.approved, self.members, now=self.now)
        backup.apply_policy(fresh)
        jti = verify_grant(self.grant, self.owner.public_key(), self.group, now=self.now)['jti']
        self.a.revoke(issue_revocation(self.owner, self.group, jti))
        sync = PolicySynchronizer(self.b, self.source, fallback_clients=[self.serve(backup, 'c'*32)])
        self.syncs.append(sync)
        status = sync.sync_once()
        self.assertEqual(status['active_source'], 1)
        self.assertEqual(status['sources'][0]['state'], 'stale')
        self.assertEqual(status['revision'], 3)
        self.assertIn(jti, self.b._admission.revoked)
        with self.assertRaises(HTTPError): self.agent_client().register(self.record)

    def test_repeated_stale_policy_never_updates_success_or_reopens_admission(self):
        first = self.sync.sync_once()
        self.agent_client().register(self.record)
        self.now = 401
        status = self.sync.sync_once()
        self.assertEqual(status['state'], 'stale')
        self.assertIsNone(status['active_source'])
        self.assertEqual(status['last_success'], first['last_success'])
        self.assertEqual(self.target.request('/v1/policy-sync')['policy']['state'], 'stale')
        self.assertEqual(self.target.request('/v1/agents')['agents'], [])
        with self.assertRaises(HTTPError): self.agent_client().register(self.record)

    def test_empty_primary_falls_back_without_creating_a_group(self):
        empty = self.directory('empty-primary')
        sync = PolicySynchronizer(self.b, self.serve(empty, 'e'*32), fallback_clients=[self.source])
        self.syncs.append(sync)
        self.assertEqual(sync.sync_once()['active_source'], 1)
        self.assertEqual(empty.export_policy(), {'policy': None})
        self.assertEqual(self.b.group_id, self.group)

    def test_foreign_future_rollback_and_conflicting_sources_cannot_weaken_fallback(self):
        self.sync.sync_once()
        conflict = sign(self.owner, verify(self.approved, self.owner.public_key(), POLICY_TYPE) | {'members': {}}, POLICY_TYPE)
        future = revise_policy(self.owner, self.approved, self.members, now=self.now + 31)
        foreign = create_policy(Ed25519PrivateKey.generate(), 'Foreign', {}, now=100)
        for token in (self.initial, conflict, future, foreign, 'invalid'):
            sync = PolicySynchronizer(self.b, ResponseClient({'policy': token}), fallback_clients=[self.source])
            self.syncs.append(sync)
            with self.subTest(token=token[:20]):
                self.assertEqual(sync.sync_once()['active_source'], 1)
                self.assertEqual(self.b.export_policy(), {'policy': self.approved})

    def test_independent_source_cursors_resume_partial_scan_after_failover(self):
        proofs = [issue_revocation(self.owner, self.group, f'{n:032x}') for n in range(15)]
        class PagedSource:
            def request(inner, path):
                if path == '/v1/policies': return {'policy': self.approved}
                after = int(path.split('after=')[1].split('&')[0])
                sequence = after + 1
                return {'generation': 'c'*32, 'entries': [{'sequence': sequence, 'revocation': proofs[after]}],
                        'next_cursor': sequence, 'has_more': sequence < 15}
        self.a.revoke(issue_revocation(self.owner, self.group, 'f'*32))
        sync = PolicySynchronizer(self.b, PagedSource(), fallback_clients=[self.source])
        self.syncs.append(sync)
        status = sync.sync_once()
        self.assertEqual(status['active_source'], 1)
        self.assertEqual([s['revocation_cursor'] for s in status['sources']], [10, 1])
        self.assertEqual(sync.sync_once()['active_source'], 0)
        self.assertEqual(len(self.b._admission.revoked), 16)
        self.assertEqual([s['revocation_cursor'] for s in sync.status()['sources']], [15, 1])

    def test_tls_hostname_failure_uses_independently_authenticated_backup(self):
        paths = certificates(self.folder.name)
        primary = self.serve(self.a, 'p'*32, tls=paths)
        backup = self.serve(self.a, 'q'*32, tls=paths)
        bad = Client(primary.url.replace('localhost', '127.0.0.1'), 'p'*32, ca_file=paths['ca'])
        sync = PolicySynchronizer(self.b, bad, fallback_clients=[backup])
        self.syncs.append(sync)
        self.assertEqual(sync.sync_once()['active_source'], 1)
        self.assertEqual(self.b.export_policy(), {'policy': self.approved})
        # Source credentials are not reused for a different configured destination.
        with self.assertRaises(HTTPError): Client(backup.url, 'p'*32, ca_file=paths['ca']).request('/v1/policies')

    def test_dissolution_from_fallback_cannot_be_undone_by_primary_recovery(self):
        backup = self.directory('terminal-backup')
        dissolved = revise_policy(self.owner, self.approved, {}, dissolve=True, now=102)
        backup.apply_policy(dissolved)
        sync = PolicySynchronizer(self.b, ResponseClient({'policy': 'invalid'}), fallback_clients=[self.serve(backup, 'd'*32)])
        self.syncs.append(sync)
        self.assertEqual(sync.sync_once()['active_source'], 1)
        sync.client = self.source
        self.assertEqual(sync.sync_once()['active_source'], 1)
        self.assertEqual(self.b.export_policy(), {'policy': dissolved})

    def test_stop_during_primary_io_never_contacts_fallback(self):
        entered, released = threading.Event(), threading.Event()
        class SlowSource:
            def request(inner, path):
                entered.set()
                if not released.wait(5): raise RuntimeError('test timeout')
                return {'policy': self.approved}
        class ForbiddenFallback:
            def request(inner, path): self.fail('fallback contacted after shutdown')
        sync = PolicySynchronizer(self.b, SlowSource(), fallback_clients=[ForbiddenFallback()])
        errors = []
        def run():
            try: sync.sync_once()
            except Exception as error: errors.append(error)
        thread = threading.Thread(target=run)
        thread.start()
        try:
            self.assertTrue(entered.wait(2))
            sync.stop()
            self.b.close(); self.nodes.remove(self.b)
            released.set(); thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(sync.status()['state'], 'stopped')
        finally:
            released.set(); thread.join(2)

    def test_service_cli_loads_ordered_sources_and_fails_over(self):
        live = VerifiedDirectory(self.owner.public_key(), self.group, 'receiver', require_policy=True)
        self.nodes.append(live)
        fresh = revise_policy(self.owner, self.approved, self.members, now=int(time.time()))
        live.apply_policy(fresh)
        source = self.serve(live, 'a'*32)
        key_path = Path(self.folder.name)/'owner.pub'
        key_path.write_text(encode(public_bytes(self.owner.public_key())))
        config = Path(self.folder.name)/'sources.json'
        backup = self.serve(live, 'b'*32)
        config.write_text(json.dumps([
            {'url': source.url, 'token_env': 'TEST_WRONG_SOURCE_TOKEN'},
            {'url': backup.url, 'token_env': 'TEST_BACKUP_SOURCE_TOKEN'},
        ]))
        # First source rejects its own deliberately wrong credential; second
        # independently configured service exposes the fresh signed snapshot.
        env = os.environ | {'TEST_WRONG_SOURCE_TOKEN': 'x'*32, 'TEST_BACKUP_SOURCE_TOKEN': 'b'*32,
                            'TAILNET_VERIFIED_READ_TOKEN': 'c'*32}
        process = subprocess.Popen([sys.executable, '-m', 'tailnet_agents.admission_server',
            '--authority-public-key', str(key_path), '--group-id', self.group,
            '--audience', 'receiver', '--database', str(Path(self.folder.name)/'failover.sqlite3'),
            '--port', '0', '--require-policy', '--policy-sources-file', str(config),
            '--policy-max-age', '120', '--policy-sync-interval', '1'],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(timeout=5), 'service did not start')
            line = process.stdout.readline().strip()
            self.assertTrue(line.startswith('Verified directory: http://127.0.0.1:'), line)
            client = Client(line.removeprefix('Verified directory: '), 'c'*32)
            deadline = time.monotonic() + 5
            while client.request('/v1/policy-sync')['state'] != 'synced' and time.monotonic() < deadline:
                threading.Event().wait(0.02)
            status = client.request('/v1/policy-sync')
            self.assertEqual(status['active_source'], 1)
            self.assertEqual(status['policy']['max_age'], 120)
            self.assertEqual(client.request('/v1/policies'), {'policy': fresh})
            process.send_signal(signal.SIGINT)
            _, error = process.communicate(timeout=8)
            self.assertEqual(process.returncode, 0, error)
            self.assertNotIn(env['TEST_BACKUP_SOURCE_TOKEN'], error)
        finally:
            if process.poll() is None:
                process.terminate(); process.communicate(timeout=8)
