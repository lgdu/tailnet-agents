import json
import os
import selectors
import signal
import subprocess
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.error import HTTPError
import test_policy_admin as fixtures

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tailnet_agents.chat import ChatStore, PolicyDeliveryError
    from tailnet_agents.client import Client
    from tailnet_agents.policy_delivery import PolicyTarget, load_policy_targets
    from tailnet_agents.identity import sign, identity_id
    from tailnet_agents.group_policy import POLICY_TYPE, revise_policy
    from tailnet_agents.verified_directory import VerifiedDirectory
    from tailnet_agents.verified_client import VerifiedClient
    from tailnet_agents.admission_server import AdmissionHTTPServer, handler, transport_config
    from test_admission_tls import certificates
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@unittest.skipUnless(HAS_CRYPTO, 'install identity extra')
class PolicyDeliveryTests(unittest.TestCase):
    setUp = fixtures.HumanPolicyTests.setUp
    serve = fixtures.HumanPolicyTests.serve
    create = fixtures.HumanPolicyTests.create
    export = fixtures.HumanPolicyTests.export
    grant = fixtures.HumanPolicyTests.grant
    change = fixtures.HumanPolicyTests.change
    rejected = fixtures.HumanPolicyTests.rejected

    def recipient(self, group=None, *, max_age=300):
        group = self.create() if group is None else group
        node = VerifiedDirectory(self.owner.public_key(), group, 'directory', require_policy=True,
                                 clock=lambda: self.now, policy_max_age=max_age)
        self.addCleanup(node.close)
        url = self.serve(handler(node, 'r'*32))
        target = PolicyTarget('configured', url, group, 'r'*32)
        self.store.configure_policy_targets([target])
        return group, node, target

    def preview(self, group, target='configured'):
        exported = self.export(group)
        return self.clients['owner'].request('/api/policy-delivery-preview', {
            'group_id': group, 'target_id': target, 'expected_revision': exported['claims']['revision'],
            'policy_hash': exported['policy_hash']})

    def body(self, preview, request_id='deliver'):
        return {'group_id': preview['group_id'], 'target_id': preview['target']['id'],
                'target_fingerprint': preview['target']['fingerprint'], 'expected_revision': preview['revision'],
                'policy_hash': preview['policy_hash'], 'request_id': request_id}

    def deliver(self, group, request_id='deliver'):
        return self.clients['owner'].request('/api/policy-deliver', self.body(self.preview(group), request_id))

    def history(self, group):
        return self.clients['owner'].request('/api/policy-deliveries?group_id='+group)['deliveries']

    def test_listing_and_preview_are_local_and_do_not_send_credentials(self):
        group, node, target = self.recipient()
        with patch.object(target.client, 'request') as request:
            targets = self.clients['owner'].request('/api/policy-targets?group_id='+group)
            preview = self.preview(group)
            self.assertEqual(self.history(group), [])
            request.assert_not_called()
        self.assertEqual(preview['target']['url'], target.url)
        self.assertEqual(preview['owner'], identity_id(self.owner.public_key()))
        self.assertNotIn('r'*32, json.dumps(targets))
        self.assertEqual(node.export_policy(), {'policy': None})

    def test_explicit_delivery_reads_back_exact_signed_snapshot_and_age(self):
        group, node, target = self.recipient(max_age=20)
        receipt = self.deliver(group)
        self.assertEqual(receipt['authorization_state'], 'fresh')
        self.assertEqual(receipt['max_age'], 20)
        self.assertEqual(receipt['expires_at'], 120)
        self.assertEqual(receipt['checked_at'], 100)
        self.assertEqual(node.export_policy()['policy'], self.export(group)['policy'])
        self.assertEqual(node.discover(), [])
        self.assertEqual(self.history(group)[0]['outcome'], 'acknowledged')
        self.assertNotIn('r'*32, json.dumps(self.history(group)))

    def test_ui_approval_delivery_and_agent_possession_are_distinct_steps(self):
        group, node, target = self.recipient()
        grant = self.grant(group)
        self.change(group, 'approve', 1, grant=grant)
        agent = VerifiedClient(target.url, self.agent, grant, 'directory')
        record = {'endpoint': 'https://simulation.example', 'skills': ['echo']}
        self.rejected(403, lambda: agent.register(record))
        self.deliver(group)
        self.assertEqual(node.discover(), [])  # Sending policy never registers the identity.
        agent.register(record)
        self.assertEqual(len(node.discover()), 1)
        self.change(group, 'remove', 2, request_id='remove', subject=self.subject)
        self.deliver(group, 'remove-delivery')
        self.assertEqual(node.discover(), [])
        self.rejected(403, lambda: agent.register(record))

    def test_terminal_policy_can_be_delivered_without_reopening_group(self):
        group, node, _ = self.recipient()
        self.store.dissolve_group('owner', group, 'Human approved')
        receipt = self.deliver(group)
        self.assertEqual(receipt['authorization_state'], 'dissolved')
        self.assertEqual(node.policy_status()['state'], 'dissolved')
        self.assertTrue(self.store.groups('owner')[0]['dissolved'])

    def test_duplicate_request_returns_original_historical_receipt_without_contact(self):
        group, _, target = self.recipient()
        body = self.body(self.preview(group))
        first = self.clients['owner'].request('/api/policy-deliver', body)
        self.now = 400
        with patch.object(target.client, 'request') as request:
            second = self.clients['owner'].request('/api/policy-deliver', body)
            request.assert_not_called()
        self.assertEqual(first, second)
        self.assertEqual(second['checked_at'], 100)
        self.assertEqual(len(self.history(group)), 1)

    def test_lost_post_response_retries_by_readback_without_posting_again(self):
        group, node, target = self.recipient()
        body = self.body(self.preview(group))
        original = target.client.request
        posts = []
        def lose(path, payload=None):
            result = original(path, payload)
            if payload is not None:
                posts.append(payload)
                raise OSError('transport detail '+'r'*32)
            return result
        with patch.object(target.client, 'request', side_effect=lose):
            self.rejected(502, lambda: self.clients['owner'].request('/api/policy-deliver', body))
            self.assertEqual(self.history(group)[0]['outcome'], 'unknown')
            self.clients['owner'].request('/api/policy-deliver', body)
        self.assertEqual(len(posts), 1)
        self.assertEqual(node.export_policy()['policy'], self.export(group)['policy'])
        self.assertEqual(self.history(group)[0]['outcome'], 'acknowledged')

    def test_failed_status_read_does_not_extend_or_resign_policy(self):
        group, node, target = self.recipient()
        original = target.client.request
        body = self.body(self.preview(group))
        calls = []
        def fail_status(path, payload=None):
            calls.append((path, payload))
            if path == '/v1/policy-sync': raise OSError('private transport detail')
            return original(path, payload)
        before = self.export(group)
        with patch.object(target.client, 'request', side_effect=fail_status):
            self.rejected(502, lambda: self.clients['owner'].request('/api/policy-deliver', body))
        self.assertEqual(node.export_policy()['policy'], before['policy'])
        with patch.object(target.client, 'request', wraps=original) as retried:
            self.clients['owner'].request('/api/policy-deliver', body)
            self.assertTrue(all(len(call.args) == 1 for call in retried.call_args_list))
        self.assertEqual(self.export(group), before)

    def test_preview_becomes_invalid_after_policy_or_recipient_configuration_changes(self):
        group, node, target = self.recipient()
        body = self.body(self.preview(group))
        self.change(group, 'renew', 1)
        with patch.object(target.client, 'request') as request:
            self.rejected(409, lambda: self.clients['owner'].request('/api/policy-deliver', body))
            request.assert_not_called()
        body = self.body(self.preview(group))
        target.fingerprint = 'a'*64  # Simulate a different startup routing/CA configuration.
        with patch.object(target.client, 'request') as request:
            self.rejected(409, lambda: self.clients['owner'].request('/api/policy-deliver', body))
            request.assert_not_called()
        self.assertEqual(node.export_policy(), {'policy': None})

    def test_changed_payload_cannot_reuse_a_completed_request_id(self):
        group, _, target = self.recipient()
        self.deliver(group)
        self.change(group, 'renew', 1)
        body = self.body(self.preview(group))
        with patch.object(target.client, 'request') as request:
            self.rejected(409, lambda: self.clients['owner'].request('/api/policy-deliver', body))
            request.assert_not_called()

    def test_other_roles_and_invited_admin_cannot_preview_deliver_or_read_history(self):
        group, _, target = self.recipient()
        body = self.body(self.preview(group))
        with patch.object(target.client, 'request') as request:
            for human in ('other', 'participant', 'observer'):
                for path in ('/api/policy-targets', '/api/policy-deliveries'):
                    self.rejected(403, lambda: self.clients[human].request(path+'?group_id='+group))
                for path in ('/api/policy-delivery-preview', '/api/policy-deliver'):
                    self.rejected(403, lambda: self.clients[human].request(path, body))
            request.assert_not_called()

    def test_http_body_cannot_supply_an_origin_or_inline_read_token(self):
        group, _, target = self.recipient()
        body = self.body(self.preview(group))
        with patch.object(target.client, 'request') as request:
            for change in ({'url': 'https://unconfigured.example'}, {'token': 's'*32}, {'target_id': 'unknown'}):
                self.rejected(400, lambda: self.clients['owner'].request('/api/policy-deliver', body | change))
            request.assert_not_called()

    def test_target_cannot_receive_another_group_and_unknown_config_cannot_create_groups(self):
        group, _, target = self.recipient()
        other = self.create('Other', 'other')
        body = self.body(self.preview(group)) | {'group_id': other}
        with patch.object(target.client, 'request') as request:
            self.rejected(403, lambda: self.clients['owner'].request('/api/policy-deliver', body))
            request.assert_not_called()
        before = self.store.groups('owner')
        with self.assertRaises(PermissionError):
            self.store.configure_policy_targets([PolicyTarget('unknown', target.url, 'nonexistent', 'r'*32)])
        self.assertEqual(self.store.groups('owner'), before)

    def test_remote_newer_conflicting_or_terminal_state_is_never_overwritten(self):
        group, node, target = self.recipient()
        base = self.export(group)
        candidates = [revise_policy(self.owner, base['policy'], {}, now=101),
                      sign(self.owner, base['claims'] | {'name': 'Conflicting'}, POLICY_TYPE),
                      revise_policy(self.owner, base['policy'], {}, dissolve=True, now=101)]
        for index, policy in enumerate(candidates):
            with node.lock, node._registry.db:
                node._registry.db.execute('DELETE FROM group_policy')
            node.apply_policy(policy)
            with patch.object(target.client, 'request', wraps=target.client.request) as request:
                self.rejected(409, lambda: self.deliver(group, str(index)))
                self.assertEqual([call.args[0] for call in request.call_args_list], ['/v1/policies'])
            self.assertEqual(node.export_policy()['policy'], policy)

    def test_foreign_owner_or_group_signed_policy_fails_before_write(self):
        group, _, target = self.recipient()
        base = self.export(group)
        foreign = Ed25519PrivateKey.generate()
        policies = [sign(foreign, base['claims'] | {'owner': identity_id(foreign.public_key())}, POLICY_TYPE),
                    sign(self.owner, base['claims'] | {'group_id': 'foreign'}, POLICY_TYPE)]
        for index, policy in enumerate(policies):
            with patch.object(target.client, 'request', return_value={'policy': policy}) as request:
                self.rejected(502, lambda: self.deliver(group, str(index)))
                self.assertEqual(len(request.call_args_list), 1)

    def test_invalid_acknowledgment_is_not_reported_as_delivery_success(self):
        group, node, target = self.recipient()
        original = target.client.request
        def bad_ack(path, payload=None):
            response = original(path, payload)
            return {'revision': 1} if payload is not None else response
        with patch.object(target.client, 'request', side_effect=bad_ack):
            self.rejected(502, lambda: self.deliver(group))
        self.assertEqual(self.history(group)[0]['outcome'], 'unknown')
        self.assertIsNotNone(node.export_policy()['policy'])

    def test_readback_and_freshness_must_match_the_exact_signed_snapshot(self):
        group, node, target = self.recipient()
        original = target.client.request
        def changed_read(path, payload=None):
            response = original(path, payload)
            if path == '/v1/policies' and payload is None and response['policy'] is not None:
                return {'policy': None}
            return response
        with patch.object(target.client, 'request', side_effect=changed_read):
            self.rejected(409, lambda: self.deliver(group))
        for index, patch_fields in enumerate([{'revision': 99}, {'expires_at': 9999}, {'max_age': True}, {'state': 'disabled'}]):
            def wrong_freshness(path, payload=None):
                response = original(path, payload)
                if path == '/v1/policy-sync': return response | {'policy': response['policy'] | patch_fields}
                return response
            with patch.object(target.client, 'request', side_effect=wrong_freshness):
                self.rejected(502, lambda: self.deliver(group, 'bad'+str(index)))

    def test_stale_policy_can_be_copied_but_receipt_does_not_claim_fresh_authorization(self):
        group, node, _ = self.recipient(max_age=10)
        self.now = 110
        before = self.export(group)
        receipt = self.deliver(group)
        self.assertEqual(receipt['authorization_state'], 'stale')
        self.assertEqual(receipt['expires_at'], 110)
        self.assertEqual(node.policy_status()['state'], 'stale')
        self.assertEqual(self.export(group), before)

    def test_network_io_does_not_block_local_policy_change_and_guard_stops_old_write(self):
        group, node, target = self.recipient()
        body = self.body(self.preview(group)); body.pop('group_id')
        original = target.client.request
        entered, release = threading.Event(), threading.Event()
        def slow(path, payload=None):
            entered.set()
            if not release.wait(3): raise TimeoutError('test deadline')
            return original(path, payload)
        with patch.object(target.client, 'request', side_effect=slow), ThreadPoolExecutor(max_workers=2) as pool:
            pending = pool.submit(self.store.policy_deliver, 'owner', group, body)
            try:
                self.assertTrue(entered.wait(2))
                pool.submit(self.store.policy_change, 'owner', group, 'renew', {'expected_revision': 1, 'request_id': 'new'}).result(timeout=2)
            finally:
                release.set()
            with self.assertRaises(FileExistsError): pending.result(timeout=3)
        self.assertEqual(node.export_policy(), {'policy': None})
        self.assertEqual(self.history(group)[0]['outcome'], 'conflict')

    def test_local_change_after_remote_acceptance_returns_conflict_and_requires_new_consent(self):
        group, node, target = self.recipient()
        original = target.client.request
        def change_after_post(path, payload=None):
            response = original(path, payload)
            if payload is not None:
                self.store.policy_change('owner', group, 'renew', {'expected_revision': 1, 'request_id': 'new'})
            return response
        with patch.object(target.client, 'request', side_effect=change_after_post):
            self.rejected(409, lambda: self.deliver(group))
        self.assertEqual(node.policy_status()['revision'], 1)
        self.assertEqual(self.export(group)['claims']['revision'], 2)
        self.assertEqual(self.history(group)[0]['outcome'], 'conflict')
        self.deliver(group, 'latest')
        self.assertEqual(node.policy_status()['revision'], 2)

    def test_restart_preserves_receipt_group_and_pending_retry_without_network_startup(self):
        group, _, target = self.recipient()
        body = self.body(self.preview(group)); body.pop('group_id')
        original = target.client.request
        def lose_status(path, payload=None):
            if path == '/v1/policy-sync': raise OSError('response lost')
            return original(path, payload)
        with patch.object(target.client, 'request', side_effect=lose_status), self.assertRaises(PolicyDeliveryError):
            self.store.policy_deliver('owner', group, body)
        self.store.close()
        with patch.object(target.client, 'request') as request:
            restored = ChatStore(self.database, policy_authority=self.authority, policy_targets=[target])
            self.addCleanup(restored.close)
            self.assertEqual(restored.groups('owner')[0]['id'], group)
            request.assert_not_called()
        with patch.object(target.client, 'request', wraps=original) as request:
            receipt = restored.policy_deliver('owner', group, body)
            self.assertTrue(all(len(call.args) == 1 for call in request.call_args_list))
        with patch.object(target.client, 'request') as request:
            self.assertEqual(restored.policy_deliver('owner', group, body), receipt)
            request.assert_not_called()

    def test_cli_restores_configured_recipient_and_requires_explicit_confirmation(self):
        self.now = int(time.time())
        group, node, target = self.recipient()
        path = self.root/'targets.json'
        path.write_text(json.dumps([{'id': target.id, 'url': target.url, 'group_id': group, 'token_env': 'TEST_RECIPIENT_READ'}]))
        command = [sys.executable, '-m', 'tailnet_agents.ui', '--port', '0', '--database', self.database,
                   '--policy-owner-key', str(self.key_path), '--policy-owner-public-key', str(self.pin_path),
                   '--policy-admin', 'owner', '--policy-targets-file', str(path)]
        env = os.environ | {'TAILNET_UI_USERS': json.dumps(self.users), 'TEST_RECIPIENT_READ': 'r'*32}
        process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(timeout=5), 'UI did not start')
            line = process.stdout.readline().strip()
            self.assertTrue(line.startswith('Simulated chat UI: http://127.0.0.1:'), line)
            client = Client(line.removeprefix('Simulated chat UI: '), 'o'*32)
            with patch.object(node, 'export_policy', wraps=node.export_policy) as contacted:
                self.assertEqual(client.request('/api/policy-targets?group_id='+group)['targets'][0]['url'], target.url)
                exported = client.request('/api/group-policy?group_id='+group)
                preview = client.request('/api/policy-delivery-preview', {'group_id': group, 'target_id': target.id,
                    'expected_revision': exported['claims']['revision'], 'policy_hash': exported['policy_hash']})
                contacted.assert_not_called()
            self.assertEqual(client.request('/api/policy-deliver', self.body(preview))['authorization_state'], 'fresh')
            process.send_signal(signal.SIGINT)
            _, error = process.communicate(timeout=8)
            self.assertEqual(process.returncode, 0, error)
            self.assertNotIn('r'*32, line+error)
        finally:
            if process.poll() is None:
                process.terminate(); process.communicate(timeout=8)

    def test_target_configuration_is_explicit_bounded_and_keeps_credentials_out_of_metadata(self):
        group, _, target = self.recipient()
        path = self.root/'targets.json'
        entry = {'id': 'lan', 'url': target.url, 'group_id': group, 'token_env': 'TEST_DELIVERY_TOKEN'}
        path.write_text(json.dumps([entry]))
        with patch.dict(os.environ, TEST_DELIVERY_TOKEN='r'*32):
            configured = load_policy_targets(path)
        self.assertEqual(configured[0].url, target.url)
        self.assertNotIn('r'*32, json.dumps(configured[0].public()))
        for data in [[entry | {'url': 'http://192.168.1.2'}], [entry | {'url': 'https://user:pass@example.test'}],
                     [entry | {'url': 'https://node.test/path'}], [entry | {'token': 'r'*32}],
                     [entry, entry], [entry]*9, []]:
            path.write_text(json.dumps(data))
            with patch.dict(os.environ, TEST_DELIVERY_TOKEN='r'*32), self.assertRaises(ValueError): load_policy_targets(path)
        path.write_text(json.dumps([entry]))
        with patch.dict(os.environ, TEST_DELIVERY_TOKEN=''), self.assertRaises(ValueError): load_policy_targets(path)

    def test_tls_ca_and_hostname_validation_apply_to_delivery(self):
        group = self.create()
        node = VerifiedDirectory(self.owner.public_key(), group, 'directory', require_policy=True, clock=lambda: self.now)
        self.addCleanup(node.close)
        paths = certificates(str(self.root))
        allowed, context = transport_config('127.0.0.1', paths['cert'], paths['key'], ['localhost', '127.0.0.1'])
        server = AdmissionHTTPServer(('127.0.0.1', 0), handler(node, 'r'*32, allowed, 'https'), context)
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        def stop(): server.shutdown(); server.server_close(); worker.join()
        self.addCleanup(stop)
        url = f'https://localhost:{server.server_port}'
        for index, target in enumerate([PolicyTarget('configured', url, group, 'r'*32),
                PolicyTarget('configured', url.replace('localhost', '127.0.0.1'), group, 'r'*32, paths['ca'])]):
            self.store.configure_policy_targets([target])
            self.rejected(502, lambda: self.deliver(group, 'bad'+str(index)))
        self.store.configure_policy_targets([PolicyTarget('configured', url, group, 'r'*32, paths['ca'])])
        self.assertEqual(self.deliver(group)['authorization_state'], 'fresh')
        config = self.root/'tls-targets.json'
        config.write_text(json.dumps([{'id': 'tls', 'url': url, 'group_id': group,
                                     'token_env': 'TEST_RECIPIENT_READ', 'ca_cert': os.path.basename(paths['ca'])}]))
        with patch.dict(os.environ, TEST_RECIPIENT_READ='r'*32):
            self.assertEqual(load_policy_targets(config)[0].client.url, url)

    def test_redirects_are_not_followed_and_errors_do_not_echo_credentials(self):
        group = self.create(); calls = []
        class Redirect(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(inner):
                calls.append(inner.path)
                inner.send_response(302); inner.send_header('Location', '/trap'); inner.end_headers()
        url = self.serve(Redirect)
        self.store.configure_policy_targets([PolicyTarget('configured', url, group, 'r'*32)])
        body = self.body(self.preview(group))
        with self.assertRaises(HTTPError) as error: self.clients['owner'].request('/api/policy-deliver', body)
        self.assertEqual(error.exception.code, 502)
        self.assertNotIn('r'*32, error.exception.read().decode()); error.exception.close()
        self.assertEqual(calls, ['/v1/policies'])
