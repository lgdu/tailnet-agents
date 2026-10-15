import copy
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import test_policy_delivery as fixtures

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tailnet_agents.agent_runtime import AgentRuntime
    from tailnet_agents.chat import ChatStore
    from tailnet_agents.client import Client
    from tailnet_agents.identity import issue_grant, sign
    from tailnet_agents.group_policy import POLICY_TYPE, revise_policy
    from tailnet_agents.policy_delivery import PolicyTarget
    from tailnet_agents.admission_server import AdmissionHTTPServer, handler, transport_config
    from test_admission_tls import certificates
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@unittest.skipUnless(HAS_CRYPTO, 'install identity extra')
class RuntimeMonitorTests(unittest.TestCase):
    serve = fixtures.PolicyDeliveryTests.serve
    create = fixtures.PolicyDeliveryTests.create
    export = fixtures.PolicyDeliveryTests.export
    grant = fixtures.PolicyDeliveryTests.grant
    change = fixtures.PolicyDeliveryTests.change
    rejected = fixtures.PolicyDeliveryTests.rejected
    recipient = fixtures.PolicyDeliveryTests.recipient
    preview = fixtures.PolicyDeliveryTests.preview
    body = fixtures.PolicyDeliveryTests.body
    deliver = fixtures.PolicyDeliveryTests.deliver

    def setUp(self):
        fixtures.PolicyDeliveryTests.setUp(self)
        self.group, self.node, self.target = self.recipient()
        self.saved_grant = self.grant(self.group)
        self.change(self.group, 'approve', 1, grant=self.saved_grant)
        self.deliver(self.group)
        self.record = {'name': 'Same host', 'endpoint': 'https://same-host.example:8901', 'ttl_seconds': 10}
        self.runtime = self.make_runtime('first', self.agent, self.saved_grant)

    def make_runtime(self, name, key, grant):
        runtime = AgentRuntime(self.target.url, key, self.owner.public_key(), grant, self.group, 'directory',
                               self.root/(name+'.sqlite3'), self.record, clock=lambda: self.now)
        self.addCleanup(runtime.close)
        return runtime

    def path(self, suffix=''):
        return '/api/runtime-presence?group_id='+self.group+'&target_id=configured'+suffix

    def monitor(self, suffix=''):
        return self.clients['owner'].request(self.path(suffix))

    def registered(self):
        self.assertEqual(self.runtime.step()['state'], 'registered')

    def test_confirmed_online_is_signed_scoped_and_attributed_to_configured_directory(self):
        self.now = 100.7
        self.registered()
        page = self.monitor()
        self.assertEqual(page['target'], self.target.public())
        self.assertTrue(page['policy']['matches_local'])
        self.assertEqual(page['policy']['state'], 'fresh')
        self.assertEqual(page['checked_at'], self.now)
        self.assertEqual(page['entries'][0]['state'], 'online')
        self.assertEqual(page['entries'][0]['subject'], self.subject)
        self.assertEqual(page['entries'][0]['issued_at'], self.now)
        self.assertEqual(page['entries'][0]['expires_at'], self.now+10)

    def test_opening_ui_and_listing_sources_do_not_contact_directory(self):
        with patch.object(self.target.client, 'request') as request:
            for path in ('/api/groups', '/api/group-policy?group_id='+self.group, '/api/policy-targets?group_id='+self.group):
                self.clients['owner'].request(path)
            request.assert_not_called()
        self.assertEqual(self.node.presence_status()['entries'], [])

    def test_empty_observations_do_not_remove_approved_member(self):
        before = self.export(self.group)
        self.assertEqual(self.monitor()['entries'], [])
        self.assertIn(self.subject, self.export(self.group)['claims']['members'])
        self.assertEqual(self.export(self.group), before)

    def test_reading_uses_only_get_and_neither_changes_leases_nor_echo_state(self):
        self.registered()
        observations = self.node.presence_status()
        echo = self.store.members()
        before = self.store.db.iterdump()
        snapshot = tuple(before)
        original = self.target.client.request
        with patch.object(self.target.client, 'request', wraps=original) as request:
            page = self.monitor()
            self.assertEqual([call.args[0] for call in request.call_args_list], ['/v1/policies', '/v1/presence?after=&limit=20', '/v1/policies'])
            self.assertTrue(all(len(call.args)==1 and not call.kwargs for call in request.call_args_list))
        self.assertEqual(self.node.presence_status(), observations)
        self.assertEqual(self.store.members(), echo)
        self.assertEqual(tuple(self.store.db.iterdump()), snapshot)
        serialized = json.dumps(page)
        for secret in (self.saved_grant, 'r'*32, 'o'*32): self.assertNotIn(secret, serialized)
        self.assertNotIn('presence', page['entries'][0])  # Browser receives validated display fields.

    def test_same_host_agents_remain_separate_and_pagination_replaces_one_page(self):
        other = Ed25519PrivateKey.generate()
        grant = issue_grant(self.owner, other.public_key(), self.group, ['join'], now=100)
        self.change(self.group, 'approve', 2, request_id='second', grant=grant)
        self.deliver(self.group, 'second-delivery')
        self.registered()
        self.assertEqual(self.make_runtime('second', other, grant).step()['state'], 'registered')
        first = self.monitor('&limit=1')
        second = self.monitor('&limit=1&after='+first['next_after'])
        self.assertTrue(first['has_more'])
        self.assertFalse(second['has_more'])
        self.assertEqual(len(first['entries']), 1)
        self.assertEqual(len(second['entries']), 1)
        self.assertNotEqual(first['entries'][0]['subject'], second['entries'][0]['subject'])
        self.assertEqual(first['entries'][0]['record']['endpoint'], second['entries'][0]['record']['endpoint'])

    def test_offline_expiry_and_revocation_are_not_membership_mutations(self):
        self.registered()
        self.assertEqual(self.runtime.step(offline=True)['state'], 'offline')
        self.assertEqual(self.monitor()['entries'][0]['state'], 'offline')
        self.registered()
        self.now = 110
        self.assertEqual(self.monitor()['entries'][0]['state'], 'expired')
        self.now = 111
        self.registered()
        from tailnet_agents.verified_directory import issue_revocation
        from tailnet_agents.identity import verify_grant
        credential = verify_grant(self.saved_grant, self.owner.public_key(), self.group, now=self.now)['jti']
        self.node.revoke(issue_revocation(self.owner, self.group, credential))
        self.assertEqual(self.monitor()['entries'][0]['state'], 'unauthorized')
        self.assertIn(self.subject, self.export(self.group)['claims']['members'])

    def test_local_removal_without_delivery_blocks_confirmed_online(self):
        self.registered()
        self.change(self.group, 'remove', 2, request_id='remove', subject=self.subject)
        page = self.monitor()
        self.assertFalse(page['policy']['matches_local'])
        self.assertEqual(page['entries'][0]['state'], 'unconfirmed')
        self.assertEqual(self.node.presence_status()['entries'][0]['state'], 'online')
        self.deliver(self.group, 'removal-delivery')
        self.assertEqual(self.monitor()['entries'][0]['state'], 'unauthorized')

    def test_higher_remote_policy_is_diagnostic_not_automatically_applied_locally(self):
        self.registered()
        before = self.export(self.group)
        self.node.apply_policy(revise_policy(self.owner, before['policy'], before['claims']['members'], now=101))
        page = self.monitor()
        self.assertFalse(page['policy']['matches_local'])
        self.assertEqual(page['entries'][0]['state'], 'unconfirmed')
        self.assertEqual(self.export(self.group), before)

    def test_policy_expiry_and_dissolution_cannot_display_confirmed_online(self):
        self.registered()
        self.now = 400
        page = self.monitor()
        self.assertEqual(page['policy']['state'], 'stale')
        self.assertEqual(page['entries'][0]['state'], 'unauthorized')
        self.store.dissolve_group('owner', self.group, 'Human approved')
        self.deliver(self.group, 'dissolution-delivery')
        page = self.monitor()
        self.assertEqual(page['policy']['state'], 'dissolved')
        self.assertEqual(page['entries'][0]['state'], 'unauthorized')

    def test_missing_remote_policy_is_empty_unconfirmed_and_not_filled_by_monitor(self):
        with self.node._registry.db: self.node._registry.db.execute('DELETE FROM group_policy')
        page = self.monitor()
        self.assertEqual(page['policy']['state'], 'missing')
        self.assertFalse(page['policy']['matches_local'])
        self.assertEqual(page['entries'], [])
        self.assertEqual(self.node.export_policy(), {'policy': None})

    def test_roles_unknown_sources_foreign_groups_and_anonymous_reads_fail_before_network(self):
        foreign = self.create(name='Other group', request_id='other-group')
        with patch.object(self.target.client, 'request') as request:
            for actor in ('other', 'participant', 'observer'):
                self.rejected(403, lambda: self.clients[actor].request(self.path()))
            self.rejected(403, lambda: Client(self.url, 'bad').request(self.path()))
            self.rejected(403, lambda: self.clients['owner'].request(self.path().replace(self.group, foreign)))
            self.rejected(400, lambda: self.clients['owner'].request(self.path().replace('target_id=configured', 'target_id=unknown')))
            request.assert_not_called()

    def test_bad_queries_and_cursors_never_contact_directory(self):
        with patch.object(self.target.client, 'request') as request:
            for suffix in ('&limit=0', '&limit=21', '&limit=true', '&limit=1&limit=2', '&after=bad', '&url=https://evil.example'):
                self.rejected(400, lambda: self.monitor(suffix))
            self.rejected(400, lambda: self.clients['owner'].request('/api/runtime-presence?group_id='+self.group))
            request.assert_not_called()

    def test_cross_origin_request_is_denied_before_network(self):
        with patch.object(self.target.client, 'request') as request:
            for extra in ({'Origin': 'https://evil.example'}, {'Host': 'evil.example'}):
                req = Request(self.url+self.path(), headers={'Authorization': 'Bearer '+'o'*32, **extra})
                with self.assertRaises(HTTPError) as caught: urlopen(req, timeout=2)
                self.assertEqual(caught.exception.code, 403)
                caught.exception.close()
            request.assert_not_called()

    def test_tampered_signature_metadata_scope_and_cursors_fail_closed(self):
        self.registered()
        original = self.target.client.request
        mutations = [lambda page: page.update(group_id='foreign'),
                     lambda page: page['entries'][0]['record'].update(endpoint='https://evil.example'),
                     lambda page: page['entries'][0].update(presence='bad'),
                     lambda page: page.update(next_after=''),
                     lambda page: page['policy'].update(expires_at=999999),
                     lambda page: page['policy'].update(revision=True),
                     lambda page: page.update(observed_at=106)]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                def changed(path, *args, **kwargs):
                    response = copy.deepcopy(original(path, *args, **kwargs))
                    if path.startswith('/v1/presence'): mutate(response)
                    return response
                with patch.object(self.target.client, 'request', side_effect=changed):
                    self.rejected(502, self.monitor)

    def test_wrong_authority_and_read_token_errors_are_sanitized(self):
        wrong = sign(Ed25519PrivateKey.generate(), self.export(self.group)['claims'], POLICY_TYPE)
        with patch.object(self.target.client, 'request', return_value={'policy': wrong}):
            self.rejected(502, self.monitor)
        def failure(*args, **kwargs): raise OSError('secret '+'r'*32+' https://hidden.example')
        with patch.object(self.target.client, 'request', side_effect=failure):
            with self.assertRaises(HTTPError) as caught: self.monitor()
            self.assertEqual(caught.exception.code, 502)
            message = caught.exception.read().decode();caught.exception.close()
            self.assertNotIn('secret', message)
            self.assertNotIn('r'*32, message)
            self.assertNotIn('hidden', message)
        self.target.client.token = 'wrong'
        self.rejected(502, self.monitor)

    def test_expiry_during_final_policy_read_is_rechecked_before_display(self):
        self.registered()
        original, reads = self.target.client.request, []
        def delayed(path, *args, **kwargs):
            response = original(path, *args, **kwargs)
            if path == '/v1/policies':
                reads.append(path)
                if len(reads)==2: self.now = 400
            return response
        with patch.object(self.target.client, 'request', side_effect=delayed): page = self.monitor()
        self.assertEqual(page['checked_at'], 400)
        self.assertEqual(page['policy']['state'], 'stale')
        self.assertEqual(page['entries'][0]['state'], 'expired')

    def test_source_policy_change_mid_read_returns_conflict(self):
        self.registered()
        original, reads = self.target.client.request, []
        def changed(path, *args, **kwargs):
            if path == '/v1/policies':
                reads.append(path)
                if len(reads)==2:
                    policy = self.export(self.group)
                    self.node.apply_policy(revise_policy(self.owner, policy['policy'], policy['claims']['members'], now=101))
            return original(path, *args, **kwargs)
        with patch.object(self.target.client, 'request', side_effect=changed): self.rejected(409, self.monitor)

    def test_network_io_does_not_hold_local_lock_and_local_policy_change_discards_page(self):
        self.registered()
        original, entered, release = self.target.client.request, threading.Event(), threading.Event()
        def delayed(path, *args, **kwargs):
            if path.startswith('/v1/presence'):
                entered.set()
                if not release.wait(5): raise TimeoutError('test deadline')
            return original(path, *args, **kwargs)
        with patch.object(self.target.client, 'request', side_effect=delayed), ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(lambda: self.rejected(409, self.monitor))
            try:
                self.assertTrue(entered.wait(3))
                self.change(self.group, 'renew', 2, request_id='renew-during-read')
                self.assertEqual(self.export(self.group)['claims']['revision'], 3)
            finally: release.set()
            future.result(timeout=5)

    def test_reconfigured_target_discards_in_flight_page(self):
        self.registered()
        original = self.target.client.request
        def changed(path, *args, **kwargs):
            response = original(path, *args, **kwargs)
            if path.startswith('/v1/presence'):
                self.store.configure_policy_targets([PolicyTarget('configured', self.target.url, self.group, 'r'*32)])
            return response
        with patch.object(self.target.client, 'request', side_effect=changed): self.rejected(409, self.monitor)

    def test_restart_restores_original_group_and_config_without_saved_online_cache(self):
        self.registered()
        before = self.export(self.group)
        with patch.object(self.target.client, 'request') as request:
            restored = ChatStore(self.database, policy_authority=self.authority, policy_targets=[self.target])
            self.addCleanup(restored.close)
            request.assert_not_called()
        self.assertEqual(restored.policy_export('owner', self.group), before)
        self.assertEqual(len(restored.groups('owner')), 1)
        self.assertEqual(restored.runtime_presence('owner', self.group, 'configured')['entries'][0]['state'], 'online')

    def test_tls_ca_and_hostname_are_verified(self):
        self.registered()
        paths = certificates(str(self.root))
        allowed, context = transport_config('127.0.0.1', paths['cert'], paths['key'], ['localhost', '127.0.0.1'])
        server = AdmissionHTTPServer(('127.0.0.1', 0), handler(self.node, 'r'*32, allowed, 'https'), context)
        thread = threading.Thread(target=server.serve_forever, daemon=True);thread.start()
        def cleanup(): server.shutdown();server.server_close();thread.join()
        self.addCleanup(cleanup)
        for host, ca, expected in [('localhost', None, 502), ('127.0.0.1', paths['ca'], 502), ('localhost', paths['ca'], 200)]:
            target = PolicyTarget('configured', f'https://{host}:{server.server_port}', self.group, 'r'*32, ca)
            self.store.configure_policy_targets([target])
            if expected==200: self.assertEqual(self.monitor()['entries'][0]['state'], 'online')
            else: self.rejected(expected, self.monitor)


if __name__ == '__main__':
    unittest.main()
