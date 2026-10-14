"""Synthetic Agents sharing a machine remain separate authorization subjects."""
import unittest
import test_policy_delivery as fixtures

try:
    from tailnet_agents.identity import generate_identity, identity_id, issue_grant, load_identity, verify_grant
    from tailnet_agents.discovery import Candidates, make_announcement
    from tailnet_agents.verified_directory import VerifiedDirectory, issue_revocation
    from tailnet_agents.verified_client import VerifiedClient
    from tailnet_agents.admission_server import handler
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@unittest.skipUnless(HAS_CRYPTO, 'install identity extra')
class MultiAgentHostTests(unittest.TestCase):
    setUp = fixtures.PolicyDeliveryTests.setUp
    serve = fixtures.PolicyDeliveryTests.serve
    create = fixtures.PolicyDeliveryTests.create
    export = fixtures.PolicyDeliveryTests.export
    change = fixtures.PolicyDeliveryTests.change
    rejected = fixtures.PolicyDeliveryTests.rejected
    recipient = fixtures.PolicyDeliveryTests.recipient
    preview = fixtures.PolicyDeliveryTests.preview
    body = fixtures.PolicyDeliveryTests.body
    deliver = fixtures.PolicyDeliveryTests.deliver

    def identities(self, group, label):
        paths = [self.root / f'{label}-{index}.pem' for index in range(2)]
        keys = [generate_identity(path) for path in paths]
        grants = [issue_grant(self.owner, key.public_key(), group, ['join', 'discover'], now=self.now)
                  for key in keys]
        return paths, keys, grants

    def approve(self, group, grant, request_id):
        revision = self.export(group)['claims']['revision']
        self.change(group, 'approve', revision, request_id=request_id, grant=grant)

    def test_same_machine_agents_need_independent_human_approval(self):
        for network, host in [('lan', '192.168.10.20'), ('tailnet', 'node.example.ts.net')]:
            with self.subTest(network=network):
                group = self.create(request_id=network)
                _, node, target = self.recipient(group)
                _, keys, grants = self.identities(group, network)
                clients = [VerifiedClient(target.url, key, grant, 'directory')
                           for key, grant in zip(keys, grants)]
                records = [{'name': 'Same display name', 'endpoint': f'https://{host}:{port}', 'skills': ['echo']}
                           for port in (8901, 8902)]
                self.approve(group, grants[0], 'approve-first')
                self.deliver(group, 'first-policy')
                first = clients[0].register(records[0])
                self.rejected(403, lambda: clients[1].register(records[1]))
                self.approve(group, grants[1], 'approve-second')
                self.deliver(group, 'second-policy')
                second = clients[1].register(records[1])
                self.assertNotEqual(first['id'], second['id'])
                self.assertEqual({record['id'] for record in node.discover()}, {first['id'], second['id']})
                self.assertEqual({record['endpoint'] for record in node.discover()},
                                 {record['endpoint'] for record in records})

    def test_shared_locator_does_not_merge_keys_and_shared_key_renews_same_agent(self):
        group, node, target = self.recipient()
        _, keys, grants = self.identities(group, 'shared')
        for index, grant in enumerate(grants):
            self.approve(group, grant, f'approve-{index}')
        self.deliver(group)
        # A configured gateway may route multiple subjects behind one origin.
        record = {'name': 'Same name', 'endpoint': 'https://same-host.example:8901', 'skills': ['echo']}
        clients = [VerifiedClient(target.url, key, grant, 'directory') for key, grant in zip(keys, grants)]
        accepted = [client.register(record) for client in clients]
        self.assertNotEqual(accepted[0]['id'], accepted[1]['id'])
        self.assertEqual(clients[0].register(record)['id'], accepted[0]['id'])
        self.assertEqual(len(node.discover()), 2)
        impostor = VerifiedClient(target.url, keys[1], grants[0], 'directory')
        self.rejected(403, lambda: impostor.register(record))
        self.assertEqual(len(node.discover()), 2)

    def test_same_host_discovery_keeps_subjects_separate_and_conflicts_local(self):
        group, node, _ = self.recipient()
        _, keys, grants = self.identities(group, 'discovery')
        for index, grant in enumerate(grants):
            self.approve(group, grant, f'approve-{index}')
        policy = self.export(group)['policy']
        for host in ('192.168.10.20', 'node.example.ts.net'):
            with self.subTest(host=host):
                candidates = Candidates(policy, self.owner.public_key(), group, clock=lambda: self.now)
                for index, key in enumerate(keys):
                    envelope = make_announcement(key, policy, self.owner.public_key(), group,
                                                 f'https://{host}:{8901+index}', 'directory', now=self.now)
                    candidates.add(envelope, 'lan')
                    candidates.add(envelope, 'seed:0')
                result = candidates.result()
                self.assertEqual(result['conflicts'], [])
                self.assertEqual({item['subject'] for item in result['candidates']},
                                 {identity_id(key.public_key()) for key in keys})
                self.assertTrue(all(item['sources'] == ['lan', 'seed:0'] for item in result['candidates']))
                clone = make_announcement(keys[0], policy, self.owner.public_key(), group,
                                          f'https://{host}:8999', 'directory', now=self.now)
                candidates.add(clone, 'seed:1')
                self.assertEqual(candidates.result()['conflicts'], [identity_id(keys[0].public_key())])
                self.assertEqual([item['subject'] for item in candidates.result()['candidates']],
                                 [identity_id(keys[1].public_key())])
        self.assertEqual(node.discover(), [])  # Candidate discovery never enrolls either Agent.

    def test_removal_and_credential_revocation_affect_only_selected_agent(self):
        for operation in ('remove', 'revoke'):
            with self.subTest(operation=operation):
                group = self.create(request_id=operation)
                _, node, target = self.recipient(group)
                _, keys, grants = self.identities(group, operation)
                for index, grant in enumerate(grants):
                    self.approve(group, grant, f'approve-{index}')
                self.deliver(group)
                clients = [VerifiedClient(target.url, key, grant, 'directory') for key, grant in zip(keys, grants)]
                records = [{'endpoint': f'https://same-host.example:{8901+index}', 'skills': ['echo']}
                           for index in range(2)]
                accepted = [client.register(record) for client, record in zip(clients, records)]
                if operation == 'remove':
                    self.change(group, 'remove', 3, request_id='remove-one', subject=identity_id(keys[0].public_key()))
                    self.deliver(group, 'remove-delivery')
                else:
                    credential = verify_grant(grants[0], self.owner.public_key(), group, now=self.now)['jti']
                    node.revoke(issue_revocation(self.owner, group, credential))
                self.assertEqual([record['id'] for record in node.discover()], [accepted[1]['id']])
                self.rejected(403, lambda: clients[0].register(records[0]))
                self.assertEqual(clients[1].register(records[1])['id'], accepted[1]['id'])

    def test_restart_restores_individual_keys_and_original_group_without_auto_join(self):
        group = self.create()
        paths, keys, grants = self.identities(group, 'restart')
        original_files = [path.read_bytes() for path in paths]
        for index, grant in enumerate(grants):
            self.approve(group, grant, f'approve-{index}')
        policy = self.export(group)['policy']
        accepted_ids = []
        for phase in range(2):
            node = VerifiedDirectory(self.owner.public_key(), group, 'directory', require_policy=True,
                                     database=str(self.root/'directory.sqlite3'), clock=lambda: self.now)
            try:
                if phase == 0:
                    node.apply_policy(policy)
                self.assertEqual(node.group_id, group)
                self.assertEqual(node.export_policy()['policy'], policy)
                self.assertEqual(node.discover(), [])
                url = self.serve(handler(node, 'r'*32))
                ids = []
                for index, path in enumerate(paths):
                    restored = load_identity(path)
                    self.assertEqual(identity_id(restored.public_key()), identity_id(keys[index].public_key()))
                    client = VerifiedClient(url, restored, grants[index], 'directory')
                    ids.append(client.register({'endpoint': f'https://same-host.example:{8901+index}'})['id'])
                    self.assertEqual(len(node.discover()), index+1)
                accepted_ids.append(ids)
            finally:
                node.close()
        self.assertEqual(accepted_ids[0], accepted_ids[1])
        self.assertEqual([path.read_bytes() for path in paths], original_files)
        self.assertEqual(len(self.clients['owner'].request('/api/groups')['groups']), 1)
