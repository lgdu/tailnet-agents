import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from tailnet_agents.chat import ChatStore
from tailnet_agents.client import Client
from tailnet_agents.ui import handler
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tailnet_agents.identity import (AdmissionError, encode, generate_identity, identity_id,
                                        issue_grant, public_bytes)
    from tailnet_agents.group_policy import verify_policy
    from tailnet_agents.policy_admin import PolicyAuthority
    from tailnet_agents.verified_directory import VerifiedDirectory
    from tailnet_agents.verified_client import VerifiedClient
    from tailnet_agents.admission_server import handler as admission_handler
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@unittest.skipUnless(HAS_CRYPTO, 'install identity extra')
class HumanPolicyTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.key_path, self.pin_path = self.root/'owner.pem', self.root/'owner.pub'
        self.owner = generate_identity(self.key_path)
        self.pin_path.write_text(encode(public_bytes(self.owner.public_key())))
        self.agent = Ed25519PrivateKey.generate()
        self.subject = identity_id(self.agent.public_key())
        self.now = 100
        self.authority = PolicyAuthority(self.owner, 'owner', clock=lambda: self.now)
        self.database = str(self.root/'chat.sqlite3')
        self.store = ChatStore(self.database, policy_authority=self.authority)
        self.addCleanup(self.store.close)
        self.users = {name: {'token': char*32, 'role': role} for name, char, role in
                      [('owner', 'o', 'admin'), ('other', 'a', 'admin'),
                       ('participant', 'p', 'participant'), ('observer', 'w', 'observer')]}
        self.url = self.serve(handler(self.store, self.users))
        self.clients = {name: Client(self.url, config['token']) for name, config in self.users.items()}

    def serve(self, http_handler):
        server = ThreadingHTTPServer(('127.0.0.1', 0), http_handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def stop():
            server.shutdown(); server.server_close(); thread.join()
        self.addCleanup(stop)
        return f'http://127.0.0.1:{server.server_port}'

    def create(self, name='Human approved', request_id='creation', **extra):
        return self.clients['owner'].request('/api/groups', {
            'name': name, 'humans': list(self.users), 'request_id': request_id, 'signed_policy': True, **extra})['id']

    def export(self, group):
        return self.clients['owner'].request('/api/group-policy?group_id='+group)

    def grant(self, group, **options):
        return issue_grant(self.owner, self.agent.public_key(), group, ['join', 'discover'], now=self.now, **options)

    def change(self, group, operation, revision, request_id='change', **options):
        return self.clients['owner'].request('/api/policy-'+operation, {
            'group_id': group, 'expected_revision': revision, 'request_id': request_id, **options})

    def rejected(self, status, call):
        with self.assertRaises(HTTPError) as error: call()
        self.assertEqual(error.exception.code, status)
        error.exception.close()

    def test_startup_and_discovery_do_not_create_or_sign_any_group(self):
        self.assertEqual(self.clients['owner'].request('/api/groups'), {'groups': []})
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM ui_group_policies').fetchone(), (0,))
        self.assertEqual(self.clients['owner'].request('/api/policy-config'), {'enabled': True, 'can_sign': True})
        self.assertFalse(self.clients['other'].request('/api/policy-config')['can_sign'])
        self.rejected(404, lambda: self.clients['owner'].request('/v1/discovery'))

    def test_explicit_creation_binds_ui_and_empty_signed_policy_to_same_id(self):
        group = self.create()
        exported = self.export(group)
        policy = verify_policy(exported['policy'], self.owner.public_key(), group)
        self.assertEqual(policy['revision'], 1)
        self.assertEqual(policy['members'], {})
        self.assertEqual(self.create(), group)
        self.assertEqual(len(self.export(group)['audit']), 1)
        self.rejected(409, lambda: self.create(signed_policy=False))
        self.assertEqual(len(self.clients['owner'].request('/api/groups')['groups']), 1)

    def test_unsigned_groups_remain_local_and_are_not_implicitly_converted(self):
        group = self.create(signed_policy=False)
        self.rejected(400, lambda: self.export(group))
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM ui_group_policies').fetchone(), (0,))
        self.store.dissolve_group('owner', group, 'Human approved')
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM ui_group_policies').fetchone(), (0,))

    def test_other_roles_and_invited_admin_cannot_sign_or_export(self):
        group = self.create()
        for human in ('other', 'participant', 'observer'):
            client = self.clients[human]
            self.rejected(403, lambda: client.request('/api/groups', {'name': 'bad', 'humans': [], 'request_id': 'bad', 'signed_policy': True}))
            self.rejected(403, lambda: client.request('/api/group-policy?group_id='+group))
            for operation in ('preview', 'approve', 'remove', 'renew'):
                self.rejected(403, lambda: client.request('/api/policy-'+operation, {'group_id': group}))
        self.assertEqual(self.export(group)['claims']['revision'], 1)

    def test_preview_does_not_approve_and_raw_grants_are_never_persisted(self):
        group = self.create()
        grant = self.grant(group)
        preview = self.clients['owner'].request('/api/policy-preview', {'group_id': group, 'grant': grant})
        self.assertEqual(preview['subject'], self.subject)
        self.assertEqual(preview['proposed_member']['permissions'], ['discover', 'join'])
        self.assertEqual(self.export(group)['claims']['members'], {})
        result = self.change(group, 'approve', 1, grant=grant)
        self.assertEqual(result['revision'], 2)
        exported = self.export(group)
        self.assertEqual(list(exported['claims']['members']), [self.subject])
        self.assertNotIn(grant, '\n'.join(self.store.db.iterdump()))
        self.assertNotIn(grant, json.dumps(exported))
        self.assertNotIn('PRIVATE KEY', json.dumps(exported))
        self.assertEqual(exported['audit'][-1]['actor'], 'owner')
        self.assertEqual(exported['audit'][-1]['policy_hash'], result['policy_hash'])

    def test_approval_rejects_foreign_expired_future_and_malformed_grants(self):
        group = self.create()
        other = Ed25519PrivateKey.generate()
        invalid = [self.grant('foreign'), issue_grant(other, self.agent.public_key(), group, ['join'], now=100),
                   issue_grant(self.owner, self.agent.public_key(), group, ['join'], now=90, lifetime=10),
                   issue_grant(self.owner, self.agent.public_key(), group, ['join'], now=101), 'bad', []]
        for grant in invalid:
            self.rejected(400, lambda: self.change(group, 'approve', 1, grant=grant))
        self.assertEqual(self.export(group)['claims']['revision'], 1)

    def test_operation_retries_deduplicate_but_revision_and_payload_conflicts_fail(self):
        group = self.create()
        grant = self.grant(group)
        first = self.change(group, 'approve', 1, grant=grant)
        self.assertEqual(self.change(group, 'approve', 1, grant=grant), first)
        self.rejected(409, lambda: self.change(group, 'renew', 2))
        self.rejected(409, lambda: self.change(group, 'renew', 1, request_id='stale'))
        self.assertEqual(len(self.export(group)['audit']), 2)
        self.rejected(400, lambda: self.change(group, 'renew', True, request_id='bool'))

    def test_competing_changes_are_serialized_by_expected_revision(self):
        group = self.create()
        def attempt(index):
            try: return self.change(group, 'renew', 1, request_id=str(index))['revision']
            except HTTPError as error: return error.code
        with ThreadPoolExecutor(max_workers=2) as executor:
            self.assertEqual(sorted(executor.map(attempt, (1, 2))), [2, 409])
        self.assertEqual(len(self.export(group)['audit']), 2)

    def test_explicit_renewal_recovers_expired_policy_without_new_identity_or_group(self):
        group = self.create()
        node = VerifiedDirectory(self.owner.public_key(), group, 'directory', require_policy=True, clock=lambda: self.now)
        self.addCleanup(node.close)
        node.apply_policy(self.export(group)['policy'])
        self.now = 400
        self.assertEqual(node.policy_status()['state'], 'stale')
        self.assertEqual(self.export(group)['claims']['issued_at'], 100)  # Reading never renews.
        self.change(group, 'renew', 1)
        node.apply_policy(self.export(group)['policy'])
        self.assertEqual(node.policy_status()['state'], 'fresh')
        self.assertEqual(node.group_id, group)
        self.assertEqual(self.store.groups('owner')[0]['id'], group)

    def test_clock_rollback_and_signing_failure_leave_policy_and_audit_unchanged(self):
        group = self.create()
        before = self.export(group)
        self.now = 99
        self.rejected(400, lambda: self.change(group, 'renew', 1))
        self.now = 100
        with patch('tailnet_agents.policy_admin.revise_policy', side_effect=ValueError('signing unavailable')):
            self.rejected(400, lambda: self.change(group, 'renew', 1))
            self.rejected(400, lambda: self.clients['owner'].request('/api/group-dissolve', {'group_id': group, 'confirm_name': 'Human approved'}))
        self.assertEqual(self.export(group), before)
        self.assertFalse(self.store.groups('owner')[0]['dissolved'])

    def test_removed_credential_cannot_be_reapproved_but_new_grant_can(self):
        group = self.create()
        grant = self.grant(group)
        self.change(group, 'approve', 1, grant=grant)
        self.change(group, 'remove', 2, request_id='remove', subject=self.subject)
        self.rejected(400, lambda: self.change(group, 'approve', 3, request_id='old', grant=grant))
        self.change(group, 'approve', 3, request_id='new', grant=self.grant(group))
        self.assertEqual(self.export(group)['claims']['revision'], 4)

    def test_failed_removal_rolls_back_retirement_and_failed_creation_creates_nothing(self):
        with patch('tailnet_agents.policy_admin.create_policy', side_effect=ValueError('signing unavailable')):
            self.rejected(400, self.create)
        self.assertEqual(self.store.groups('owner'), [])
        group = self.create()
        grant = self.grant(group)
        self.change(group, 'approve', 1, grant=grant)
        before = self.export(group)
        with patch('tailnet_agents.policy_admin.revise_policy', side_effect=ValueError('signing unavailable')):
            self.rejected(400, lambda: self.change(group, 'remove', 2, request_id='remove', subject=self.subject))
        self.assertEqual(self.export(group), before)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM ui_retired_grants').fetchone(), (0,))

    def test_approval_limit_and_duplicate_grant_do_not_advance_revision(self):
        group = self.create()
        grants = [self.grant(group) for _ in range(9)]
        for index, grant in enumerate(grants[:8]):
            self.change(group, 'approve', index+1, request_id=str(index), grant=grant)
        self.rejected(400, lambda: self.change(group, 'approve', 9, request_id='ninth', grant=grants[8]))
        self.rejected(400, lambda: self.change(group, 'approve', 9, request_id='duplicate', grant=grants[0]))
        self.assertEqual(self.export(group)['claims']['revision'], 9)
        self.assertEqual(len(self.export(group)['audit']), 9)

    def test_enabling_signing_preserves_existing_local_groups_without_conversion(self):
        database = str(self.root/'old.sqlite3')
        local = ChatStore(database)
        group = local.create_group('Original local', 'owner', [], request_id='old')
        local.close()
        upgraded = ChatStore(database, policy_authority=self.authority)
        self.addCleanup(upgraded.close)
        self.assertEqual(upgraded.groups('owner'), [group | {'dissolved': False}])
        with self.assertRaises(ValueError): upgraded.policy_export('owner', group['id'])
        self.assertEqual(upgraded.db.execute('SELECT COUNT(*) FROM ui_group_policies').fetchone(), (0,))

    def test_terminal_dissolution_signs_once_and_preserves_history(self):
        group = self.create()
        self.store.send({'conversation': 'group', 'text': 'retained', 'request_id': 'message'}, 'owner', group, enforce_access=True)
        for _ in range(2):
            self.clients['owner'].request('/api/group-dissolve', {'group_id': group, 'confirm_name': 'Human approved'})
        exported = self.export(group)
        self.assertEqual(exported['claims']['state'], 'dissolved')
        self.assertEqual(exported['claims']['revision'], 2)
        self.assertEqual([event['action'] for event in exported['audit']], ['create', 'dissolve'])
        self.assertEqual(len(self.store.page('group', 'owner', group_id=group)['messages']), 2)
        self.rejected(403, lambda: self.change(group, 'renew', 2))
        self.rejected(403, lambda: self.clients['owner'].request('/api/policy-preview', {'group_id': group, 'grant': self.grant(group)}))

    def test_human_membership_and_echo_presence_do_not_change_network_policy(self):
        group = self.create()
        before = self.export(group)
        self.store.update_member('owner', group, 'participant', 'remove')
        self.store.set_online('coder', False)
        self.assertEqual(self.export(group), before)

    def test_network_directory_requires_explicit_policy_delivery_and_agent_proof(self):
        group = self.create()
        node = VerifiedDirectory(self.owner.public_key(), group, 'directory', require_policy=True, clock=lambda: self.now)
        self.addCleanup(node.close)
        url = self.serve(admission_handler(node, 'r'*32))
        reader = Client(url, 'r'*32)
        grant = self.grant(group)
        agent = VerifiedClient(url, self.agent, grant, 'directory')
        record = {'endpoint': 'https://approved.example', 'skills': ['echo']}
        reader.request('/v1/policies', {'policy': self.export(group)['policy']})
        self.rejected(403, lambda: agent.register(record))
        self.change(group, 'approve', 1, grant=grant)
        self.rejected(403, lambda: agent.register(record))  # UI does not push or register.
        reader.request('/v1/policies', {'policy': self.export(group)['policy']})
        agent.register(record)
        self.assertEqual(len(reader.request('/v1/agents')['agents']), 1)
        self.change(group, 'remove', 2, request_id='remove', subject=self.subject)
        reader.request('/v1/policies', {'policy': self.export(group)['policy']})
        self.rejected(403, lambda: agent.register(record))
        self.assertEqual(reader.request('/v1/agents'), {'agents': []})
        self.clients['owner'].request('/api/group-dissolve', {'group_id': group, 'confirm_name': 'Human approved'})
        reader.request('/v1/policies', {'policy': self.export(group)['policy']})
        self.assertEqual(node.policy_status()['state'], 'dissolved')

    def test_restart_restores_original_authority_group_policy_and_retry_results(self):
        group = self.create()
        body = {'expected_revision': 1, 'request_id': 'approve', 'grant': self.grant(group)}
        result = self.store.policy_change('owner', group, 'approve', body)
        before = self.export(group)
        self.store.close()
        restored = ChatStore(self.database, policy_authority=self.authority)
        self.addCleanup(restored.close)
        self.assertEqual(restored.policy_export('owner', group), before)
        self.assertEqual(restored.policy_change('owner', group, 'approve', body), result)
        self.assertEqual(len(restored.groups('owner')), 1)

    def test_restart_cannot_disable_signer_or_change_owner_or_human(self):
        self.create()
        self.store.close()
        for authority in (None, PolicyAuthority(Ed25519PrivateKey.generate(), 'owner'), PolicyAuthority(self.owner, 'other')):
            with self.subTest(authority=authority), self.assertRaises(ValueError):
                ChatStore(self.database, policy_authority=authority)

    def test_key_loading_rejects_missing_symlink_permissions_and_wrong_public_pin(self):
        loaded = PolicyAuthority.from_files(self.key_path, self.pin_path, 'owner')
        self.assertEqual(loaded.owner, self.authority.owner)
        missing = self.root/'missing.pem'
        with self.assertRaises(OSError): PolicyAuthority.from_files(missing, self.pin_path, 'owner')
        self.assertFalse(missing.exists())
        link = self.root/'link.pem'
        link.symlink_to(self.key_path)
        with self.assertRaises(OSError): PolicyAuthority.from_files(link, self.pin_path, 'owner')
        self.key_path.chmod(0o644)
        with self.assertRaises(ValueError): PolicyAuthority.from_files(self.key_path, self.pin_path, 'owner')
        self.key_path.chmod(0o600)
        self.pin_path.write_text(encode(public_bytes(self.agent.public_key())))
        with self.assertRaises(ValueError): PolicyAuthority.from_files(self.key_path, self.pin_path, 'owner')

    def test_http_origin_host_unknown_fields_and_duplicate_group_query_are_rejected(self):
        group = self.create()
        request = Request(self.url+'/api/policy-renew', data=json.dumps({'group_id': group}).encode(),
                          headers={'Authorization': 'Bearer '+'o'*32, 'Origin': 'https://foreign.example'})
        self.rejected(403, lambda: urlopen(request))
        request = Request(self.url+'/api/group-policy?group_id='+group, headers={'Authorization': 'Bearer '+'o'*32, 'Host': 'foreign.example'})
        self.rejected(403, lambda: urlopen(request))
        self.rejected(400, lambda: self.clients['owner'].request('/api/group-policy?group_id='+group+'&group_id='+group))
        self.rejected(400, lambda: self.change(group, 'renew', 1, private_key='forbidden'))

    def test_cli_rejects_incomplete_config_without_creating_database_or_key(self):
        database = self.root/'must-not-exist.sqlite3'
        result = subprocess.run([sys.executable, '-m', 'tailnet_agents.ui', '--database', str(database),
                                 '--policy-owner-key', str(self.root/'missing.pem')],
                                env=os.environ | {'TAILNET_UI_TOKEN': 's'*32}, capture_output=True, text=True, timeout=8)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(database.exists())
        self.assertFalse((self.root/'missing.pem').exists())

    def test_real_ui_cli_restart_keeps_group_and_policy_without_auto_renewal(self):
        database = self.root/'cli.sqlite3'
        env = os.environ | {'TAILNET_UI_TOKEN': 's'*32}
        env.pop('TAILNET_UI_USERS', None)
        command = [sys.executable, '-m', 'tailnet_agents.ui', '--port', '0', '--database', str(database),
                   '--policy-owner-key', str(self.key_path), '--policy-owner-public-key', str(self.pin_path), '--policy-admin', 'demo-owner']
        before = group = None
        for restart in (False, True):
            process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(timeout=5), 'UI did not start')
                line = process.stdout.readline().strip()
                self.assertTrue(line.startswith('Simulated chat UI: http://127.0.0.1:'), line)
                client = Client(line.removeprefix('Simulated chat UI: '), 's'*32)
                if not restart:
                    self.assertEqual(client.request('/api/groups'), {'groups': []})
                    group = client.request('/api/groups', {'name': 'Original', 'humans': [], 'request_id': 'create', 'signed_policy': True})['id']
                    before = client.request('/api/group-policy?group_id='+group)
                self.assertEqual(client.request('/api/group-policy?group_id='+group), before)
                self.assertEqual(len(client.request('/api/groups')['groups']), 1)
                process.send_signal(signal.SIGINT)
                _, error = process.communicate(timeout=8)
                self.assertEqual(process.returncode, 0, error)
                self.assertNotIn('s'*32, line+error)
            finally:
                if process.poll() is None:
                    process.terminate(); process.communicate(timeout=8)
