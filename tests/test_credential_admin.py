import hashlib
import json
import subprocess
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
import test_policy_delivery as fixtures

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tailnet_agents.chat import ChatStore
    from tailnet_agents.identity import (encode, generate_identity, identity_id, load_identity,
                                        public_bytes, verify_grant)
    from tailnet_agents.credential_admin import FIELDS
    from tailnet_agents.grant_install import install_grant
    from tailnet_agents.verified_client import VerifiedClient
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@unittest.skipUnless(HAS_CRYPTO, 'install identity extra')
class CredentialAdminTests(unittest.TestCase):
    setUp = fixtures.PolicyDeliveryTests.setUp
    serve = fixtures.PolicyDeliveryTests.serve
    create = fixtures.PolicyDeliveryTests.create
    export = fixtures.PolicyDeliveryTests.export
    change = fixtures.PolicyDeliveryTests.change
    rejected = fixtures.PolicyDeliveryTests.rejected
    recipient = fixtures.PolicyDeliveryTests.recipient
    # Keep the existing delivery helpers independent of issuance consent.
    preview = fixtures.PolicyDeliveryTests.preview
    body = fixtures.PolicyDeliveryTests.body
    deliver = fixtures.PolicyDeliveryTests.deliver

    def grant_preview(self, group, key=None, **changes):
        exported = self.export(group)
        return self.clients['owner'].request('/api/credential-preview', {
            'group_id': group, 'public_key': encode(public_bytes((key or self.agent).public_key())),
            'permissions': ['join'], 'lifetime': 300, 'expected_revision': exported['claims']['revision'],
            'policy_hash': exported['policy_hash'], **changes})

    def grant_body(self, preview, request_id='issue'):
        return {name: preview[name] for name in FIELDS | {'issued_at', 'consent_hash', 'group_id'}} | {'request_id': request_id}

    def issue(self, group, request_id='issue', **options):
        return self.clients['owner'].request('/api/credential-issue', self.grant_body(self.grant_preview(group, **options), request_id))

    def history(self, group):
        return self.clients['owner'].request('/api/credential-issuances?group_id='+group)['issuances']

    def test_preview_and_history_do_not_issue_approve_or_contact_recipient(self):
        group, node, target = self.recipient()
        before = self.export(group)
        with patch.object(target.client, 'request') as contacted:
            preview = self.grant_preview(group, permissions=['discover', 'join'], lifetime=600)
            self.assertEqual(preview['subject'], self.subject)
            self.assertEqual(preview['expires_at'], 700)
            self.assertEqual(preview['preview_expires_at'], 160)
            self.assertEqual(self.history(group), [])
            contacted.assert_not_called()
        self.assertEqual(self.export(group), before)
        self.assertEqual(node.export_policy(), {'policy': None})

    def test_issue_binds_exact_existing_key_scope_and_preview_expiry(self):
        group = self.create()
        preview = self.grant_preview(group, permissions=['task.echo', 'join'], lifetime=120)
        self.now = 110
        result = self.clients['owner'].request('/api/credential-issue', self.grant_body(preview))
        claims = verify_grant(result['grant'], self.owner.public_key(), group, now=self.now)
        self.assertEqual(claims['sub'], self.subject)
        self.assertEqual(claims['permissions'], ['join', 'task.echo'])
        self.assertEqual((claims['iat'], claims['exp']), (100, 220))
        self.assertFalse(result['membership_changed'])
        self.assertEqual(self.export(group)['claims']['members'], {})
        self.assertEqual(self.export(group)['claims']['revision'], 1)

    def test_issuance_install_approval_delivery_and_possession_are_separate_for_two_agents(self):
        group, node, target = self.recipient()
        keys = [generate_identity(self.root/f'agent-{index}.pem') for index in range(2)]
        accepted = []
        for index, key in enumerate(keys):
            result = self.issue(group, f'issue-{index}', key=key)
            path = self.root/f'agent-{index}.grant'
            install_grant(result['grant'], key, self.owner.public_key(), group, path, now=self.now)
            client = VerifiedClient(target.url, key, path.read_text().strip(), 'directory')
            record = {'name': 'Same machine', 'endpoint': f'https://same-host.example:{8901+index}'}
            self.rejected(403, lambda: client.register(record))
            revision = self.export(group)['claims']['revision']
            self.change(group, 'approve', revision, request_id=f'approve-{index}', grant=result['grant'])
            self.rejected(403, lambda: client.register(record))
            self.deliver(group, f'deliver-{index}')
            self.assertEqual(len(node.discover()), index)
            accepted.append(client.register(record)['id'])
        self.assertEqual(len(set(accepted)), 2)
        self.assertEqual(len(node.discover()), 2)

    def test_identical_retry_reconstructs_same_credential_without_extending_expiry(self):
        group = self.create()
        body = self.grant_body(self.grant_preview(group))
        first = self.clients['owner'].request('/api/credential-issue', body)
        self.now = 180  # Preview expired; recovery of the existing issuance is still allowed.
        second = self.clients['owner'].request('/api/credential-issue', body)
        self.assertEqual(first, second)
        self.assertEqual(len(self.history(group)), 1)

    def test_changed_consent_cannot_reuse_request_id(self):
        group = self.create()
        self.issue(group)
        body = self.grant_body(self.grant_preview(group, lifetime=600))
        self.rejected(409, lambda: self.clients['owner'].request('/api/credential-issue', body))
        self.assertEqual(len(self.history(group)), 1)

    def test_consent_hash_rejects_changed_scope_key_or_timestamps(self):
        group = self.create()
        body = self.grant_body(self.grant_preview(group))
        for change in ({'lifetime': 600}, {'permissions': ['join', 'task.echo']}, {'issued_at': 99},
                       {'public_key': encode(public_bytes(Ed25519PrivateKey.generate().public_key()))}, {'consent_hash': '0'*64}):
            self.rejected(409, lambda: self.clients['owner'].request('/api/credential-issue', body | change))
        self.assertEqual(self.history(group), [])

    def test_invalid_keys_permissions_lifetime_and_schema_fail_before_issuance(self):
        group = self.create()
        invalid = [{'public_key': 'bad'}, {'public_key': []}, {'public_key': '-----BEGIN PRIVATE KEY-----'},
                   {'permissions': []}, {'permissions': ['discover']}, {'permissions': ['join', 'join']},
                   {'permissions': ['join', 'admin']}, {'permissions': ['join', {}]},
                   {'lifetime': True}, {'lifetime': 0}, {'lifetime': 86401}, {'lifetime': 1.5},
                   {'expected_revision': True}, {'policy_hash': 'bad'}, {'url': 'https://unconfigured.example'}]
        for change in invalid:
            self.rejected(400, lambda: self.grant_preview(group, **change))
        self.assertEqual(self.history(group), [])

    def test_owner_authority_key_cannot_be_provisioned_as_an_agent(self):
        group = self.create()
        self.rejected(400, lambda: self.grant_preview(group, key=self.owner))

    def test_policy_changes_require_new_preview_but_recovery_keeps_original_grant(self):
        group = self.create()
        body = self.grant_body(self.grant_preview(group))
        self.change(group, 'renew', 1)
        self.rejected(409, lambda: self.clients['owner'].request('/api/credential-issue', body))
        result = self.issue(group)
        recovery = self.history(group)[0]['request'] | {'group_id': group}
        self.change(group, 'approve', 2, request_id='approve', grant=result['grant'])
        self.assertEqual(self.clients['owner'].request('/api/credential-issue', recovery), result)

    def test_expired_or_future_preview_cannot_create_credential(self):
        group = self.create()
        body = self.grant_body(self.grant_preview(group))
        for now in (99, 160, 400):
            self.now = now
            self.rejected(409, lambda: self.clients['owner'].request('/api/credential-issue', body))
        self.assertEqual(self.history(group), [])

    def test_short_lifetime_cannot_be_extended_by_delayed_confirmation(self):
        group = self.create()
        body = self.grant_body(self.grant_preview(group, lifetime=1))
        self.now = 101
        self.rejected(409, lambda: self.clients['owner'].request('/api/credential-issue', body))

    def test_expired_credential_retry_fails_without_issuing_replacement(self):
        group = self.create()
        self.issue(group, lifetime=10)
        recovery = self.history(group)[0]['request'] | {'group_id': group}
        self.now = 110
        self.rejected(400, lambda: self.clients['owner'].request('/api/credential-issue', recovery))
        self.assertEqual(self.history(group)[0]['state'], 'expired')
        self.assertEqual(len(self.history(group)), 1)

    def test_removed_credential_cannot_be_retrieved_or_reapproved(self):
        group = self.create()
        issued = self.issue(group)
        recovery = self.history(group)[0]['request'] | {'group_id': group}
        self.change(group, 'approve', 1, request_id='approve', grant=issued['grant'])
        self.change(group, 'remove', 2, request_id='remove', subject=self.subject)
        self.rejected(403, lambda: self.clients['owner'].request('/api/credential-issue', recovery))
        self.assertEqual(self.history(group)[0]['state'], 'retired')
        fresh = self.issue(group, 'new-credential')
        self.assertNotEqual(fresh['claims']['jti'], issued['claims']['jti'])
        self.assertEqual(self.export(group)['claims']['members'], {})

    def test_roles_and_group_creator_checks_apply_to_all_issuance_routes(self):
        group = self.create()
        body = self.grant_body(self.grant_preview(group))
        for human in ('other', 'participant', 'observer'):
            for route in ('/api/credential-preview', '/api/credential-issue'):
                self.rejected(403, lambda: self.clients[human].request(route, body))
            self.rejected(403, lambda: self.clients[human].request('/api/credential-issuances?group_id='+group))
        self.assertEqual(self.history(group), [])

    def test_dissolution_blocks_new_issuance_and_retrieval_but_preserves_history(self):
        group = self.create()
        self.issue(group)
        body = self.history(group)[0]['request'] | {'group_id': group}
        self.store.dissolve_group('owner', group, 'Human approved')
        self.rejected(403, lambda: self.clients['owner'].request('/api/credential-issue', body))
        self.rejected(403, lambda: self.grant_preview(group))
        self.assertEqual(len(self.history(group)), 1)

    def test_local_only_group_cannot_issue_or_be_converted(self):
        group = self.create(signed_policy=False)
        body = {'group_id': group, 'public_key': encode(public_bytes(self.agent.public_key())),
                'permissions': ['join'], 'lifetime': 300, 'expected_revision': 1, 'policy_hash': 'a'*64}
        self.rejected(400, lambda: self.clients['owner'].request('/api/credential-preview', body))
        self.assertEqual(self.history(group), [])

    def test_cross_group_consent_cannot_issue_for_another_group(self):
        group, other = self.create(), self.create('Other', 'other')
        body = self.grant_body(self.grant_preview(group)) | {'group_id': other}
        self.rejected(409, lambda: self.clients['owner'].request('/api/credential-issue', body))
        self.assertEqual(self.history(other), [])

    def test_history_and_database_never_store_raw_credential_or_private_key(self):
        group = self.create()
        issued = self.issue(group)
        metadata = json.dumps(self.history(group))
        database = '\n'.join(self.store.db.iterdump())
        self.assertNotIn(issued['grant'], metadata+database)
        self.assertNotIn('PRIVATE KEY', metadata+database)
        self.assertEqual(self.history(group)[0]['grant_hash'], hashlib.sha256(issued['grant'].encode()).hexdigest())

    def test_restart_recovers_same_issuance_only_on_explicit_request(self):
        group = self.create()
        issued = self.issue(group)
        body = self.history(group)[0]['request']
        self.store.close()
        with patch('tailnet_agents.credential_admin.sign') as signer:
            restored = ChatStore(self.database, policy_authority=self.authority)
            self.addCleanup(restored.close)
            signer.assert_not_called()
        self.assertEqual(restored.credential_issue('owner', group, body), issued)
        self.assertEqual(restored.groups('owner')[0]['id'], group)

    def test_signature_failure_rolls_back_issuance_and_keeps_policy_unchanged(self):
        group = self.create()
        before = self.export(group)
        for target in ('issue_grant', 'sign'):
            with patch('tailnet_agents.credential_admin.'+target, side_effect=ValueError('signing failed')):
                self.rejected(400, lambda: self.issue(group))
            self.assertEqual(self.history(group), [])
        self.assertEqual(self.export(group), before)

    def test_concurrent_identical_requests_commit_one_credential(self):
        group = self.create()
        body = self.grant_body(self.grant_preview(group))
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.clients['owner'].request('/api/credential-issue', body), range(4)))
        self.assertTrue(all(result == results[0] for result in results))
        self.assertEqual(len(self.history(group)), 1)

    def test_changed_stored_claims_cannot_be_resigned_as_another_scope(self):
        group = self.create()
        issued = self.issue(group)
        body = self.history(group)[0]['request'] | {'group_id': group}
        with self.store.db:
            self.store.db.execute('UPDATE ui_grant_issuances SET claims=?', (json.dumps(issued['claims'] | {'permissions': ['join', 'task.echo']}),))
        self.rejected(400, lambda: self.clients['owner'].request('/api/credential-issue', body))

    def test_installer_writes_private_new_file_and_never_overwrites(self):
        group = self.create()
        issued = self.issue(group)
        path = self.root/'agent-state'/'grant.jwt'
        result = install_grant(issued['grant'], self.agent, self.owner.public_key(), group, path, now=self.now)
        self.assertEqual(result['subject'], self.subject)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.read_text().strip(), issued['grant'])
        with self.assertRaises(FileExistsError):
            install_grant(issued['grant'], self.agent, self.owner.public_key(), group, path, now=self.now)
        self.assertEqual(path.read_text().strip(), issued['grant'])

    def test_installer_rejects_wrong_subject_owner_group_and_expiry_before_writing(self):
        group = self.create()
        issued = self.issue(group)
        other = Ed25519PrivateKey.generate()
        for key, owner, target, now in [(other, self.owner.public_key(), group, 100),
                                       (self.agent, other.public_key(), group, 100),
                                       (self.agent, self.owner.public_key(), 'foreign', 100),
                                       (self.agent, self.owner.public_key(), group, 400)]:
            path = self.root/'not-created'/'grant.jwt'
            with self.assertRaises(ValueError): install_grant(issued['grant'], key, owner, target, path, now=now)
            self.assertFalse(path.parent.exists())

    def test_installer_rejects_symlinks_and_removes_failed_partial_file(self):
        group = self.create()
        issued = self.issue(group)
        original, path = self.root/'original', self.root/'grant.jwt'
        original.write_text('keep')
        path.symlink_to(original)
        with self.assertRaises(FileExistsError):
            install_grant(issued['grant'], self.agent, self.owner.public_key(), group, path, now=self.now)
        self.assertEqual(original.read_text(), 'keep')
        path.unlink()
        with patch('tailnet_agents.grant_install.os.fsync', side_effect=OSError('disk failure')), self.assertRaises(OSError):
            install_grant(issued['grant'], self.agent, self.owner.public_key(), group, path, now=self.now)
        self.assertFalse(path.exists())

    def test_real_installer_cli_reads_stdin_validates_key_and_does_not_print_grant(self):
        self.now = int(time.time())
        group = self.create()
        key_path = self.root/'recipient.pem'
        key = generate_identity(key_path)
        issued = self.issue(group, key=key)
        output = self.root/'installed.jwt'
        command = [sys.executable, '-m', 'tailnet_agents.grant_install', '--agent-key', str(key_path),
                   '--authority-public-key', str(self.pin_path), '--group-id', group, '--output', str(output)]
        accepted = subprocess.run(command, input=issued['grant'], text=True, capture_output=True, timeout=10)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(json.loads(accepted.stdout)['subject'], identity_id(load_identity(key_path).public_key()))
        self.assertNotIn(issued['grant'], accepted.stdout+accepted.stderr)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        for data in (issued['grant'], '', 'x'*16385, '\u00e9'):
            failed = subprocess.run(command, input=data, text=True, capture_output=True, timeout=10)
            self.assertNotEqual(failed.returncode, 0)
            self.assertNotIn(issued['grant'], failed.stdout+failed.stderr)
        self.assertEqual(output.read_text().strip(), issued['grant'])
