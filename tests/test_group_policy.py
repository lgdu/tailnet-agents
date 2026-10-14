import tempfile
from contextlib import closing
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from http.server import ThreadingHTTPServer
    from tailnet_agents.identity import AdmissionError, identity_id, issue_grant, verify_grant, prove_possession, sign, verify
    from tailnet_agents.group_policy import POLICY_TYPE, create_policy, revise_policy
    from tailnet_agents.verified_directory import VerifiedDirectory
    from tailnet_agents.admission_server import handler
    from tailnet_agents.client import Client
    from tailnet_agents.verified_client import VerifiedClient
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@unittest.skipUnless(HAS_CRYPTO, 'install the identity extra')
class GroupPolicyTests(unittest.TestCase):
    def setUp(self):
        self.now = 110
        self.folder = tempfile.TemporaryDirectory()
        self.path = str(Path(self.folder.name) / 'directory.sqlite3')
        self.owner = Ed25519PrivateKey.generate()
        self.agent = Ed25519PrivateKey.generate()
        self.subject = identity_id(self.agent.public_key())
        self.policy = create_policy(self.owner, 'Human created', {}, now=100)
        self.claims = verify(self.policy, self.owner.public_key(), POLICY_TYPE)
        self.group = self.claims['group_id']
        self.grant = issue_grant(self.owner, self.agent.public_key(), self.group, ['join', 'discover'], now=100)
        claims = verify_grant(self.grant, self.owner.public_key(), self.group, now=100)
        self.members = {self.subject: {'permissions': ['join', 'discover'], 'grant_ids': [claims['jti']]}}
        self.allowed = revise_policy(self.owner, self.policy, self.members, now=101)
        self.directory = self.open()
        self.record = {'endpoint': 'https://agent.example', 'ttl_seconds': 60}

    def open(self, require=True, max_age=None):
        return VerifiedDirectory(self.owner.public_key(), self.group, 'receiver', database=self.path,
                                 clock=lambda: self.now, require_policy=require, policy_max_age=max_age)

    def tearDown(self):
        self.directory.close()
        self.folder.cleanup()

    def join(self, grant=None):
        grant = grant or self.grant
        challenge = self.directory.challenge(self.record)
        proof = prove_possession(self.agent, grant, challenge['nonce'], 'receiver', context=challenge['context'])
        return self.directory.register(grant, self.agent.public_key(), proof, challenge['nonce'], self.record)

    def test_missing_policy_and_unapproved_member_fail_closed(self):
        with self.assertRaises(AdmissionError): self.join()
        self.directory.apply_policy(self.policy)
        with self.assertRaises(AdmissionError): self.join()
        self.directory.apply_policy(self.allowed)
        self.assertEqual(len(self.directory.discover()), 0)
        self.join()
        self.assertEqual(len(self.directory.discover()), 1)

    def test_removal_blocks_live_record_and_all_old_grants_after_readdition(self):
        self.directory.apply_policy(self.allowed)
        self.join()
        removed = revise_policy(self.owner, self.allowed, {}, now=102)
        self.directory.apply_policy(removed)
        self.assertEqual(self.directory.discover(), [])
        with self.assertRaises(AdmissionError): self.join()
        new = issue_grant(self.owner, self.agent.public_key(), self.group, ['join'], now=100)
        jti = verify_grant(new, self.owner.public_key(), self.group, now=110)['jti']
        self.directory.apply_policy(revise_policy(self.owner, removed,
            {self.subject: {'permissions': ['join'], 'grant_ids': [jti]}}, now=103))
        with self.assertRaises(AdmissionError): self.join()
        self.join(new)

    def test_permissions_do_not_expand_just_because_grant_is_signed(self):
        self.directory.apply_policy(self.allowed)
        reduced = {self.subject: self.members[self.subject] | {'permissions': ['join']}}
        self.directory.apply_policy(revise_policy(self.owner, self.allowed, reduced, now=102))
        with self.assertRaises(AdmissionError): self.join()

    def test_stale_conflicting_foreign_and_malformed_snapshots_rejected(self):
        self.directory.apply_policy(self.allowed)
        conflict = sign(self.owner, verify(self.allowed, self.owner.public_key(), POLICY_TYPE) | {'members': {}}, POLICY_TYPE)
        foreign = create_policy(Ed25519PrivateKey.generate(), 'Foreign', {}, now=100)
        wrong_group = create_policy(self.owner, 'Another group', {}, now=100)
        malformed = sign(self.owner, self.claims | {'revision': True}, POLICY_TYPE)
        wrong_type = sign(self.owner, self.claims, 'tailnet-agent-grant+jwt')
        for token in [self.policy, conflict, foreign, wrong_group, malformed, wrong_type]:
            with self.subTest(token=token[:20]), self.assertRaises(AdmissionError): self.directory.apply_policy(token)
        self.directory.apply_policy(self.allowed)  # duplicate delivery is harmless
        self.join()

    def test_restart_retains_policy_and_forbids_enforcement_downgrade(self):
        self.directory.apply_policy(self.allowed)
        accepted = self.join()
        self.directory.close()
        with self.assertRaises(AdmissionError): self.open(False)
        self.directory = self.open()
        self.assertEqual(self.directory.discover(), [])  # leases need fresh possession proof
        self.assertEqual(self.join()['id'], accepted['id'])

    def test_dissolution_is_terminal_even_against_newer_owner_signed_snapshot(self):
        self.directory.apply_policy(self.allowed)
        self.join()
        dissolved = revise_policy(self.owner, self.allowed, {}, dissolve=True, now=102)
        self.directory.apply_policy(dissolved)
        self.directory.apply_policy(dissolved)
        self.assertEqual(self.directory.discover(), [])
        self.directory.close()
        self.directory = self.open()
        resurrection = sign(self.owner, self.claims | {'revision': 100, 'issued_at': 200}, POLICY_TYPE)
        with self.assertRaises(AdmissionError): self.directory.apply_policy(resurrection)
        with self.assertRaises(AdmissionError): self.join()
        with self.assertRaises(AdmissionError): revise_policy(self.owner, dissolved, self.members, now=103)

    def test_disabled_policy_mode_rejects_updates(self):
        self.directory.close()
        with closing(VerifiedDirectory(self.owner.public_key(), self.group, 'receiver')) as disabled:
            with self.assertRaises(AdmissionError): disabled.apply_policy(self.allowed)
        self.directory = self.open()

    def test_bad_members_and_time_rollback_rejected(self):
        for members in [{self.subject: {'permissions': ['join'], 'grant_ids': []}},
                        {self.subject: {'permissions': ['join', 'admin'], 'grant_ids': ['a'*32]}},
                        {'not-an-identity': self.members[self.subject]}]:
            with self.assertRaises(AdmissionError): create_policy(self.owner, 'Group', members, now=100)
        with self.assertRaises(AdmissionError): revise_policy(self.owner, self.allowed, {}, now=100)

    def test_policy_expiry_caps_leases_and_replay_does_not_refresh_authorization(self):
        self.directory.apply_policy(self.allowed)
        self.join()
        self.now = 390
        self.directory.apply_policy(self.allowed)
        self.assertEqual(self.join()['ttl_seconds'], 11)
        self.assertEqual(self.directory.policy_status()['expires_at'], 401)
        self.now = 392
        with self.assertRaises(AdmissionError): self.join()  # less than a minimum lease remains
        self.now = 401
        self.assertEqual(self.directory.policy_status()['state'], 'stale')
        self.assertEqual(self.directory.discover(), [])
        with self.assertRaises(AdmissionError): self.join()
        self.directory.apply_policy(self.allowed)
        self.assertEqual(self.directory.policy_status()['state'], 'stale')

    def test_fresh_owner_revision_recovers_same_identity_and_group_after_expired_restart(self):
        self.directory.apply_policy(self.allowed)
        original = self.join()['id']
        self.directory.close()
        self.now = 401
        self.directory = self.open()
        self.assertEqual(self.directory.policy_status()['state'], 'stale')
        self.assertEqual(self.directory.export_policy(), {'policy': self.allowed})
        with self.assertRaises(AdmissionError): self.join()
        refreshed = revise_policy(self.owner, self.allowed, self.members, now=self.now)
        self.directory.apply_policy(refreshed)
        self.assertEqual(self.join()['id'], original)
        self.assertEqual(self.directory.group_id, self.group)

    def test_future_policy_cannot_extend_freshness_and_clock_rollback_fails_closed(self):
        self.directory.apply_policy(self.allowed)
        self.join()
        future = revise_policy(self.owner, self.allowed, self.members, now=self.now + 31)
        with self.assertRaises(AdmissionError): self.directory.apply_policy(future)
        self.assertEqual(self.directory.export_policy(), {'policy': self.allowed})
        self.now = 70
        self.assertEqual(self.directory.policy_status()['state'], 'future')
        self.assertEqual(self.directory.discover(), [])
        with self.assertRaises(AdmissionError): self.join()

    def test_freshness_limit_persists_and_cannot_be_weakened(self):
        self.directory.apply_policy(self.allowed)
        self.directory.close()
        self.directory = self.open(max_age=30)
        self.assertEqual(self.directory.policy_status()['expires_at'], 131)
        self.directory.close()
        with self.assertRaises(AdmissionError): self.open(max_age=31)
        self.directory = self.open()
        self.assertEqual(self.directory.policy_max_age, 30)
        self.now = 131
        with self.assertRaises(AdmissionError): self.join()

    def test_invalid_freshness_limits_cannot_disable_enforcement(self):
        for age in (0, -1, 86401, True, 3.5, float('inf'), float('nan'), '300'):
            with self.subTest(age=age), self.assertRaises(ValueError): self.open(max_age=age)
        with self.assertRaises(AdmissionError):
            VerifiedDirectory(self.owner.public_key(), self.group, 'receiver', policy_max_age=300)

    def test_v017_database_upgrade_enforces_default_age_without_resetting_group(self):
        self.directory.apply_policy(self.allowed)
        self.directory._registry.db.execute('DROP TABLE admission_policy_freshness')
        self.directory._registry.db.commit()
        self.directory.close()
        self.now = 401
        self.directory = self.open()
        self.assertEqual(self.directory.policy_max_age, 300)
        self.assertEqual(self.directory.policy_status()['state'], 'stale')
        self.assertEqual(self.directory.group_id, self.group)
        self.assertEqual(self.directory.export_policy(), {'policy': self.allowed})
        with self.assertRaises(AdmissionError): self.join()

    def test_old_dissolution_remains_terminal_after_freshness_deadline(self):
        dissolved = revise_policy(self.owner, self.allowed, {}, dissolve=True, now=102)
        self.directory.apply_policy(dissolved)
        self.now = 1000
        self.directory.apply_policy(dissolved)
        self.assertEqual(self.directory.policy_status()['state'], 'dissolved')
        resurrection = revise_policy(self.owner, self.allowed, self.members, now=self.now)
        resurrection = sign(self.owner, verify(resurrection, self.owner.public_key(), POLICY_TYPE) | {'revision': 4}, POLICY_TYPE)
        with self.assertRaises(AdmissionError): self.directory.apply_policy(resurrection)
        with self.assertRaises(AdmissionError): self.join()

    def test_http_status_exposes_expiry_even_without_background_sync(self):
        self.directory.apply_policy(self.allowed)
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler(self.directory, 'r'*32))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client = Client(f'http://127.0.0.1:{server.server_port}', 'r'*32)
        try:
            status = client.request('/v1/policy-sync')
            self.assertEqual(status['state'], 'disabled')
            self.assertEqual(status['policy']['state'], 'fresh')
            self.now = 401
            self.assertEqual(client.request('/v1/policy-sync')['policy']['state'], 'stale')
            with self.assertRaises(HTTPError) as error:
                VerifiedClient(client.url, self.agent, self.grant, 'receiver').register(self.record)
            self.assertEqual(error.exception.code, 403)
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_http_policy_updates_require_reader_and_owner_signature(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler(self.directory, 'r'*32))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f'http://127.0.0.1:{server.server_port}'
        try:
            reader, stranger = Client(url, 'r'*32), Client(url, 'wrong')
            with self.assertRaises(HTTPError) as error: stranger.request('/v1/policies', {'policy': self.allowed})
            self.assertEqual(error.exception.code, 403)
            with self.assertRaises(HTTPError) as error: reader.request('/v1/policies', {'policy': 'invalid'})
            self.assertEqual(error.exception.code, 403)
            self.assertEqual(reader.request('/v1/policies', {'policy': self.allowed})['revision'], 2)
            agent_client = VerifiedClient(url, self.agent, self.grant, 'receiver')
            agent_client.register(self.record)
            self.assertEqual(len(reader.request('/v1/agents')['agents']), 1)
            removed = revise_policy(self.owner, self.allowed, {}, now=102)
            reader.request('/v1/policies', {'policy': removed})
            self.assertEqual(reader.request('/v1/agents')['agents'], [])
            with self.assertRaises(HTTPError) as error: agent_client.register(self.record)
            self.assertEqual(error.exception.code, 403)
        finally:
            server.shutdown(); server.server_close(); thread.join()

