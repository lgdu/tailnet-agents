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

    def open(self, require=True):
        return VerifiedDirectory(self.owner.public_key(), self.group, 'receiver', database=self.path,
                                 clock=lambda: 110, require_policy=require)

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

