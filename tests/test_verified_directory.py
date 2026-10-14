import tempfile
import unittest
from pathlib import Path
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tailnet_agents.identity import AdmissionError,issue_grant,prove_possession,verify_grant
    from tailnet_agents.verified_directory import VerifiedDirectory,issue_revocation
    HAS_CRYPTO=True
except ImportError:
    HAS_CRYPTO=False


@unittest.skipUnless(HAS_CRYPTO,'install the identity extra')
class VerifiedDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.owner=Ed25519PrivateKey.generate()
        self.agent=Ed25519PrivateKey.generate()
        self.now=100
        self.grant=issue_grant(self.owner,self.agent.public_key(),'g',['join','discover'],now=100,lifetime=60)
        self.directory=VerifiedDirectory(self.owner.public_key(),'g','receiver',clock=lambda:self.now)
        self.record={'endpoint':'https://agent.example.ts.net','skills':['echo'],'ttl_seconds':300}

    def tearDown(self):
        self.directory.close()

    def join(self,directory=None,grant=None):
        directory=directory or self.directory
        grant=grant or self.grant
        challenge=directory.challenge(self.record)
        nonce=challenge['nonce']
        proof=prove_possession(self.agent,grant,nonce,'receiver',context=challenge['context'])
        return directory.register(grant,self.agent.public_key(),proof,nonce,self.record)

    def test_verified_registration_and_expiry_filter(self):
        accepted=self.join()
        self.assertEqual(accepted['ttl_seconds'],60)
        self.assertEqual(self.directory.discover('echo')[0]['id'],accepted['id'])
        self.now=160
        self.assertEqual(self.directory.discover(),[])
        with self.assertRaises(AdmissionError):
            self.join()

    def test_revocation_hides_live_record_and_denies_renewal(self):
        self.join()
        credential=verify_grant(self.grant,self.owner.public_key(),'g',now=100)['jti']
        revocation=issue_revocation(self.owner,'g',credential)
        self.directory.revoke(revocation)
        self.directory.revoke(revocation)
        self.assertEqual(self.directory.discover(),[])
        with self.assertRaises(AdmissionError):
            self.join()

    def test_wrong_authority_and_group_revocation_rejected(self):
        credential='a'*32
        for signed in (issue_revocation(Ed25519PrivateKey.generate(),'g',credential),
                       issue_revocation(self.owner,'other',credential)):
            with self.assertRaises(AdmissionError):
                self.directory.revoke(signed)

    def test_restart_retains_revocation_and_pinned_authority(self):
        with tempfile.TemporaryDirectory() as folder:
            path=str(Path(folder)/'verified.sqlite3')
            directory=VerifiedDirectory(self.owner.public_key(),'g','receiver',database=path,clock=lambda:self.now)
            accepted=self.join(directory)
            credential=verify_grant(self.grant,self.owner.public_key(),'g',now=100)['jti']
            directory.revoke(issue_revocation(self.owner,'g',credential))
            directory.close()
            directory=VerifiedDirectory(self.owner.public_key(),'g','receiver',database=path,clock=lambda:self.now)
            try:
                self.assertEqual(directory.discover(),[])
                with self.assertRaises(AdmissionError):self.join(directory)
                new=issue_grant(self.owner,self.agent.public_key(),'g',['join'],now=100)
                self.assertEqual(self.join(directory,new)['id'],accepted['id'])
            finally:directory.close()
            with self.assertRaises(AdmissionError):
                VerifiedDirectory(Ed25519PrivateKey.generate().public_key(),'g','receiver',database=path)

    def test_cannot_choose_someone_elses_id_or_replay_nonce(self):
        challenge=self.directory.challenge(self.record)
        nonce=challenge['nonce']
        proof=prove_possession(self.agent,self.grant,nonce,'receiver',context=challenge['context'])
        with self.assertRaises(AdmissionError):
            self.directory.register(self.grant,self.agent.public_key(),proof,nonce,self.record|{'id':'victim'})
        self.directory.register(self.grant,self.agent.public_key(),proof,nonce,self.record)
        with self.assertRaises(AdmissionError):
            self.directory.register(self.grant,self.agent.public_key(),proof,nonce,self.record)

    def test_registration_metadata_is_bound_to_proof(self):
        challenge=self.directory.challenge(self.record)
        proof=prove_possession(self.agent,self.grant,challenge['nonce'],'receiver',context=challenge['context'])
        with self.assertRaises(AdmissionError):
            self.directory.register(self.grant,self.agent.public_key(),proof,challenge['nonce'],self.record|{'endpoint':'https://attacker.example'})
        self.assertEqual(self.directory.discover(),[])
