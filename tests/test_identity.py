import tempfile
import unittest
from pathlib import Path
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tailnet_agents.identity import Admission, AdmissionError, generate_identity, load_identity, identity_id, issue_grant, prove_possession, verify_grant
    HAS_CRYPTO=True
except ImportError:
    HAS_CRYPTO=False


@unittest.skipUnless(HAS_CRYPTO,'install the identity extra to run crypto tests')
class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.owner=Ed25519PrivateKey.generate()
        self.agent=Ed25519PrivateKey.generate()
        self.now=100
        self.grant=issue_grant(self.owner,self.agent.public_key(),'group',['join','discover'],now=100,lifetime=60)
        self.verifier=Admission(self.owner.public_key(),'group','verifier-a',clock=lambda:self.now)

    def test_valid_admission_and_single_use_proof(self):
        nonce=self.verifier.challenge()
        proof=prove_possession(self.agent,self.grant,nonce,'verifier-a')
        accepted=self.verifier.admit(self.grant,self.agent.public_key(),proof,nonce)
        self.assertEqual(accepted['sub'],identity_id(self.agent.public_key()))
        with self.assertRaises(AdmissionError):
            self.verifier.admit(self.grant,self.agent.public_key(),proof,nonce)

    def test_wrong_owner_group_permission_and_time(self):
        cases=[{'owner_key':Ed25519PrivateKey.generate().public_key()}, {'group_id':'other'},
               {'permission':'task.echo'},{'now':99},{'now':160}]
        for patch in cases:
            args={'owner_key':self.owner.public_key(),'group_id':'group','now':100}|patch
            with self.subTest(patch=patch),self.assertRaises(AdmissionError):
                verify_grant(self.grant,**args)

    def test_tampering_and_wrong_subject_rejected(self):
        parts=self.grant.split('.')
        tampered=parts[0]+'.'+parts[1][:-2]+'AA.'+parts[2]
        with self.assertRaises(AdmissionError):
            verify_grant(tampered,self.owner.public_key(),'group',now=100)
        nonce=self.verifier.challenge()
        other=Ed25519PrivateKey.generate()
        with self.assertRaises(AdmissionError):
            self.verifier.admit(self.grant,other.public_key(),prove_possession(other,self.grant,nonce,'verifier-a'),nonce)

    def test_proof_bound_to_grant_and_audience_and_challenge_expiry(self):
        nonce=self.verifier.challenge()
        with self.assertRaises(AdmissionError):
            self.verifier.admit(self.grant,self.agent.public_key(),prove_possession(self.agent,self.grant,nonce,'other'),nonce)
        other_grant=issue_grant(self.owner,self.agent.public_key(),'group',['join'],now=100)
        with self.assertRaises(AdmissionError):
            self.verifier.admit(self.grant,self.agent.public_key(),prove_possession(self.agent,other_grant,nonce,'verifier-a'),nonce)
        self.now=130
        with self.assertRaises(AdmissionError):
            self.verifier.admit(self.grant,self.agent.public_key(),prove_possession(self.agent,self.grant,nonce,'verifier-a'),nonce)

    def test_revoked_grant_rejected(self):
        claims=verify_grant(self.grant,self.owner.public_key(),'group',now=100)
        self.verifier.revoked.add(claims['jti'])
        nonce=self.verifier.challenge()
        with self.assertRaises(AdmissionError):
            self.verifier.admit(self.grant,self.agent.public_key(),prove_possession(self.agent,self.grant,nonce,'verifier-a'),nonce)

    def test_identity_survives_reload_and_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'agent.pem'
            key=generate_identity(path)
            self.assertEqual(identity_id(key.public_key()),identity_id(load_identity(path).public_key()))
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            with self.assertRaises(FileExistsError):
                generate_identity(path)
