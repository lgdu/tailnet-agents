import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request,urlopen
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tailnet_agents.admission_server import handler
    from tailnet_agents.identity import encode,public_bytes,issue_grant,prove_possession,verify_grant
    from tailnet_agents.verified_directory import VerifiedDirectory,issue_revocation
    from tailnet_agents.verified_client import VerifiedClient
    from tailnet_agents.client import Client
    from http.server import ThreadingHTTPServer
    HAS_CRYPTO=True
except ImportError:
    HAS_CRYPTO=False


@unittest.skipUnless(HAS_CRYPTO,'install identity extra')
class AdmissionHTTPTests(unittest.TestCase):
    def setUp(self):
        self.owner=Ed25519PrivateKey.generate()
        self.now=100
        self.directory=VerifiedDirectory(self.owner.public_key(),'group','receiver',clock=lambda:self.now)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),handler(self.directory,'r'*32))
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.url=f'http://127.0.0.1:{self.server.server_port}'
        self.reader=Client(self.url,'r'*32)
        self.joiner=Client(self.url,'not-a-read-token')

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.directory.close()

    def payload(self,key=None,group='group'):
        key=key or Ed25519PrivateKey.generate()
        record={'endpoint':'https://agent.example.ts.net','skills':['echo'],'ttl_seconds':30}
        grant=issue_grant(self.owner,key.public_key(),group,['join','discover'],now=100)
        challenge=self.joiner.request('/v1/challenges',{'record':record})
        proof=prove_possession(key,grant,challenge['nonce'],'receiver',context=challenge['context'])
        return {'record':record,'grant':grant,'public_key':encode(public_bytes(key.public_key())),
                'proof':proof,'nonce':challenge['nonce']}

    def test_two_agents_join_discover_and_signed_revoke_over_http(self):
        first=self.payload();second=self.payload()
        one=self.joiner.request('/v1/registrations',first)
        two=self.joiner.request('/v1/registrations',second)
        self.assertNotEqual(one['id'],two['id'])
        self.assertEqual(len(self.reader.request('/v1/agents?skill=echo')['agents']),2)
        credential=verify_grant(first['grant'],self.owner.public_key(),'group',now=100)['jti']
        signed=issue_revocation(self.owner,'group',credential)
        self.reader.request('/v1/revocations',{'revocation':signed})
        self.assertEqual([a['id'] for a in self.reader.request('/v1/agents')['agents']],[two['id']])

    def test_discovery_needs_read_token_and_revocation_needs_both_checks(self):
        with self.assertRaises(HTTPError) as error:self.joiner.request('/v1/agents')
        self.assertEqual(error.exception.code,403)
        with self.assertRaises(HTTPError) as error:self.joiner.request('/v1/revocations',{'revocation':'bad'})
        self.assertEqual(error.exception.code,403)
        with self.assertRaises(HTTPError) as error:self.reader.request('/v1/revocations',{'revocation':'bad'})
        self.assertEqual(error.exception.code,403)

    def test_wrong_group_metadata_tampering_and_replay_denied(self):
        with self.assertRaises(HTTPError) as error:self.joiner.request('/v1/registrations',self.payload(group='other'))
        self.assertEqual(error.exception.code,403)
        body=self.payload()
        with self.assertRaises(HTTPError) as error:self.joiner.request('/v1/registrations',body|{'record':body['record']|{'endpoint':'https://evil.example'}})
        self.assertEqual(error.exception.code,403)
        self.joiner.request('/v1/registrations',body)
        with self.assertRaises(HTTPError) as error:self.joiner.request('/v1/registrations',body)
        self.assertEqual(error.exception.code,403)

    def test_origin_and_body_limit(self):
        request=Request(self.url+'/v1/agents',headers={'Origin':'https://evil.example','Authorization':'Bearer '+'r'*32})
        with self.assertRaises(HTTPError) as error:urlopen(request)
        self.assertEqual(error.exception.code,403)
        with self.assertRaises(HTTPError) as error:self.joiner.request('/v1/challenges',{'record':'x'*65536})
        self.assertEqual(error.exception.code,413)

    def test_client_sdk_renews_same_identity_with_fresh_proof(self):
        key=Ed25519PrivateKey.generate()
        grant=issue_grant(self.owner,key.public_key(),'group',['join'],now=100)
        client=VerifiedClient(self.url,key,grant,'receiver',read_token='r'*32)
        record={'endpoint':'https://agent.example.ts.net','ttl_seconds':30}
        first=client.register(record)
        self.now=110
        second=client.register(record)
        self.assertEqual(first['id'],second['id'])
        self.assertEqual(len(client.discover()['agents']),1)
