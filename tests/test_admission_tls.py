from datetime import datetime,timedelta,timezone
import ipaddress
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import URLError,HTTPError
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa,ed25519
    from tailnet_agents.admission_server import AdmissionHTTPServer,handler,transport_config
    from tailnet_agents.verified_directory import VerifiedDirectory
    from tailnet_agents.verified_client import VerifiedClient
    from tailnet_agents.identity import issue_grant
    from tailnet_agents.client import Client
    HAS_CRYPTO=True
except ImportError:
    HAS_CRYPTO=False


def certificates(folder):
    now=datetime.now(timezone.utc)
    authority=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Test CA')])
    ca=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(authority.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .add_extension(x509.KeyUsage(True,False,False,False,False,True,True,None,None),critical=True)
        .sign(authority,hashes.SHA256()))
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    leaf=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]))
          .issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
          .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False)
          .sign(authority,hashes.SHA256()))
    paths={label:str(Path(folder)/(label+'.pem')) for label in ('ca','cert','key')}
    Path(paths['ca']).write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    Path(paths['cert']).write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    Path(paths['key']).write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    Path(paths['key']).chmod(0o600)
    return paths


@unittest.skipUnless(HAS_CRYPTO,'install identity extra')
class AdmissionTLSTests(unittest.TestCase):
    def test_trusted_tls_admission_and_untrusted_ca_or_hostname_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            paths=certificates(folder)
            allowed,context=transport_config('127.0.0.1',paths['cert'],paths['key'],['localhost','127.0.0.1'])
            owner=ed25519.Ed25519PrivateKey.generate();agent=ed25519.Ed25519PrivateKey.generate()
            directory=VerifiedDirectory(owner.public_key(),'g','receiver')
            server=AdmissionHTTPServer(('127.0.0.1',0),handler(directory,'r'*32,allowed,'https'),context)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            url=f'https://localhost:{server.server_port}'
            try:
                grant=issue_grant(owner,agent.public_key(),'g',['join'])
                client=VerifiedClient(url,agent,grant,'receiver',read_token='r'*32,ca_file=paths['ca'])
                result=client.register({'endpoint':'https://agent.example','skills':['echo']})
                self.assertEqual(client.discover()['agents'][0]['id'],result['id'])
                with self.assertRaises(URLError):Client(url,'r'*32).request('/v1/agents')
                with self.assertRaises(URLError):Client(f'https://127.0.0.1:{server.server_port}','r'*32,ca_file=paths['ca']).request('/v1/agents')
            finally:
                server.shutdown();server.server_close();thread.join();directory.close()

    def test_nonloopback_plaintext_and_missing_allowed_hosts_fail_closed(self):
        for options in ({'host':'0.0.0.0'}, {'host':'192.168.1.2'}, {'host':'127.0.0.1','cert_file':'only-cert'},
                        {'host':'127.0.0.1','allowed_hosts':['*.example']}):
            with self.subTest(options=options),self.assertRaises(ValueError):transport_config(**options)
