import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

try:
    from tailnet_agents.policy_sync import load_policy_sources, PolicySynchronizer
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@unittest.skipUnless(HAS_CRYPTO, 'install identity extra')
class PolicySourceConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / 'sources.json'

    def load(self, entries):
        self.path.write_text(json.dumps(entries))
        return load_policy_sources(self.path)

    def test_lan_and_tailnet_sources_use_separate_environment_credentials(self):
        entries = [{'url': 'https://lan.example:8771', 'token_env': 'TEST_LAN_TOKEN'},
                   {'url': 'https://node.example.ts.net:8771', 'token_env': 'TEST_TAILNET_TOKEN'}]
        with patch.dict(os.environ, TEST_LAN_TOKEN='l'*32, TEST_TAILNET_TOKEN='t'*32):
            clients = self.load(entries)
        self.assertEqual([client.url for client in clients], [entry['url'] for entry in entries])
        self.assertEqual([client.token for client in clients], ['l'*32, 't'*32])
        self.assertNotIn('l'*32, self.path.read_text())
        self.assertNotIn('t'*32, self.path.read_text())

    def test_bad_missing_or_inline_credentials_and_unsafe_urls_are_rejected(self):
        valid = {'url': 'http://127.0.0.1:8771', 'token_env': 'TEST_SOURCE_TOKEN'}
        cases = [[], {}, [valid] * 9, [valid, valid | {'url': valid['url'] + '/'}],
                 [valid | {'token': 'x'*32}], [valid | {'token_env': 'missing-invalid-name'}],
                 [valid | {'url': 'http://192.168.1.2:8771'}],
                 [valid | {'url': 'https://username:password@host.example'}],
                 [valid | {'ca_cert': ''}], [valid | {'ca_cert': 1}], [None]]
        with patch.dict(os.environ, TEST_SOURCE_TOKEN='s'*32):
            for entries in cases:
                with self.subTest(entries=entries), self.assertRaises(ValueError): self.load(entries)
        with patch.dict(os.environ, TEST_SOURCE_TOKEN='short'):
            with self.assertRaises(ValueError): self.load([valid])
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError): self.load([valid])

    def test_source_count_is_bounded_for_in_process_callers_too(self):
        class Directory:
            require_policy = True
        with self.assertRaises(ValueError):
            PolicySynchronizer(Directory(), object(), fallback_clients=[object()] * 8)

    def test_private_ca_path_is_relative_to_source_configuration(self):
        from tests.test_admission_tls import certificates
        certificates(self.folder.name)
        with patch.dict(os.environ, TEST_SOURCE_TOKEN='s'*32):
            clients = self.load([{'url': 'https://localhost:8771', 'token_env': 'TEST_SOURCE_TOKEN', 'ca_cert': 'ca.pem'}])
        self.assertEqual(clients[0].url, 'https://localhost:8771')
