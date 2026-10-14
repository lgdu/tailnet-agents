import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from tailnet_agents.client import Client
from tailnet_agents.registry import Registry, make_handler
from tailnet_agents.bridge import Lease


class PersistenceTests(unittest.TestCase):
    record = {'id': 'worker', 'endpoint': 'https://worker.example.ts.net', 'skills': ['echo'], 'ttl_seconds': 10}

    def test_restart_preserves_owner_but_requires_fresh_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'registry.sqlite3')
            registry = Registry({'a': 'a'*32}, database=path)
            registry.register('a', self.record)
            registry.close()
            registry = Registry({'a': 'new-token', 'b': 'b'*32}, database=path)
            try:
                self.assertEqual(registry.discover(), [])
                with self.assertRaises(PermissionError):
                    registry.register('b', self.record)
                registry.register('a', self.record)
                self.assertEqual(registry.discover()[0]['id'], 'worker')
                if os.name == 'posix':
                    self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            finally:
                registry.close()

    def test_owner_can_remove_and_release_id(self):
        registry = Registry({})
        try:
            registry.register('a', self.record)
            with self.assertRaises(KeyError):
                registry.deregister('b', 'worker')
            registry.deregister('a', 'worker')
            self.assertEqual(registry.discover(), [])
            registry.register('b', self.record)
        finally:
            registry.close()

    def test_lease_can_renew_against_restarted_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'registry.sqlite3')
            registry = Registry({'a': 'a'*32}, database=path)
            registry.register('a', self.record)
            registry.close()
            registry = Registry({'a': 'a'*32, 'b': 'b'*32}, database=path)
            server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(registry))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            client = Client(f'http://127.0.0.1:{server.server_port}', 'a'*32)
            try:
                self.assertEqual(client.request('/v1/agents')['agents'], [])
                self.assertEqual(client.request('/v1/status'), {'registered': 1, 'online': 0, 'stale': 1})
                lease = Lease(client, self.record)
                lease.renew()
                self.assertEqual(len(client.request('/v1/agents')['agents']), 1)
                self.assertEqual(client.request('/v1/status')['online'], 1)
                with self.assertRaises(HTTPError) as failure:
                    Client(client.url, 'b'*32).request('/v1/agents/worker', method='DELETE')
                self.assertEqual(failure.exception.code, 404)
                self.assertTrue(client.request('/v1/agents/worker', method='DELETE')['removed'])
                self.assertEqual(client.request('/v1/agents')['agents'], [])
            finally:
                server.shutdown()
                server.server_close()
                thread.join()
                registry.close()
