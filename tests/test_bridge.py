import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from tailnet_agents.bridge import Lease, PROTOCOL, TaskConflict, TaskStore, task_handler
from tailnet_agents.client import Client, validate_url
from tailnet_agents.cli import select_peer
from tailnet_agents.registry import Registry, make_handler


class BridgeTests(unittest.TestCase):
    def test_tasks_are_idempotent_and_results_are_private(self):
        calls = []
        store = TaskStore(lambda msg: calls.append(msg) or msg, capacity=1)
        try:
            payload = {'message': 'hello', 'idempotency_key': 'request-1'}
            first = store.submit('alice', payload)
            again = store.submit('alice', payload)
            self.assertEqual(first['id'], again['id'])
            with self.assertRaises(TaskConflict):
                store.submit('alice', payload | {'message': 'different'})
            with self.assertRaises(KeyError):
                store.get('bob', first['id'])
            with self.assertRaises(OverflowError):
                store.submit('alice', payload | {'idempotency_key': 'request-2'})
        finally:
            store.close()
        self.assertEqual(calls, ['hello'])
        self.assertEqual(store.get('alice', first['id'])['status'], 'completed')

    def test_adapter_failure_does_not_disclose_exception(self):
        def fail(_):
            raise RuntimeError('secret')
        store = TaskStore(fail)
        task = store.submit('alice', {'message': 'test', 'idempotency_key': '1'})
        store.close()
        self.assertEqual(store.get('alice', task['id'])['error'], 'adapter failed')

    def test_transport_url_policy(self):
        for url in ('http://example.com', 'file:///tmp/test', 'https://user:password@example.com',
                    'https://example.com?token=secret'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_url(url)
        validate_url('http://127.0.0.1:1234')
        validate_url('https://agent.example.ts.net')

    def test_two_bridges_register_discover_and_exchange_tasks(self):
        registry = Registry({'node-a': 'a' * 32, 'node-b': 'b' * 32})
        servers, threads, stores, leases = [], [], [], []
        def serve(handler):
            server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            servers.append(server)
            threads.append(thread)
            return f'http://127.0.0.1:{server.server_port}'
        registry_url = serve(make_handler(registry))
        try:
            for name, token in [('a', 'a' * 32), ('b', 'b' * 32)]:
                store = TaskStore(lambda msg: 'Echo: ' + msg)
                stores.append(store)
                local_url = serve(task_handler({'caller': 'p' * 32, 'other': 'q' * 32}, store))
                # Production registration requires HTTPS. Tests map the advertised
                # HTTPS origin to its loopback HTTP server without TLS setup.
                record = {'id': name, 'endpoint': local_url.replace('http:', 'https:'),
                          'protocol': PROTOCOL, 'skills': ['echo'], 'ttl_seconds': 10}
                lease = Lease(Client(registry_url, token), record)
                leases.append(lease)
                lease.start()
            client = Client(registry_url, 'a' * 32)
            deadline = time.monotonic() + 3
            while len(client.request('/v1/agents')['agents']) != 2:
                if time.monotonic() > deadline:
                    self.fail('automatic registration did not finish')
                time.sleep(0.01)
            for agent_id in ['a', 'b']:
                with self.assertRaises(ValueError):
                    select_peer(client, agent_id, ['unexpected-host'])
                agent = select_peer(client, agent_id, ['127.0.0.1'])
                peer = Client(agent['endpoint'].replace('https:', 'http:'), 'p' * 32)
                payload = {'message': 'hello', 'idempotency_key': 'test-key'}
                task = peer.request('/v1/tasks', payload)
                self.assertEqual(peer.request('/v1/tasks', payload)['id'], task['id'])
                with self.assertRaises(HTTPError) as failure:
                    Client(peer.url, 'q' * 32).request('/v1/tasks/' + task['id'])
                self.assertEqual(failure.exception.code, 404)
                deadline = time.monotonic() + 3
                while task['status'] in ('queued', 'running'):
                    if time.monotonic() > deadline:
                        self.fail('task did not complete')
                    task = peer.request('/v1/tasks/' + task['id'])
                self.assertEqual(task['result'], 'Echo: hello')
        finally:
            for lease in leases:
                lease.close()
                self.assertFalse(lease.thread.is_alive())
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join()
            for store in stores:
                store.close()


if __name__ == '__main__':
    unittest.main()
