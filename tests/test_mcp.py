import io
import json
import os
import subprocess
import sys
import unittest
from urllib.error import URLError
from tailnet_agents.mcp import Backend, Server, serve
from tailnet_agents.bridge import PROTOCOL


class FakeBackend:
    def call(self, name, args):
        if name == 'discover_agents':
            return {'agents': []}
        return {'id': 'a' * 32, 'status': 'queued'}


class MCPTests(unittest.TestCase):
    def ready(self, backend=None):
        server = Server(backend or FakeBackend())
        response = server.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                                  'params': {'protocolVersion': '2025-11-25',
                                             'capabilities': {}, 'clientInfo': {'name': 'test', 'version': '1'}}})
        self.assertEqual(response['result']['protocolVersion'], '2025-11-25')
        server.handle({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        return server

    def call(self, server, name, args):
        return server.handle({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                              'params': {'name': name, 'arguments': args}})

    def test_lifecycle_and_tool_schemas(self):
        server = Server(FakeBackend())
        self.assertIn('error', server.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}))
        server = self.ready()
        tools = server.handle({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'})['result']['tools']
        self.assertEqual([t['name'] for t in tools], ['discover_agents', 'delegate_task', 'get_task_result'])
        self.assertEqual(self.call(server, 'discover_agents', {})['result']['structuredContent'], {'agents': []})

    def test_reject_invalid_and_unknown_tool_arguments(self):
        server = self.ready()
        for name, args in [('unknown', {}), ('delegate_task', {}),
                           ('discover_agents', {'url': 'http://evil'}),
                           ('discover_agents', {'skill': 3}),
                           ('get_task_result', {'agent_id': 'a', 'task_id': '../secrets'})]:
            with self.subTest(name=name, args=args):
                self.assertEqual(self.call(server, name, args)['error']['code'], -32602)

    def test_network_errors_are_tool_errors_without_secrets(self):
        class Failure:
            def call(self, *_):
                raise URLError('secret-token')
        response = self.call(self.ready(Failure()), 'discover_agents', {})
        self.assertTrue(response['result']['isError'])
        self.assertNotIn('secret-token', json.dumps(response))

    def test_peer_origin_mismatch_cannot_redirect_delegation(self):
        class Registry:
            def request(self, _):
                return {'agents': [{'id': 'peer', 'protocol': PROTOCOL,
                                    'endpoint': 'https://peer.example.ts.net:9999'}]}
        backend = Backend(Registry(), {'peer': {'url': 'https://peer.example.ts.net', 'token': 'x'*32}})
        self.assertEqual(backend.discover(), [])
        response = self.call(self.ready(backend), 'delegate_task',
                             {'agent_id': 'peer', 'message': 'hello', 'idempotency_key': '1'})
        self.assertTrue(response['result']['isError'])

    def test_stdio_parse_errors_notifications_and_limits(self):
        output = io.StringIO()
        serve(Server(FakeBackend()), io.BytesIO(b'not-json\n{"jsonrpc":"2.0","method":"notifications/initialized"}\n{"jsonrpc":"2.0","id":3,"method":"ping"}\n'), output)
        responses = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(responses), 2)
        self.assertEqual(responses[0]['error']['code'], -32700)
        self.assertEqual(responses[1]['id'], 3)
        output = io.StringIO()
        serve(Server(FakeBackend()), io.BytesIO(b'x'*65537), output)
        self.assertEqual(json.loads(output.getvalue())['error']['code'], -32600)

    def test_real_stdio_process_has_clean_stdout_and_exits_at_eof(self):
        env = os.environ | {'TAILNET_REGISTRY_URL': 'http://127.0.0.1:1',
                            'TAILNET_REGISTRY_TOKEN': 'x'*32, 'TAILNET_MCP_PEERS': '{}'}
        requests = [ {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                      'params': {'protocolVersion': '2025-11-25', 'capabilities': {}, 'clientInfo': {}}},
                     {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
                     {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'} ]
        result = subprocess.run([sys.executable, '-m', 'tailnet_agents.mcp'],
                                input=''.join(json.dumps(r)+'\n' for r in requests),
                                text=True, capture_output=True, env=env, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        self.assertEqual(len([json.loads(line) for line in result.stdout.splitlines()]), 2)
