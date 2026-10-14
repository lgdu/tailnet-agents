import tempfile
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from tailnet_agents.chat import ChatStore
from tailnet_agents.client import Client
from tailnet_agents.ui import handler


class ChatTests(unittest.TestCase):
    def setUp(self):
        self.store = ChatStore()

    def tearDown(self):
        self.store.close()

    def send(self, **kwargs):
        return self.store.send({'conversation': 'group', 'text': 'hello', 'request_id': '1', **kwargs})

    def test_group_default_and_explicit_recipients_do_not_loop(self):
        self.send()
        self.assertEqual([m['sender'] for m in self.store.history('group')], ['human', 'moderator'])
        self.send(request_id='2', targets=['coder', 'researcher'])
        self.assertEqual([m['sender'] for m in self.store.history('group')][-3:], ['human', 'coder', 'researcher'])

    def test_private_conversations_are_separate_and_target_cannot_be_overridden(self):
        self.send(conversation='dm:coder', targets=['researcher'])
        self.assertEqual(self.store.history('group'), [])
        self.assertEqual(self.store.history('dm:researcher'), [])
        self.assertEqual([m['sender'] for m in self.store.history('dm:coder')], ['human', 'coder'])

    def test_durable_deduplication_and_history_after_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / 'chat.sqlite3')
            payload = {'conversation': 'group', 'text': 'persisted', 'request_id': 'stable'}
            store = ChatStore(path)
            result = store.send(payload)
            store.close()
            store = ChatStore(path)
            try:
                self.assertEqual(store.send(payload), result)
                self.assertEqual(len(store.history('group')), 2)
                with self.assertRaises(FileExistsError):
                    store.send(payload | {'text': 'changed'})
            finally:
                store.close()

    def test_offline_recipient_and_invalid_input(self):
        self.store.set_online('coder', False)
        self.assertEqual(self.send(targets=['coder'])['offline_targets'], ['coder'])
        self.assertEqual(len(self.store.history('group')), 1)
        for patch in ({'conversation': 'dm:stranger'}, {'text': ' '}, {'targets': ['unknown']}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                self.send(request_id='new', **patch)

    def test_http_auth_origin_and_assets(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler(self.store, 't'*32))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f'http://127.0.0.1:{server.server_port}'
        try:
            with urlopen(base) as response:
                self.assertIn(b'Agent Commons', response.read())
                self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])
            with self.assertRaises(HTTPError) as error:
                urlopen(base + '/api/members')
            self.assertEqual(error.exception.code, 403)
            client = Client(base, 't'*32)
            self.assertEqual(len(client.request('/api/members')['members']), 3)
            client.request('/api/messages', {'conversation':'dm:coder','text':'HTTP hello','request_id':'http-1'})
            self.assertEqual(len(client.request('/api/messages?conversation=dm:coder')['messages']), 2)
            request = Request(base+'/api/members', headers={'Authorization':'Bearer '+'t'*32, 'Origin':'https://evil.example'})
            with self.assertRaises(HTTPError) as error:
                urlopen(request)
            self.assertEqual(error.exception.code, 403)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
