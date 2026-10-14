import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from tailnet_agents.chat import ChatStore
from tailnet_agents.client import Client
from tailnet_agents.ui import handler


class ChatPagingTests(unittest.TestCase):
    def setUp(self):
        self.store = ChatStore()
        for index in range(6):
            self.store.send({'conversation':'group','text':str(index),'request_id':str(index)})

    def tearDown(self):
        self.store.close()

    def test_backward_pages_and_incremental_updates_without_duplicates(self):
        newest = self.store.page('group', limit=3)
        self.assertTrue(newest['has_more'])
        ids = [m['id'] for m in newest['messages']]
        cursor = min(ids)
        while True:
            older = self.store.page('group', before=cursor, limit=3)
            ids += [m['id'] for m in older['messages']]
            if not older['has_more']:
                break
            cursor = older['messages'][0]['id']
        self.assertEqual(len(ids), 12)
        self.assertEqual(len(set(ids)), 12)
        self.store.send({'conversation':'group','text':'new','request_id':'new'})
        updates = self.store.page('group', after=max(ids), limit=1)
        self.assertTrue(updates['has_more'])
        following = self.store.page('group', after=updates['messages'][-1]['id'], limit=1)
        self.assertFalse(following['has_more'])
        self.assertEqual(following['messages'][0]['sender'], 'moderator')

    def test_private_cursors_never_cross_humans(self):
        for principal in ('alice','bob'):
            self.store.send({'conversation':'dm:coder','text':principal,'request_id':'private'}, principal)
        alice = self.store.page('dm:coder','alice', after=0, limit=200)
        bob = self.store.page('dm:coder','bob', after=0, limit=200)
        self.assertEqual(len(alice['messages']), 2)
        self.assertEqual(len(bob['messages']), 2)
        self.assertTrue(all('alice' in m['text'] for m in alice['messages']))
        alice_id = alice['messages'][-1]['id']
        self.assertEqual(self.store.page('dm:coder','alice',after=alice_id)['messages'], [])

    def test_invalid_cursor_combinations_rejected(self):
        for options in ({'before':1,'after':2},{'after':-1},{'limit':201},{'before':True},{'after':2**64}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.store.page('group',**options)

    def test_http_pages_and_invalid_queries(self):
        server = ThreadingHTTPServer(('127.0.0.1',0),handler(self.store,'t'*32))
        thread = threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        client = Client(f'http://127.0.0.1:{server.server_port}','t'*32)
        try:
            result = client.request('/api/messages?conversation=group&after=0&limit=2')
            self.assertEqual([m['id'] for m in result['messages']],[1,2])
            self.assertTrue(result['has_more'])
            for query in ('after=-1','after=1&before=2','limit=0','after=x','after=1&after=2','owner=alice'):
                with self.subTest(query=query), self.assertRaises(HTTPError) as error:
                    client.request('/api/messages?conversation=group&'+query)
                self.assertEqual(error.exception.code,400)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
