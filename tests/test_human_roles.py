import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from tailnet_agents.chat import ChatStore
from tailnet_agents.client import Client
from tailnet_agents.ui import handler, validate_users


class HumanRoleTests(unittest.TestCase):
    def setUp(self):
        self.store = ChatStore()
        users = {name: {'token': char*32, 'role': role} for name, char, role in
                 [('alice','a','participant'),('bob','b','participant'),('owner','o','admin'),('watcher','w','observer')]}
        self.store.create_group('Test group','owner',list(users),group_id='legacy')
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), handler(self.store, users))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        base = f'http://127.0.0.1:{self.server.server_port}'
        self.clients = {name: Client(base, config['token']) for name, config in users.items()}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.store.close()

    def message(self, conversation='dm:coder', **extra):
        return {'conversation': conversation, 'text': 'private-alice', 'request_id': 'same-key', **extra}

    def test_private_history_isolated_even_from_admin(self):
        self.clients['alice'].request('/api/messages', self.message())
        self.assertEqual(len(self.clients['alice'].request('/api/messages?conversation=dm:coder')['messages']), 2)
        for principal in ('bob', 'owner'):
            self.assertEqual(self.clients[principal].request('/api/messages?conversation=dm:coder')['messages'], [])
        self.assertEqual(self.clients['bob'].request('/api/me'), {'id':'bob','role':'participant'})

    def test_same_request_key_is_independent_between_humans(self):
        first = self.clients['alice'].request('/api/messages', self.message())
        second = self.clients['bob'].request('/api/messages', self.message(text='private-bob'))
        self.assertNotEqual(first['message_id'], second['message_id'])
        self.assertEqual(self.clients['alice'].request('/api/messages', self.message()), first)
        bob_history = self.clients['bob'].request('/api/messages?conversation=dm:coder')['messages']
        self.assertEqual(bob_history[0]['text'], 'private-bob')

    def test_roles_are_checked_on_api_not_only_ui(self):
        observer = self.clients['watcher']
        self.assertEqual(observer.request('/api/messages?conversation=group')['messages'], [])
        for path, body in [('/api/messages', self.message('group')),
                           ('/api/presence', {'agent':'coder','online':False})]:
            with self.subTest(path=path), self.assertRaises(HTTPError) as error:
                observer.request(path, body)
            self.assertEqual(error.exception.code, 403)
        with self.assertRaises(HTTPError) as error:
            observer.request('/api/messages?conversation=dm:coder')
        self.assertEqual(error.exception.code, 403)
        with self.assertRaises(HTTPError) as error:
            self.clients['alice'].request('/api/presence', {'agent':'coder','online':False})
        self.assertEqual(error.exception.code, 403)
        self.clients['owner'].request('/api/presence', {'agent':'coder','online':False})
        self.assertFalse(next(m for m in self.store.members() if m['id']=='coder')['online'])

    def test_cannot_supply_another_human_identity(self):
        with self.assertRaises(HTTPError) as error:
            self.clients['bob'].request('/api/messages', self.message(principal='alice'))
        self.assertEqual(error.exception.code, 400)
        self.clients['alice'].request('/api/messages', self.message('group'))
        history = self.clients['bob'].request('/api/messages?conversation=group')['messages']
        self.assertEqual(history[0]['author'], 'alice')


class HumanMigrationTests(unittest.TestCase):
    def test_legacy_private_messages_remain_exclusively_demo_owner(self):
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder)/'chat.sqlite3')
            db = sqlite3.connect(path)
            db.execute('CREATE TABLE messages (id INTEGER PRIMARY KEY, conversation TEXT NOT NULL, sender TEXT NOT NULL, text TEXT NOT NULL, created REAL NOT NULL)')
            db.execute("INSERT INTO messages VALUES(1,'dm:coder','human','legacy-private',1)")
            db.commit()
            db.close()
            store = ChatStore(path)
            try:
                self.assertEqual(store.history('dm:coder', 'alice'), [])
                self.assertEqual(store.history('dm:coder', 'demo-owner')[0]['text'], 'legacy-private')
            finally:
                store.close()

    def test_duplicate_tokens_and_invalid_roles_rejected(self):
        with self.assertRaises(ValueError):
            validate_users({'a': {'token':'x'*32,'role':'admin'}, 'b': {'token':'x'*32,'role':'participant'}})
        with self.assertRaises(ValueError):
            validate_users({'a': {'token':'x'*32,'role':'god'}})
