import tempfile
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from tailnet_agents.chat import ChatStore
from tailnet_agents.client import Client
from tailnet_agents.ui import handler


class GroupHTTPTests(unittest.TestCase):
    def setUp(self):
        self.store=ChatStore()
        users={p:{'token':c*32,'role':r} for p,c,r in [('owner','o','admin'),('alice','a','participant'),('bob','b','admin'),('watcher','w','observer')]}
        self.server=ThreadingHTTPServer(('127.0.0.1',0),handler(self.store,users))
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        url=f'http://127.0.0.1:{self.server.server_port}'
        self.clients={p:Client(url,c['token']) for p,c in users.items()}

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.store.close()

    def create(self,name='Explicit group',humans=None):
        return self.clients['owner'].request('/api/groups',{'name':name,'humans':humans or ['alice']})['id']

    def test_fresh_install_has_no_groups_until_human_creation(self):
        for client in self.clients.values():
            self.assertEqual(client.request('/api/groups'),{'groups':[]})
        group=self.create()
        self.assertEqual(self.clients['owner'].request('/api/groups')['groups'][0]['id'],group)
        self.assertEqual(self.clients['alice'].request('/api/groups')['groups'][0]['id'],group)
        self.assertEqual(self.clients['bob'].request('/api/groups')['groups'],[])

    def test_only_admin_can_create_and_only_selected_humans_can_read(self):
        with self.assertRaises(HTTPError) as error:
            self.clients['alice'].request('/api/groups',{'name':'Forbidden','humans':[]})
        self.assertEqual(error.exception.code,403)
        with self.assertRaises(HTTPError) as error:
            self.clients['owner'].request('/api/groups',{'name':'Invalid','humans':['unknown']})
        self.assertEqual(error.exception.code,400)
        group=self.create()
        for path in ('/api/messages?conversation=group&group_id=','/api/members?group_id='):
            with self.assertRaises(HTTPError) as error:
                self.clients['bob'].request(path+group)
            self.assertEqual(error.exception.code,403)
        with self.assertRaises(HTTPError) as error:
            self.clients['bob'].request('/api/messages',{'group_id':group,'conversation':'group','text':'bad','request_id':'1'})
        self.assertEqual(error.exception.code,403)

    def test_group_and_private_histories_and_keys_are_group_scoped(self):
        first=self.create('First')
        second=self.create('Second')
        alice=self.clients['alice']
        for group in (first,second):
            alice.request('/api/messages',{'group_id':group,'conversation':'group','text':group,'request_id':'same'})
        for group in (first,second):
            history=alice.request('/api/messages?conversation=group&group_id='+group)['messages']
            self.assertEqual(history[0]['text'],group)
            self.assertEqual(len(history),2)
        alice.request('/api/messages',{'group_id':first,'conversation':'dm:coder','text':'first private','request_id':'private'})
        self.assertEqual(alice.request('/api/messages?conversation=dm:coder&group_id='+second)['messages'],[])
        self.assertEqual(self.clients['owner'].request('/api/messages?conversation=dm:coder&group_id='+first)['messages'],[])

    def test_observer_membership_does_not_grant_send_permission(self):
        group=self.create(humans=['watcher'])
        watcher=self.clients['watcher']
        self.assertEqual(watcher.request('/api/messages?conversation=group&group_id='+group)['messages'],[])
        with self.assertRaises(HTTPError) as error:
            watcher.request('/api/messages',{'group_id':group,'conversation':'group','text':'forbidden','request_id':'1'})
        self.assertEqual(error.exception.code,403)


class GroupPersistenceTests(unittest.TestCase):
    def test_restart_retains_exact_group_and_membership_without_creating_new_one(self):
        with tempfile.TemporaryDirectory() as folder:
            path=str(Path(folder)/'chat.sqlite3')
            store=ChatStore(path)
            group=store.create_group('Persisted','owner',['alice'])
            store.close()
            store=ChatStore(path)
            try:
                self.assertEqual(store.groups('owner'),[group])
                self.assertEqual(store.groups('alice'),[group])
                self.assertEqual(store.groups('other'),[])
            finally:
                store.close()
