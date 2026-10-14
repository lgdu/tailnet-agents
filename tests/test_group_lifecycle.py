import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError
import test_groups
from tailnet_agents.chat import ChatStore


class GroupLifecycleHTTPTests(unittest.TestCase):
    setUp=test_groups.GroupHTTPTests.setUp
    tearDown=test_groups.GroupHTTPTests.tearDown
    create=test_groups.GroupHTTPTests.create

    def test_creation_retry_is_deduplicated_and_conflict_is_rejected(self):
        body={'name':'Stable','humans':['alice'],'request_id':'stable-creation'}
        client=self.clients['owner']
        first=client.request('/api/groups',body)
        self.assertEqual(client.request('/api/groups',body),first)
        self.assertEqual(len(client.request('/api/groups')['groups']),1)
        with self.assertRaises(HTTPError) as error:
            client.request('/api/groups',body|{'name':'Changed'})
        self.assertEqual(error.exception.code,409)

    def test_creator_manages_members_but_invited_admin_cannot(self):
        group=self.create(humans=['alice','bob'])
        with self.assertRaises(HTTPError) as error:
            self.clients['bob'].request('/api/group-members',{'group_id':group,'subject':'watcher','operation':'add'})
        self.assertEqual(error.exception.code,403)
        self.clients['owner'].request('/api/group-members',{'group_id':group,'subject':'watcher','operation':'add'})
        self.assertEqual(len(self.clients['watcher'].request('/api/groups')['groups']),1)
        self.clients['owner'].request('/api/group-members',{'group_id':group,'subject':'alice','operation':'remove'})
        self.assertEqual(self.clients['alice'].request('/api/groups')['groups'],[])
        with self.assertRaises(HTTPError) as error:
            self.clients['alice'].request('/api/messages?conversation=group&group_id='+group)
        self.assertEqual(error.exception.code,403)
        with self.assertRaises(HTTPError) as error:
            self.clients['owner'].request('/api/group-members',{'group_id':group,'subject':'owner','operation':'remove'})
        self.assertEqual(error.exception.code,400)
        actions=[e['action'] for e in self.clients['owner'].request('/api/group-info?group_id='+group)['audit']]
        self.assertEqual(actions,['create','add','remove'])

    def test_dissolution_requires_confirmation_and_keeps_history_readonly(self):
        group=self.create('Closed')
        payload={'group_id':group,'conversation':'group','text':'history','request_id':'message'}
        self.clients['alice'].request('/api/messages',payload)
        with self.assertRaises(HTTPError) as error:
            self.clients['owner'].request('/api/group-dissolve',{'group_id':group,'confirm_name':'Wrong'})
        self.assertEqual(error.exception.code,400)
        for _ in range(2):
            self.clients['owner'].request('/api/group-dissolve',{'group_id':group,'confirm_name':'Closed'})
        self.assertEqual(len(self.clients['alice'].request('/api/messages?conversation=group&group_id='+group)['messages']),2)
        with self.assertRaises(HTTPError) as error:
            self.clients['alice'].request('/api/messages',payload|{'request_id':'new'})
        self.assertEqual(error.exception.code,403)
        with self.assertRaises(HTTPError) as error:
            self.clients['owner'].request('/api/group-members',{'group_id':group,'subject':'watcher','operation':'add'})
        self.assertEqual(error.exception.code,403)
        info=self.clients['owner'].request('/api/group-info?group_id='+group)
        self.assertEqual([e['action'] for e in info['audit']].count('dissolve'),1)


class GroupLifecyclePersistenceTests(unittest.TestCase):
    def test_revocation_and_dissolution_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path=str(Path(directory)/'chat.sqlite3')
            store=ChatStore(path)
            group=store.create_group('Terminal','owner',['alice'],request_id='create')
            store.update_member('owner',group['id'],'alice','remove')
            store.dissolve_group('owner',group['id'],'Terminal')
            store.close()
            store=ChatStore(path)
            try:
                self.assertEqual(store.groups('alice'),[])
                self.assertTrue(store.groups('owner')[0]['dissolved'])
                self.assertEqual(store.create_group('Terminal','owner',['alice'],request_id='create'),group)
                self.assertEqual(len(store.groups('owner')),1)
                with self.assertRaises(PermissionError):
                    store.send({'conversation':'group','text':'bad','request_id':'send'},'owner',group['id'],enforce_access=True)
            finally:
                store.close()

    def test_legacy_import_cannot_reauthorize_revoked_message_author(self):
        with tempfile.TemporaryDirectory() as directory:
            path=str(Path(directory)/'chat.sqlite3')
            store=ChatStore(path)
            store.create_group('Legacy','demo-owner',['alice'],group_id='legacy')
            store.send({'conversation':'group','text':'old','request_id':'old'},'alice',group_id='legacy')
            store.update_member('demo-owner','legacy','alice','remove')
            store.close()
            store=ChatStore(path)
            try:
                self.assertEqual(store.groups('alice'),[])
                with self.assertRaises(PermissionError):
                    store.require_group('alice','legacy')
            finally:
                store.close()
