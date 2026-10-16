"""Human UI consent, isolation and original signed-task recovery."""
import json
import os
from pathlib import Path
import sqlite3
import selectors
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from tailnet_agents.chat import ChatStore
from tailnet_agents.client import Client
from tailnet_agents.task_mcp import Backend
from tailnet_agents.task_ui import TaskBridge
from tailnet_agents.ui import handler
from tests import test_durable_tasks as fixtures
from tests import test_task_mcp as mcp_fixtures

try:
    from tailnet_agents.policy_admin import PolicyAuthority
    from tailnet_agents.group_policy import verify_policy
    from tailnet_agents.identity import generate_identity
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class TaskUICoreTests(unittest.TestCase):
    def test_default_ui_exposes_no_task_bindings_and_cannot_mutate_tasks(self):
        store = ChatStore();self.addCleanup(store.close)
        group = store.create_group('Explicit group','owner',[],request_id='group')['id']
        users = {'owner':{'role':'admin','token':'o'*32}}
        server = ThreadingHTTPServer(('127.0.0.1',0), handler(store,users))
        worker = threading.Thread(target=server.serve_forever);worker.start()
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),worker.join()))
        client = Client(f'http://127.0.0.1:{server.server_port}','o'*32)
        self.assertEqual(client.request('/api/task-bindings?group_id='+group), {'bindings':[]})
        for endpoint in ('preview','confirm','read'):
            with self.assertRaises(HTTPError) as caught:client.request('/api/task-'+endpoint,{'group_id':group})
            self.assertEqual(caught.exception.code,403);caught.exception.close()
        self.assertEqual(len(store.groups('owner')),1)

    def test_binding_file_requires_private_absolute_regular_file_and_exact_fields(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'bindings.json'
            with self.assertRaises(ValueError):TaskBridge.from_file(None,{},'relative.json')
            path.write_text('[]');path.chmod(0o644)
            with self.assertRaises(ValueError):TaskBridge.from_file(None,{},str(path))
            path.chmod(0o600)
            for value in ([],{},[{'id':'x','human':'owner','url':'https://untrusted'}],
                          [{'id':'x','human':'observer','config_file':'/unused'}]):
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):TaskBridge.from_file(None,{'observer':{'role':'observer'}},str(path))
            link=Path(folder)/'link';link.symlink_to(path)
            with self.assertRaises(OSError):TaskBridge.from_file(None,{},str(link))


@unittest.skipUnless(HAS_CRYPTO,'install identity extra')
class TaskUIIdentityTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.DurableTaskTests('test_two_same_host_callers_keep_separate_task_identity_and_private_results')
        self.addCleanup(self.f.doCleanups);self.f.setUp()
        self.root,self.group=self.f.root,self.f.group
        self.database=str(self.root/'ui.sqlite3')
        self.users={name:{'role':role,'token':char*32} for name,role,char in
                    [('owner','admin','o'),('other','admin','a'),('participant','participant','p'),('observer','observer','w')]}
        self.store=ChatStore(self.database,policy_authority=PolicyAuthority(self.f.owner,'owner',clock=lambda:self.f.now))
        self.addCleanup(lambda:self.store.close())
        name=verify_policy(self.f.policy,self.f.owner.public_key(),self.group)['name']
        self.store.create_group(name,'owner',list(self.users),group_id=self.group)
        with self.store.db:self.store.policy_authority._save(self.store.db,self.group,self.f.policy,'fixture-create',self.group)
        self.client=self.f.client()
        self.bridge=TaskBridge(self.store,[('caller','owner',Backend(self.client))],clock=lambda:self.f.now)
        self.addCleanup(lambda:self.bridge.close())
        self.server=ThreadingHTTPServer(('127.0.0.1',0),handler(self.store,self.users,task_bridge=self.bridge))
        worker=threading.Thread(target=self.server.serve_forever);worker.start()
        self.addCleanup(lambda:(self.server.shutdown(),self.server.server_close(),worker.join()))
        self.url=f'http://127.0.0.1:{self.server.server_port}'
        self.humans={name:Client(self.url,config['token']) for name,config in self.users.items()}
        self.counter=0

    def preview(self,operation,mid='a'*32,**extra):
        self.counter+=1
        return self.humans['owner'].request('/api/task-preview',{'group_id':self.group,'binding_id':'caller',
            'operation':operation,'task_id':mid,'request_id':f'{self.counter:032x}',**extra})

    def confirmation(self,preview):
        return {'group_id':self.group,'binding_id':preview['binding_id'],'consent_id':preview['consent_id'],
                'confirm_task_id':preview['task_id']}

    def confirm(self,preview):return self.humans['owner'].request('/api/task-confirm',self.confirmation(preview))

    def queue(self,mid='a'*32,text='original Echo'):
        return self.confirm(self.preview('queue',mid,input=text))

    def denied(self,code,action):
        with self.assertRaises(HTTPError) as caught:action()
        self.assertEqual(caught.exception.code,code)
        body=caught.exception.read().decode();caught.exception.close();return body

    def test_open_preview_and_local_reads_never_queue_submit_or_create_groups(self):
        before=self.f.node._registry.db.total_changes
        with patch.object(self.client.http,'request',side_effect=AssertionError('unexpected network')):
            bindings=self.humans['owner'].request('/api/task-bindings?group_id='+self.group)
            self.assertEqual(len(bindings['bindings']),1)
            p=self.preview('queue',input='exact original')
            self.assertEqual(p['input'],'exact original');self.assertFalse(p['network'])
            self.assertEqual(self.client.list_tasks()['tasks'],[])
            self.assertEqual(self.confirm(p)['state'],'pending')
        self.assertEqual(self.f.node._registry.db.total_changes,before)
        self.assertEqual(len(self.store.groups('owner')),1);self.assertEqual(self.f.calls,[])

    def test_roles_other_admin_and_forged_human_cannot_use_original_consent(self):
        p=self.preview('queue',input='secret input')
        for name in ('other','participant','observer'):
            self.denied(403,lambda:self.humans[name].request('/api/task-confirm',self.confirmation(p)))
            self.denied(403,lambda:self.humans[name].request('/api/task-read',{'group_id':self.group,
                'binding_id':'caller','operation':'history'}))
        self.denied(400,lambda:self.humans['owner'].request('/api/task-confirm',self.confirmation(p)|{'human':'other'}))
        self.assertEqual(self.client.list_tasks()['tasks'],[])

    def test_exact_schemas_ids_pages_and_fixed_credential_bindings(self):
        p=self.preview('queue',input='secret input')
        for change in ({'url':'https://evil'},{'state':'/tmp/other'},{'confirm_task_id':'b'*32}):
            self.denied(400,lambda:self.humans['owner'].request('/api/task-confirm',self.confirmation(p)|change))
        for page in ({'limit':True},{'after':-1},{'limit':101},{'task_id':'a'*32}):
            self.denied(400,lambda:self.humans['owner'].request('/api/task-read',{'group_id':self.group,
                'binding_id':'caller','operation':'history',**page}))
        self.denied(400,lambda:self.preview('queue',input='界'*683))
        self.denied(400,lambda:self.preview('queue',mid='../secret',input='x'))
        self.denied(403,lambda:self.humans['owner'].request('/api/task-confirm',self.confirmation(p)|{'group_id':'other'}))

    def test_preview_retry_is_stable_and_changed_request_id_conflicts(self):
        payload={'binding_id':'caller','operation':'queue','task_id':'a'*32,'request_id':'f'*32,'input':'original'}
        p=self.bridge.preview('owner',self.group,payload)
        self.assertEqual(self.bridge.preview('owner',self.group,payload),p)
        with self.assertRaises(FileExistsError):self.bridge.preview('owner',self.group,payload|{'input':'changed'})
        self.assertEqual(self.client.list_tasks()['tasks'],[])
        self.preview('queue','b'*32,input='another preview')
        first=self.bridge.read('owner',self.group,{'binding_id':'caller','operation':'history','limit':1})
        second=self.bridge.read('owner',self.group,{'binding_id':'caller','operation':'history','limit':1,'after':first['next_after']})
        self.assertTrue(first['has_more']);self.assertFalse(second['has_more'])
        self.assertNotEqual(first['consents'][0]['consent_id'],second['consents'][0]['consent_id'])

    def test_expired_or_rolled_back_consent_stays_expired(self):
        for offset in (60,-1):
            self.f.now=110;p=self.preview('queue',input='original')
            self.f.now=110+offset;self.denied(409,lambda:self.confirm(p))
            self.f.now=110;self.denied(409,lambda:self.confirm(p))
        self.assertEqual(self.client.list_tasks()['tasks'],[])

    def test_changed_group_policy_invalidates_unstarted_consent(self):
        p=self.preview('queue',input='original')
        with self.store.lock,self.store.db:
            revision=self.store.policy_authority.current(self.store.db,self.group)[1]['revision']
            self.store.policy_authority.change(self.store.db,self.group,'renew',{'expected_revision':revision,'request_id':'renew'})
        self.denied(409,lambda:self.confirm(p));self.assertEqual(self.client.list_tasks()['tasks'],[])

    def test_single_task_submit_and_repeat_confirmation_never_batch_or_replay(self):
        self.queue();self.queue('b'*32,'other pending')
        p=self.preview('submit');self.assertEqual(self.f.calls,[])
        result=self.confirm(p);self.assertEqual(result['status'],'completed')
        self.assertEqual(self.confirm(p),result);self.assertEqual(self.f.calls,['original Echo'])
        self.assertEqual(self.client.show('b'*32)['state'],'pending')

    def test_started_authorization_precedes_network_and_survives_lost_submit_ack(self):
        self.queue();p=self.preview('submit');original=self.client.http.request
        def lost(path,body):
            state=self.store.db.execute('SELECT state FROM ui_task_consents WHERE id=?',(p['consent_id'],)).fetchone()[0]
            self.assertEqual(state,'started')
            response=original(path,body)
            if path=='/v1/agent-tasks':raise URLError('SECRET transport detail')
            return response
        with patch.object(self.client.http,'request',side_effect=lost):
            self.assertNotIn('SECRET',self.denied(502,lambda:self.confirm(p)))
        self.f.now+=70
        self.assertEqual(self.confirm(p)['status'],'completed');self.assertEqual(self.f.calls,['original Echo'])

    def test_cancel_barrier_survives_failure_refresh_and_ui_restart(self):
        self.queue();p=self.preview('cancel')
        with patch.object(self.client.http,'request',side_effect=URLError('offline')):
            self.denied(502,lambda:self.confirm(p))
        self.assertTrue(self.client.show('a'*32)['cancellation_requested'])
        self.bridge.close();self.store.close()
        self.store=ChatStore(self.database,policy_authority=PolicyAuthority(self.f.owner,'owner',clock=lambda:self.f.now))
        self.client=self.f.client();self.bridge=TaskBridge(self.store,[('caller','owner',Backend(self.client))],clock=lambda:self.f.now)
        self.server.RequestHandlerClass=handler(self.store,self.users,task_bridge=self.bridge)
        self.assertEqual(self.confirm(p)['status'],'cancelled')
        self.denied(409,lambda:self.confirm(self.preview('submit')))
        self.assertEqual(self.f.calls,[])

    def test_completed_confirmation_remains_historical_local_after_dissolution(self):
        self.queue();p=self.preview('submit');result=self.confirm(p)
        name=self.store.group_info('owner',self.group)['name'];self.store.dissolve_group('owner',self.group,name)
        with patch.object(self.client.http,'request',side_effect=AssertionError('network')):
            self.assertEqual(self.confirm(p),result)
        self.denied(403,lambda:self.preview('submit'))
        history=self.humans['owner'].request('/api/task-read',{'group_id':self.group,'binding_id':'caller','operation':'history'})
        self.assertEqual(len(history['consents']),2)

    def test_terminal_archive_and_remote_refresh_require_separate_confirmation(self):
        self.queue();self.confirm(self.preview('submit'))
        archive=self.preview('archive')
        self.assertEqual(self.f.node._registry.db.execute('SELECT COUNT(*) FROM archived_tasks').fetchone()[0],0)
        self.assertTrue(self.confirm(archive)['archived']);self.assertEqual(self.f.calls,['original Echo'])
        refresh=self.preview('refresh');self.assertEqual(self.confirm(refresh)['status'],'completed')
        self.assertEqual(self.f.calls,['original Echo'])

    def test_concurrent_same_confirmation_queues_one_original_intent(self):
        p=self.preview('queue',input='concurrent')
        with ThreadPoolExecutor(max_workers=4) as pool:
            result=list(pool.map(lambda _:self.confirm(p),range(4)))
        self.assertTrue(all(item==result[0] for item in result))
        self.assertEqual(len(self.client.list_tasks()['tasks']),1)

    def test_failed_consent_start_commit_cannot_queue_or_contact_executor(self):
        p=self.preview('queue',input='never queued')
        with self.store.lock,self.store.db:self.store.db.execute("CREATE TRIGGER reject_consent BEFORE UPDATE ON ui_task_consents BEGIN SELECT RAISE(ABORT,'SECRET'); END")
        self.assertNotIn('SECRET',self.denied(502,lambda:self.confirm(p)))
        self.assertEqual(self.client.list_tasks()['tasks'],[])

    def test_failed_result_commit_retries_original_queue_and_retains_audit(self):
        p=self.preview('queue',input='original')
        with self.store.lock,self.store.db:self.store.db.execute("CREATE TRIGGER reject_result BEFORE UPDATE ON ui_task_consents WHEN NEW.state='done' BEGIN SELECT RAISE(ABORT,'SECRET'); END")
        self.denied(502,lambda:self.confirm(p));self.assertEqual(len(self.client.list_tasks()['tasks']),1)
        with self.store.lock,self.store.db:self.store.db.execute('DROP TRIGGER reject_result')
        self.assertEqual(self.confirm(p)['state'],'pending');self.assertEqual(len(self.client.list_tasks()['tasks']),1)

    def test_restart_rejects_replaced_human_binding_state_or_missing_binding(self):
        self.bridge.close()
        for bindings in ([],[('renamed','owner',Backend(self.f.client()))]):
            with self.assertRaises(ValueError):TaskBridge(self.store,bindings)
        replacement=self.f.client(state=self.root/'replacement.sqlite3')
        with self.assertRaises(ValueError):TaskBridge(self.store,[('caller','owner',Backend(replacement))])
        client=self.f.client()
        with self.assertRaises(PermissionError):TaskBridge(self.store,[('caller','other',Backend(client))])

    def test_two_same_host_callers_have_separate_binding_history_and_original_ids(self):
        other=self.f.client(i=1)
        bridge=TaskBridge(self.store,[('caller','owner',Backend(self.client)),('second','owner',Backend(other))],clock=lambda:self.f.now)
        self.bridge=bridge;self.server.RequestHandlerClass=handler(self.store,self.users,task_bridge=bridge)
        self.queue()
        p=bridge.preview('owner',self.group,{'binding_id':'second','operation':'queue','task_id':'a'*32,'request_id':'f'*32,'input':'independent'})
        result=bridge.confirm('owner',self.group,{'binding_id':'second','consent_id':p['consent_id'],'confirm_task_id':'a'*32})
        self.assertEqual(result['state'],'pending');self.assertNotEqual(self.client.subject,other.subject)
        self.assertEqual(len(bridge.read('owner',self.group,{'binding_id':'second','operation':'history'})['consents']),1)

    def test_configured_file_loader_restores_original_keys_group_and_lock(self):
        self.bridge.close();path,config=mcp_fixtures.SignedTaskMCPTests.configuration(self.f,state=self.root/'caller-0.sqlite3')
        bindings=self.root/'bindings.json';bindings.write_text(json.dumps([{'id':'caller','human':'owner','config_file':str(path)}]));bindings.chmod(0o600)
        from tailnet_agents.identity import encode, public_bytes
        pin=Path(config['authority_public_key']);original=pin.read_text()
        wrong=generate_identity(self.root/'wrong-owner.pem')
        pin.write_text(encode(public_bytes(wrong.public_key())))
        path.write_text(json.dumps(config|{'state':str(self.root/'must-not-create.sqlite3')}))
        with self.assertRaises(PermissionError):TaskBridge.from_file(self.store,self.users,str(bindings))
        self.assertFalse((self.root/'must-not-create.sqlite3').exists())
        pin.write_text(original);path.write_text(json.dumps(config))
        bridge=TaskBridge.from_file(self.store,self.users,str(bindings));self.addCleanup(bridge.close)
        self.assertEqual(bridge.bindings['caller'][1].subject,self.f.subjects[0])
        self.assertEqual(bridge.bindings['caller'][1].group,self.group)
        with self.assertRaises(OSError):Backend.from_config(str(path))

    def test_original_preview_and_confirmation_survive_restart_without_execution(self):
        p=self.preview('queue',input='after restart')
        self.bridge.close();self.store.close()
        self.store=ChatStore(self.database,policy_authority=PolicyAuthority(self.f.owner,'owner',clock=lambda:self.f.now))
        self.client=self.f.client();self.bridge=TaskBridge(self.store,[('caller','owner',Backend(self.client))],clock=lambda:self.f.now)
        self.server.RequestHandlerClass=handler(self.store,self.users,task_bridge=self.bridge)
        self.assertEqual(self.client.list_tasks()['tasks'],[])
        self.assertEqual(self.confirm(p)['state'],'pending');self.assertEqual(self.f.calls,[])

    def test_remote_executor_revocation_and_expiry_still_deny_confirmed_submit(self):
        for change in ('revoked','expired'):
            mid=('a' if change=='revoked' else 'b')*32;self.queue(mid)
            if change=='expired':
                self.f.revise(self.f.members);self.f.now=4000
            p=self.preview('submit',mid)
            if change=='revoked':
                members={k:v for k,v in self.f.members.items() if k!=self.f.subjects[2]}
                self.f.revise(members)
            self.denied(502 if change=='revoked' else 400,lambda:self.confirm(p))
        self.assertEqual(self.f.calls,[])

    def test_uncertain_task_cannot_submit_cancel_or_archive_through_ui(self):
        from tailnet_agents.durable_tasks import TaskUnavailable
        self.queue();p=self.preview('submit')
        with patch.object(self.f.executor,'_run',side_effect=TaskUnavailable('pause')):
            self.denied(502,lambda:self.confirm(p))
        with self.f.node._registry.db:self.f.node._registry.db.execute("UPDATE durable_tasks SET status='running' WHERE task_id=?",('a'*32,))
        self.f.restart();self.confirm(self.preview('refresh'))
        self.assertEqual(self.client.show('a'*32)['status'],'uncertain')
        for operation in ('submit','cancel','archive'):
            preview=self.preview(operation);self.assertFalse(preview['eligible'])
            self.denied(409,lambda:self.confirm(preview))
        self.assertEqual(self.f.calls,[])

    def test_https_binding_uses_configured_ca_and_original_executor(self):
        from tests.test_admission_tls import certificates
        tls=certificates(self.root);url,_=self.f.serve_tasks(self.f.executor,tls=tls)
        self.bridge.close()
        path,_=mcp_fixtures.SignedTaskMCPTests.configuration(self.f,url=url,ca=tls['ca'],state=self.root/'tls-caller.sqlite3')
        backend=Backend.from_config(str(path));backend.client.clock=lambda:self.f.now
        self.bridge=TaskBridge(self.store,[('caller','owner',Backend(self.f.client())),('https','owner',backend)],clock=lambda:self.f.now)
        queue=self.bridge.preview('owner',self.group,{'binding_id':'https','operation':'queue','task_id':'a'*32,'request_id':'d'*32,'input':'TLS'})
        confirmation={'binding_id':'https','consent_id':queue['consent_id'],'confirm_task_id':'a'*32}
        self.bridge.confirm('owner',self.group,confirmation)
        submit=self.bridge.preview('owner',self.group,{'binding_id':'https','operation':'submit','task_id':'a'*32,'request_id':'e'*32})
        self.assertEqual(self.bridge.confirm('owner',self.group,confirmation|{'consent_id':submit['consent_id']})['status'],'completed')

    def test_real_ui_cli_requires_bindings_on_restart_and_restores_without_dispatch(self):
        from cryptography.hazmat.primitives import serialization
        self.bridge.close()
        path,_=mcp_fixtures.SignedTaskMCPTests.configuration(self.f,state=self.root/'caller-0.sqlite3')
        bindings=self.root/'bindings.json';bindings.write_text(json.dumps([{'id':'caller','human':'owner','config_file':str(path)}]));bindings.chmod(0o600)
        owner=self.root/'owner.pem';owner.write_bytes(self.f.owner.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));owner.chmod(0o600)
        command=[sys.executable,'-m','tailnet_agents.ui','--port','0','--database',self.database,
            '--policy-owner-key',str(owner),'--policy-owner-public-key',str(self.root/'owner.pub'),'--policy-admin','owner']
        env=dict(os.environ,TAILNET_UI_USERS=json.dumps(self.users))
        missing=subprocess.run(command,env=env,capture_output=True,text=True,timeout=5)
        self.assertEqual(missing.returncode,2);self.assertNotIn('Traceback',missing.stderr)
        process=subprocess.Popen(command+['--task-bindings-file',str(bindings)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout,selectors.EVENT_READ)
                self.assertTrue(selector.select(5),'UI CLI startup timeout')
                line=process.stdout.readline().strip()
            self.assertIn('http://127.0.0.1:',line)
            client=Client(line.split()[-1],'o'*32)
            self.assertEqual(len(client.request('/api/task-bindings?group_id='+self.group)['bindings']),1)
            self.assertEqual(client.request('/api/task-read',{'group_id':self.group,'binding_id':'caller','operation':'list'})['tasks'],[])
        finally:
            process.send_signal(signal.SIGINT)
            try:out,err=process.communicate(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.communicate();raise
        self.assertEqual(process.returncode,0,err);self.assertEqual(self.f.calls,[])
