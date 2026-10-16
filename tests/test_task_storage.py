"""Local admission limits preserve original signed history and recovery writes."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from tailnet_agents import task_storage as storage
from tailnet_agents.task_mcp import Backend, load_config
from tailnet_agents.task_ui import TaskBridge
from tailnet_agents.ui import handler
import test_durable_tasks as fixtures
import test_task_mcp as mcp_fixtures
import test_task_ui as ui_fixtures

try:
    from tailnet_agents.durable_tasks import make_task, TaskUnavailable
    HAS_CRYPTO=fixtures.HAS_CRYPTO
except ImportError:
    HAS_CRYPTO=False


class StorageCoreTests(unittest.TestCase):
    def test_mcp_capacity_failure_is_actionable_and_never_leaks_exception_details(self):
        class Full:
            def call(self,*_):raise storage.StorageFull('SECRET')
        server,_=mcp_fixtures.ready(Full())
        result=mcp_fixtures.call(server,'queue_signed_task',task_id='a'*32,input='x')
        self.assertTrue(result['result']['isError'])
        self.assertIn('storage admission full',json.dumps(result));self.assertNotIn('SECRET',json.dumps(result))

    def test_limits_validate_exact_integer_configuration_without_crypto(self):
        self.assertEqual(storage.limits({}),storage.CALLER_DEFAULTS)
        for values in ({'capacity':True},{'byte_capacity':1.5},{'capacity':0},{'history_capacity':100001},
                       {'byte_capacity':1024**3+1},{'url':'https://other'},[],None):
            with self.subTest(values=values),self.assertRaises(ValueError):storage.limits(values)
        with self.assertRaises(ValueError):storage.limits({'review_capacity':1},consent=True)

    def test_private_caller_config_accepts_only_valid_nested_limits(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);config=mcp_fixtures.TaskMCPCoreTests().config(root)
            path=root/'config'
            for value in ({'capacity':1,'byte_capacity':40000},{'capacity':False},{'capacity':'1'},
                          {'caller':'other'},None):
                path.write_text(json.dumps(config|{'storage_limits':value}));path.chmod(0o600)
                if value=={'capacity':1,'byte_capacity':40000}:self.assertEqual(load_config(str(path))['storage_limits'],value)
                else:
                    with self.assertRaises(ValueError):load_config(str(path))
            path.write_text(json.dumps(config)[:-1]+',"storage_limits":{"capacity":1,"capacity":2}}')
            with self.assertRaises(ValueError):load_config(str(path))

    def test_ui_quota_flags_fail_before_database_creation_without_bindings(self):
        with tempfile.TemporaryDirectory() as folder:
            env=dict(os.environ,TAILNET_UI_TOKEN='o'*32);env.pop('TAILNET_UI_USERS',None)
            for value in ('0','1'):
                database=Path(folder)/'ui.sqlite3'
                result=subprocess.run([sys.executable,'-m','tailnet_agents.ui','--database',str(database),
                    '--task-consent-capacity',value],env=env,capture_output=True,text=True,timeout=5)
                self.assertEqual(result.returncode,2);self.assertFalse(database.exists())
                self.assertNotIn('Traceback',result.stderr)


@unittest.skipUnless(HAS_CRYPTO,'install identity extra')
class CallerStorageTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.DurableTaskTests('test_two_same_host_callers_keep_separate_task_identity_and_private_results')
        self.addCleanup(self.f.doCleanups);self.f.setUp()

    def token(self,mid='a'*32,text='original'):
        f=self.f
        return make_task(f.keys[0],f.owner.public_key(),f.group,f.audience,f.subjects[2],text,identifier=mid,now=f.now)

    def submit(self,a,mid):
        p=a.submit_preview(mid);return a.submit(mid,p['request_hash'],mid)

    def test_active_capacity_blocks_only_new_intents_and_terminal_result_frees_slot(self):
        a=self.f.client(capacity=1,history_capacity=3)
        original=a.queue_once('a'*32,'original')
        self.assertEqual(a.queue_once('a'*32,'original'),original)
        with self.assertRaises(FileExistsError):a.queue_once('a'*32,'changed')
        with self.assertRaises(storage.StorageFull):a.queue_once('b'*32,'blocked')
        self.assertEqual(self.f.calls,[]);self.assertEqual(self.submit(a,'a'*32)['status'],'completed')
        a.queue_once('b'*32,'next');self.assertEqual(a.storage_status()['usage']['active'],1)
        self.assertEqual(a.storage_status()['usage']['tasks'],2)

    def test_history_capacity_keeps_completed_cancelled_and_archived_originals(self):
        a=self.f.client(history_capacity=1);a.queue_once('a'*32,'original');self.submit(a,'a'*32)
        p=a.archive_preview('a'*32);a.archive('a'*32,p['request_hash'],p['receipt_hash'],'a'*32)
        with self.assertRaises(storage.StorageFull):a.queue('new task')
        self.assertEqual(a.show('a'*32)['status'],'completed');self.assertEqual(a.refresh('a'*32)['status'],'completed')
        self.assertEqual(self.f.calls,['original'])

    def test_exact_byte_budget_admits_one_multibyte_intent_and_rejects_one_byte_less(self):
        text='界'*682;budget=len(self.token(text=text).encode())+storage.TASK_RESERVE
        a=self.f.client(byte_capacity=budget);a.queue_once('a'*32,text)
        self.assertEqual(a.storage_status()['usage']['charged_bytes'],budget)
        b=self.f.client(state=self.f.root/'too-small.sqlite3',byte_capacity=budget-1)
        with self.assertRaises(storage.StorageFull):b.queue_once('a'*32,text)
        self.assertEqual(b.list_tasks()['tasks'],[])

    def test_full_budget_reserved_result_and_cancellation_writes_survive_failure(self):
        budget=len(self.token().encode())+storage.TASK_RESERVE
        a=self.f.client(capacity=1,history_capacity=1,byte_capacity=budget);a.queue_once('a'*32,'original')
        before=a.storage_status()['usage'];p=a.cancel_preview('a'*32)
        with patch.object(a.http,'request',side_effect=URLError('offline')):
            with self.assertRaises(URLError):a.cancel('a'*32,p['request_hash'],'a'*32)
        self.assertTrue(a.show('a'*32)['cancellation_requested'])
        a.close();a=self.f.client(capacity=1,history_capacity=1,byte_capacity=1)
        self.assertEqual(a.cancel('a'*32,p['request_hash'],'a'*32)['status'],'cancelled')
        self.assertEqual(a.storage_status()['usage']['charged_bytes'],before['charged_bytes'])
        self.assertEqual(a.refresh('a'*32)['status'],'cancelled');self.assertEqual(self.f.calls,[])

    def test_signed_result_commit_is_allowed_even_after_lowering_budget_below_usage(self):
        a=self.f.client(byte_capacity=1_000_000);a.queue_once('a'*32,'original');a.close()
        a=self.f.client(byte_capacity=1)
        self.assertEqual(self.submit(a,'a'*32)['status'],'completed')
        self.assertEqual(a.show('a'*32)['status'],'completed')
        with self.assertRaises(storage.StorageFull):a.queue('blocked')

    def test_parallel_new_queue_admission_never_exceeds_capacity(self):
        a=self.f.client(capacity=1)
        def queue(i):
            try:a.queue_once(f'{i:032x}','parallel');return True
            except storage.StorageFull:return False
        with ThreadPoolExecutor(max_workers=4) as pool:self.assertEqual(sum(pool.map(queue,range(4))),1)
        self.assertEqual(len(a.list_tasks()['tasks']),1)

    def test_queue_sql_failure_rolls_back_usage_and_stable_id_remains_available(self):
        a=self.f.client(capacity=1)
        with a.db:a.db.execute("CREATE TRIGGER no_queue BEFORE INSERT ON task_outbox BEGIN SELECT RAISE(ABORT,'fail'); END")
        with self.assertRaises(sqlite3.Error):a.queue_once('a'*32,'original')
        self.assertEqual(a.storage_status()['usage']['charged_bytes'],0)
        with a.db:a.db.execute('DROP TRIGGER no_queue')
        a.queue_once('a'*32,'original');self.assertEqual(a.storage_status()['usage']['tasks'],1)

    def test_invalid_limits_never_create_caller_state(self):
        for options in ({'capacity':False},{'byte_capacity':0},{'review_capacity':100001}):
            path=self.f.root/'must-not-create.sqlite3'
            with self.assertRaises(ValueError):self.f.client(state=path,**options)
            self.assertFalse(path.exists())

    def test_same_host_independent_keys_have_independent_outbox_budgets(self):
        a=self.f.client(capacity=1);b=self.f.client(i=1,capacity=1)
        a.queue_once('a'*32,'caller A');b.queue_once('a'*32,'caller B')
        for client in (a,b):
            with self.assertRaises(storage.StorageFull):client.queue('blocked')
        self.assertNotEqual(a.subject,b.subject);self.assertEqual(a.group,b.group)

    def uncertain(self,a):
        a.queue_once('a'*32,'original')
        with patch.object(self.f.executor,'_run',side_effect=TaskUnavailable('pause')):
            with self.assertRaises(HTTPError) as error:self.submit(a,'a'*32)
            error.exception.close()
        with self.f.node._registry.db:self.f.node._registry.db.execute("UPDATE durable_tasks SET status='running' WHERE task_id=?",('a'*32,))
        self.f.restart();a.refresh('a'*32)

    def test_uncertain_outcomes_keep_active_admission_slot_and_cannot_bypass_quota(self):
        a=self.f.client(capacity=1);self.uncertain(a)
        self.assertEqual(a.storage_status()['usage']['active'],1)
        with self.assertRaises(storage.StorageFull):a.queue('replacement')
        self.assertEqual(self.f.calls,[])

    def test_review_count_and_bytes_bound_new_notes_but_retries_keep_original_signature(self):
        a=self.f.client(review_capacity=1);self.uncertain(a);p=a.review_preview('a'*32)
        first=a.review('a'*32,p['receipt_hash'],'unresolved','original evidence','e'*32,'a'*32)
        self.assertEqual(a.review('a'*32,p['receipt_hash'],'unresolved','original evidence','e'*32,'a'*32),first)
        with self.assertRaises(storage.StorageFull):a.review('a'*32,p['receipt_hash'],'unresolved','new evidence','f'*32,'a'*32)
        usage=a.storage_status()['usage'];a.close();a=self.f.client(byte_capacity=usage['charged_bytes'],review_capacity=2)
        with self.assertRaises(storage.StorageFull):a.review('a'*32,p['receipt_hash'],'unresolved','new evidence','f'*32,'a'*32)
        self.assertEqual(a.review('a'*32,p['receipt_hash'],'unresolved','original evidence','e'*32,'a'*32),first)
        self.assertEqual(len(a.reviews('a'*32)['reviews']),1)

    def test_private_config_and_signed_mcp_share_limits_without_tool_overrides(self):
        path,config=mcp_fixtures.SignedTaskMCPTests.configuration(self.f)
        path.write_text(json.dumps(config|{'storage_limits':{'capacity':1}}))
        backend=Backend.from_config(str(path));self.addCleanup(backend.close);backend.client.clock=lambda:self.f.now
        backend.call('queue_signed_task',{'task_id':'a'*32,'input':'original'})
        with self.assertRaises(storage.StorageFull):backend.call('queue_signed_task',{'task_id':'b'*32,'input':'blocked'})
        self.assertEqual(backend.call('signed_task_status',{})['storage']['usage']['tasks'],1)

    def test_actual_caller_cli_enforces_limits_and_reports_original_state(self):
        path,config=mcp_fixtures.SignedTaskMCPTests.configuration(self.f)
        command=[sys.executable,'-m','tailnet_agents.task_client']
        for field,value in config.items():command.extend(['--'+field.replace('_','-'),value])
        command.extend(['--capacity','1','--history-capacity','1','--byte-capacity','100000'])
        text=self.f.root/'input';text.write_text('CLI original')
        first=subprocess.run(command+['queue','--input-file',str(text)],capture_output=True,text=True,timeout=5)
        self.assertEqual(first.returncode,0,first.stderr);mid=json.loads(first.stdout)['task_id']
        second=subprocess.run(command+['queue','--input-file',str(text)],capture_output=True,text=True,timeout=5)
        self.assertEqual(second.returncode,1);self.assertEqual(second.stdout,'')
        self.assertIn('storage admission full',second.stderr)
        status=subprocess.run(command+['storage'],capture_output=True,text=True,timeout=5)
        self.assertEqual(status.returncode,0,status.stderr)
        self.assertEqual(json.loads(status.stdout)['usage']['tasks'],1)
        shown=subprocess.run(command+['show','--task-id',mid],capture_output=True,text=True,timeout=5)
        self.assertEqual(json.loads(shown.stdout)['state'],'pending');self.assertEqual(self.f.calls,[])


@unittest.skipUnless(HAS_CRYPTO,'install identity extra')
class HumanConsentStorageTests(unittest.TestCase):
    def setUp(self):
        self.case=ui_fixtures.TaskUIIdentityTests('test_single_task_submit_and_repeat_confirmation_never_batch_or_replay')
        self.addCleanup(self.case.doCleanups);self.case.setUp()

    def configure(self,**limits):
        c=self.case;c.bridge=TaskBridge(c.store,[('caller','owner',Backend(c.client))],clock=lambda:c.f.now,**limits)
        c.server.RequestHandlerClass=handler(c.store,c.users,task_bridge=c.bridge)

    def test_full_consent_count_preserves_history_saved_confirmation_and_cli_cancellation(self):
        c=self.case;self.configure(consent_capacity=1)
        p=c.preview('queue',input='original');self.assertEqual(c.confirm(p)['state'],'pending')
        c.denied(429,lambda:c.preview('cancel'))
        self.assertEqual(c.confirm(p)['state'],'pending')
        result=c.humans['owner'].request('/api/task-read',{'group_id':c.group,'binding_id':'caller','operation':'storage'})
        self.assertEqual(result['consents']['usage']['consents'],1)
        cancel=c.client.cancel_preview('a'*32)
        self.assertEqual(c.client.cancel('a'*32,cancel['request_hash'],'a'*32)['status'],'cancelled')
        self.assertEqual(c.client.show('a'*32)['status'],'cancelled')

    def test_full_consent_bytes_deny_preview_without_queuing_or_creating_partial_record(self):
        c=self.case;self.configure(consent_byte_capacity=1)
        c.denied(429,lambda:c.preview('queue',input='secret'))
        self.assertEqual(c.client.list_tasks()['tasks'],[])
        self.assertEqual(storage.consent_usage(c.store.db,'caller','owner')['consents'],0)

    def test_consent_budget_exact_boundary_counts_multibyte_serialized_payload(self):
        c=self.case;c.preview('queue',input='界'*100)
        charged=storage.consent_usage(c.store.db,'caller','owner')['charged_bytes']
        self.configure(consent_byte_capacity=charged*2)
        c.preview('queue','b'*32,input='界'*100)
        self.assertEqual(storage.consent_usage(c.store.db,'caller','owner')['charged_bytes'],charged*2)
        c.denied(429,lambda:c.preview('queue','c'*32,input='界'*100))

    def test_existing_preview_id_retry_works_above_both_consent_limits(self):
        c=self.case;payload={'binding_id':'caller','operation':'queue','task_id':'a'*32,'request_id':'f'*32,'input':'original'}
        first=c.bridge.preview('owner',c.group,payload);self.configure(consent_capacity=1,consent_byte_capacity=1)
        self.assertEqual(c.bridge.preview('owner',c.group,payload),first)
        self.assertEqual(c.confirm(first)['state'],'pending')
        self.assertEqual(storage.consent_usage(c.store.db,'caller','owner')['consents'],1)

    def test_started_cancel_retry_saves_result_at_full_consent_and_caller_budgets(self):
        c=self.case;c.queue();p=c.preview('cancel')
        with patch.object(c.client.http,'request',side_effect=URLError('offline')):c.denied(502,lambda:c.confirm(p))
        before=storage.consent_usage(c.store.db,'caller','owner')['charged_bytes']
        from tailnet_agents.chat import ChatStore
        from tailnet_agents.policy_admin import PolicyAuthority
        c.bridge.close();c.store.close()
        c.store=ChatStore(c.database,policy_authority=PolicyAuthority(c.f.owner,'owner',clock=lambda:c.f.now))
        c.client=c.f.client(byte_capacity=1)
        self.configure(consent_capacity=1,consent_byte_capacity=1)
        self.assertEqual(c.confirm(p)['status'],'cancelled')
        self.assertEqual(storage.consent_usage(c.store.db,'caller','owner')['charged_bytes'],before)
        self.assertEqual(c.f.calls,[])

    def test_ui_caller_quota_error_is_429_and_original_consent_recovers_after_increase(self):
        c=self.case;c.client.storage_limits=storage.limits({'byte_capacity':1})
        p=c.preview('queue',input='original');c.denied(429,lambda:c.confirm(p))
        self.assertEqual(c.client.list_tasks()['tasks'],[])
        c.client.storage_limits=storage.limits({})
        self.assertEqual(c.confirm(p)['state'],'pending');self.assertEqual(len(c.client.list_tasks()['tasks']),1)

    def test_parallel_distinct_previews_never_exceed_per_binding_count(self):
        c=self.case;self.configure(consent_capacity=1)
        def preview(i):
            try:
                c.bridge.preview('owner',c.group,{'binding_id':'caller','operation':'queue','task_id':f'{i:032x}','request_id':f'{i:032x}','input':'parallel'})
                return True
            except storage.StorageFull:return False
        with ThreadPoolExecutor(max_workers=4) as pool:self.assertEqual(sum(pool.map(preview,range(4))),1)
        self.assertEqual(storage.consent_usage(c.store.db,'caller','owner')['consents'],1)

    def test_same_host_bindings_keep_separate_consent_budgets_and_histories(self):
        c=self.case;other=c.f.client(i=1)
        c.bridge=TaskBridge(c.store,[('caller','owner',Backend(c.client)),('other','owner',Backend(other))],clock=lambda:c.f.now,consent_capacity=1)
        for name,mid in [('caller','a'*32),('other','b'*32)]:
            c.bridge.preview('owner',c.group,{'binding_id':name,'operation':'queue','task_id':mid,'request_id':mid,'input':'independent'})
            self.assertEqual(storage.consent_usage(c.store.db,name,'owner')['consents'],1)
        self.assertNotEqual(c.client.subject,other.subject)

    def test_capacity_read_is_local_role_checked_and_rejects_override_fields(self):
        c=self.case
        body={'group_id':c.group,'binding_id':'caller','operation':'storage'}
        with patch.object(c.client.http,'request',side_effect=AssertionError('network')):
            result=c.humans['owner'].request('/api/task-read',body)
        self.assertFalse(result['caller']['physical_disk_limit'])
        for human in ('other','participant','observer'):
            c.denied(403,lambda:c.humans[human].request('/api/task-read',body))
        c.denied(400,lambda:c.humans['owner'].request('/api/task-read',body|{'capacity':999}))
