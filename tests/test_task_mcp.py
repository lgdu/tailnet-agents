"""Explicit signed-task MCP, durable intent IDs and fixed-authority recovery."""
from concurrent.futures import ThreadPoolExecutor
import io
import json
import os
from pathlib import Path
import selectors
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.error import URLError
from tailnet_agents.mcp import Server, serve
from tailnet_agents.task_mcp import Backend, INSTRUCTIONS, TOOLS, load_config
import test_durable_tasks as fixtures
import test_task_operations as operation_fixtures

try:
    from tailnet_agents.identity import (AdmissionError, encode, generate_identity, identity_id,
        issue_grant, public_bytes, verify_grant)
    from tailnet_agents.group_policy import revise_policy
    from tailnet_agents.verified_directory import issue_revocation
    from tailnet_agents.durable_tasks import TaskUnavailable
    from tests.test_discovery import DiscoveryFixture
    from tests.test_admission_tls import certificates
    HAS_CRYPTO = fixtures.HAS_CRYPTO
except ImportError:
    HAS_CRYPTO = False
    DiscoveryFixture = unittest.TestCase


def ready(backend, *, signed=True):
    server = Server(backend, tools=TOOLS if signed else None, instructions=INSTRUCTIONS if signed else None)
    response = server.handle({'jsonrpc':'2.0','id':1,'method':'initialize',
        'params':{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{}}})
    server.handle({'jsonrpc':'2.0','method':'notifications/initialized'})
    return server, response


def call(server, name, **args):
    return server.handle({'jsonrpc':'2.0','id':2,'method':'tools/call',
        'params':{'name':name,'arguments':args}})


class TaskMCPCoreTests(unittest.TestCase):
    def config(self, root):
        return {'url':'http://127.0.0.1:1','agent_key':str(root/'caller.pem'),
            'authority_public_key':str(root/'owner.pub'),'grant_file':str(root/'caller.grant'),
            'group_id':'existing-group','audience':'original-executor',
            'executor_public_key':str(root/'executor.pub'),'state':str(root/'caller.sqlite3')}

    def test_legacy_and_signed_catalogs_and_instructions_are_explicitly_separate(self):
        legacy, _ = ready(None, signed=False)
        server, initialized = ready(None)
        listing = lambda s:s.handle({'jsonrpc':'2.0','id':3,'method':'tools/list'})['result']['tools']
        self.assertEqual(len(listing(legacy)), 3);self.assertEqual(len(listing(server)), 12)
        self.assertFalse(set(t['name'] for t in listing(legacy)) & set(t['name'] for t in listing(server)))
        self.assertEqual(initialized['result']['capabilities'], {'tools':{'listChanged':False}})
        self.assertIn('not independently authenticated human consent', initialized['result']['instructions'])
        cancel = next(t for t in TOOLS if t['name']=='cancel_signed_task')
        self.assertTrue(cancel['annotations']['destructiveHint'])

    def test_schema_rejects_credential_paths_unknown_fields_ids_and_boolean_pages(self):
        server, _ = ready(None)
        for name, args in [('queue_signed_task',{'task_id':'a'*32,'input':'hello','state':'/tmp/other'}),
                ('submit_signed_task',{'task_id':'a'*32,'request_hash':'f'*64,'confirm_task_id':'a'*32,'url':'https://evil'}),
                ('get_signed_task',{'task_id':'../private'}),('list_signed_tasks',{'limit':True}),
                ('list_signed_tasks',{'after':-1}),('list_signed_tasks',{'limit':'2'}),
                ('list_signed_tasks',{'limit':101}),('signed_task_status',{'grant':'secret'}),('delegate_task',{})]:
            self.assertEqual(call(server,name,**args)['error']['code'], -32602)

    def test_config_requires_absolute_private_paths_and_an_exact_fixed_schema(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder);path = root/'config.json';config = self.config(root)
            path.write_text(json.dumps(config));path.chmod(0o600)
            self.assertEqual(load_config(str(path)), config)
            with self.assertRaises(ValueError):load_config('relative.json')
            for change in ({'url':None},{'state':'relative.sqlite3'},{'token':'secret'},{'agent_key':7}):
                path.write_text(json.dumps(config|change))
                with self.assertRaises(ValueError):load_config(str(path))
            path.write_text(json.dumps({k:v for k,v in config.items() if k!='group_id'}))
            with self.assertRaises(ValueError):load_config(str(path))

    def test_config_rejects_symlinks_fifo_public_permissions_oversize_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder);path = root/'config.json';text = json.dumps(self.config(root))
            path.write_text(text);path.chmod(0o644)
            with self.assertRaises(ValueError):load_config(str(path))
            path.chmod(0o600);link = root/'link';link.symlink_to(path)
            with self.assertRaises(OSError):load_config(str(link))
            fifo = root/'fifo';os.mkfifo(fifo,0o600)
            with self.assertRaises(ValueError):load_config(str(fifo))
            for data in (' '*16385,'{"url":"https://evil",'+text[1:],'[]'):
                path.write_text(data)
                with self.assertRaises(ValueError):load_config(str(path))

    def test_missing_signed_configuration_never_falls_back_to_legacy_or_prints_credentials(self):
        env = {k:v for k,v in os.environ.items() if k!='TAILNET_TASK_MCP_CONFIG'}
        env |= {'TAILNET_REGISTRY_URL':'http://127.0.0.1:1','TAILNET_REGISTRY_TOKEN':'SECRET'*8,'TAILNET_MCP_PEERS':'{}'}
        result = subprocess.run([sys.executable,'-m','tailnet_agents.task_mcp'],env=env,input='',
            capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,1);self.assertEqual(result.stdout,'')
        self.assertIn('private configuration',result.stderr);self.assertNotIn('SECRET',result.stderr)

    def test_sqlite_failures_are_sanitized_tool_errors_and_integer_pages_work(self):
        class Failed:
            def call(self,*args):raise sqlite3.OperationalError('SECRET credential and private path')
        server, _ = ready(Failed());response = call(server,'list_signed_tasks',after=0,limit=2)
        self.assertTrue(response['result']['isError']);self.assertNotIn('SECRET',json.dumps(response))


@unittest.skipUnless(HAS_CRYPTO,'install identity extra')
class SignedTaskMCPTests(DiscoveryFixture):
    echo = fixtures.DurableTaskTests.echo
    open_executor = fixtures.DurableTaskTests.open_executor
    restart = fixtures.DurableTaskTests.restart
    serve_tasks = fixtures.DurableTaskTests.serve_tasks
    client = fixtures.DurableTaskTests.client
    authenticated = fixtures.DurableTaskTests.authenticated
    post = fixtures.DurableTaskTests.post
    denied = fixtures.DurableTaskTests.denied
    wire = operation_fixtures.TaskOperationTests.wire
    queued = operation_fixtures.TaskOperationTests.queued
    uncertain = operation_fixtures.TaskOperationTests.uncertain

    def setUp(self):
        super().setUp()
        self.keys = [self.agent]+[generate_identity(self.root/f'agent-{i}.pem') for i in range(1,4)]
        self.subjects = [identity_id(key.public_key()) for key in self.keys]
        self.permissions = ['join','task.echo']
        self.grants = [issue_grant(self.owner,key.public_key(),self.group,self.permissions if i<3 else ['join'],now=100)
            for i,key in enumerate(self.keys)]
        self.members = {self.subjects[i]:{'permissions':self.permissions if i<3 else ['join'],
            'grant_ids':[verify_grant(grant,self.owner.public_key(),self.group,now=110)['jti']]}
            for i,grant in enumerate(self.grants)}
        self.policy = revise_policy(self.owner,self.policy,self.members,now=102)
        self.node = self.directory(database=str(self.root/'directory.sqlite3'));self.calls = []
        self.executor = self.open_executor();self.url,self.server = self.serve_tasks(self.executor)

    def bridge(self,a=None):
        a = a or self.client()
        server, _ = ready(Backend(a))
        return server,a

    def invoke(self,server,name,**args):
        response = call(server,name,**args)
        self.assertNotIn('error',response,response)
        self.assertFalse(response['result']['isError'],response)
        return response['result']['structuredContent']

    def failed(self,server,name,**args):
        response = call(server,name,**args)
        self.assertTrue(response['result']['isError'],response)
        for grant in self.grants:self.assertNotIn(grant,json.dumps(response))
        return response

    def queue(self,server,mid='a'*32,text='MCP original intent'):
        return self.invoke(server,'queue_signed_task',task_id=mid,input=text)

    def submit(self,server,mid='a'*32):
        p = self.invoke(server,'preview_signed_task',task_id=mid)
        return self.invoke(server,'submit_signed_task',task_id=mid,request_hash=p['request_hash'],confirm_task_id=mid)

    def configuration(self,*,i=0,url=None,state=None,ca=None):
        owner,executor,grant = (self.root/name for name in ('owner.pub','executor.pub',f'grant-{i}'))
        owner.write_text(encode(public_bytes(self.owner.public_key())));executor.write_text(encode(public_bytes(self.keys[2].public_key())))
        grant.write_text(self.grants[i]);grant.chmod(0o600)
        config = {'url':url or self.url,'agent_key':str(self.agent_path if i==0 else self.root/f'agent-{i}.pem'),
            'authority_public_key':str(owner),'executor_public_key':str(executor),'grant_file':str(grant),
            'group_id':self.group,'audience':self.audience,'state':str(state or self.root/'mcp.sqlite3')}
        if ca:config['ca_cert'] = str(ca)
        path = self.root/f'mcp-{i}.json';path.write_text(json.dumps(config));path.chmod(0o600)
        return path,config

    def realtime(self):
        self.now = int(time.time())
        self.grants = [issue_grant(self.owner,key.public_key(),self.group,self.permissions,now=self.now) for key in self.keys]
        self.members = {self.subjects[i]:{'permissions':self.permissions,
            'grant_ids':[verify_grant(grant,self.owner.public_key(),self.group,now=self.now)['jti']]}
            for i,grant in enumerate(self.grants)}
        self.policy = revise_policy(self.owner,self.policy,self.members,now=self.now);self.node.apply_policy(self.policy);self.restart()

    def test_stable_queue_retry_preserves_original_envelope_and_rejects_changed_input(self):
        server,a = self.bridge()
        with patch.object(a.http,'request',side_effect=AssertionError('network')):
            first = self.queue(server);token = a.db.execute('SELECT token FROM task_outbox').fetchone()[0]
            self.now += 20;self.assertEqual(self.queue(server),first)
            self.failed(server,'queue_signed_task',task_id='a'*32,input='changed intent')
        a.close();server,a = self.bridge(self.client())
        self.assertEqual(self.queue(server),first);self.assertEqual(a.db.execute('SELECT token FROM task_outbox').fetchone()[0],token)
        self.assertEqual(a.status(),{'pending':1});self.assertEqual(self.calls,[])

    def test_queue_transaction_failure_never_creates_a_second_intent_on_retry(self):
        server,a = self.bridge()
        a.db.execute("CREATE TRIGGER reject_queue BEFORE INSERT ON task_outbox BEGIN SELECT RAISE(ABORT,'SECRET'); END")
        self.failed(server,'queue_signed_task',task_id='a'*32,input='original')
        self.assertEqual(a.status(),{});a.db.execute('DROP TRIGGER reject_queue')
        self.queue(server,text='original');self.queue(server,text='original')
        self.assertEqual(a.status(),{'pending':1})

    def test_concurrent_stable_queue_requests_share_one_original_intent(self):
        server,a = self.bridge()
        with ThreadPoolExecutor(4) as pool:results = list(pool.map(lambda _:a.queue_once('a'*32,'same intent'),range(4)))
        self.assertTrue(all(r==results[0] for r in results));self.assertEqual(a.status(),{'pending':1})

    def test_submit_confirms_one_original_task_and_leaves_other_pending_work_alone(self):
        server,a = self.bridge();self.queue(server);self.queue(server,'b'*32,'second')
        result = self.submit(server)
        self.assertEqual(result['status'],'completed');self.assertEqual(result['output'],'MCP original intent')
        self.assertEqual(a.status(),{'completed':1,'pending':1});self.assertEqual(self.calls,['MCP original intent'])
        self.assertEqual(self.invoke(server,'list_signed_tasks',after=0,limit=1)['has_more'],True)

    def test_wrong_submit_confirmation_and_hash_never_contact_executor(self):
        server,a = self.bridge();p = self.queue(server)
        with patch.object(a.http,'request',side_effect=AssertionError('network')):
            for fingerprint,confirmation in [('0'*64,'a'*32),(p['request_hash'],'b'*32)]:
                self.failed(server,'submit_signed_task',task_id='a'*32,request_hash=fingerprint,confirm_task_id=confirmation)
        self.assertEqual(a.status(),{'pending':1});self.assertEqual(self.calls,[])

    def test_terminal_submit_retry_returns_verified_local_receipt_without_network(self):
        server,a = self.bridge();self.queue(server);original = self.submit(server)
        with patch.object(a.http,'request',side_effect=AssertionError('network')):
            self.assertEqual(self.submit(server),original)
            self.assertEqual(self.invoke(server,'get_signed_task',task_id='a'*32),original)
        self.assertEqual(self.calls,['MCP original intent'])

    def test_known_running_receipt_is_returned_locally_without_another_submit(self):
        server,a = self.bridge();self.queue(server)
        token = a.db.execute('SELECT token FROM task_outbox').fetchone()[0]
        with patch.object(self.executor,'_run',side_effect=TaskUnavailable('pause')):
            self.denied(lambda:self.wire('submit',token),503)
        with self.node._registry.db:self.node._registry.db.execute("UPDATE durable_tasks SET status='running'")
        original = self.invoke(server,'refresh_signed_task',task_id='a'*32)
        self.assertEqual(original['status'],'running')
        with patch.object(a.http,'request',side_effect=AssertionError('another submission')):
            self.assertEqual(self.submit(server),original)
        self.assertEqual(self.calls,[])

    def test_uncertain_result_and_advisory_reviews_cannot_enable_another_attempt(self):
        a,mid,_ = self.uncertain();server,_ = self.bridge(a)
        p = a.review_preview(mid)
        a.review(mid,p['receipt_hash'],'no_effect_observed','Advisory caller note; result remains uncertain.','b'*32,mid)
        with patch.object(a.http,'request',side_effect=AssertionError('network')):
            self.assertEqual(self.submit(server,mid)['status'],'uncertain')
            notes = self.invoke(server,'list_signed_task_reviews',task_id=mid,limit=1)
        self.assertEqual(notes['task_status'],'uncertain');self.assertEqual(self.calls,[])
        self.assertEqual(call(server,'review_signed_task',task_id=mid)['error']['code'],-32602)

    def test_lost_submit_ack_retries_original_intent_without_another_execution(self):
        server,a = self.bridge();self.queue(server);send = a._request
        def lost(request):send(request);raise URLError('SECRET lost ACK')
        with patch.object(a,'_request',side_effect=lost):
            p = a.submit_preview('a'*32)
            self.failed(server,'submit_signed_task',task_id='a'*32,request_hash=p['request_hash'],confirm_task_id='a'*32)
        self.assertEqual(a.status(),{'pending':1});a.close();server,a = self.bridge(self.client())
        self.assertEqual(self.submit(server)['status'],'completed');self.assertEqual(len(self.calls),1)

    def test_failed_cancel_barrier_survives_refresh_restart_and_mcp_submit(self):
        server,a = self.bridge();self.queue(server)
        token = a.db.execute('SELECT token FROM task_outbox').fetchone()[0]
        with patch.object(self.executor,'_run',side_effect=TaskUnavailable('pause')):
            self.denied(lambda:self.wire('submit',token),503)
        p = a.cancel_preview('a'*32)
        with patch.object(a.http,'request',side_effect=URLError('offline')):
            self.failed(server,'cancel_signed_task',task_id='a'*32,request_hash=p['request_hash'],confirm_task_id='a'*32)
        self.assertEqual(self.invoke(server,'refresh_signed_task',task_id='a'*32)['status'],'queued')
        a.close();server,a = self.bridge(self.client())
        p = a.submit_preview('a'*32);self.assertFalse(p['eligible'])
        with patch.object(a.http,'request',side_effect=AssertionError('resubmission')):
            self.failed(server,'submit_signed_task',task_id='a'*32,request_hash=p['request_hash'],confirm_task_id='a'*32)
        self.assertEqual(self.calls,[])

    def test_cancelled_intent_never_resubmits_and_keeps_original_tombstone(self):
        server,a = self.bridge();self.queue(server)
        p = self.invoke(server,'preview_signed_task_cancel',task_id='a'*32)
        result = self.invoke(server,'cancel_signed_task',task_id='a'*32,request_hash=p['request_hash'],confirm_task_id='a'*32)
        self.assertEqual(result['status'],'cancelled');self.assertTrue(result['cancellation_requested'])
        self.assertEqual(self.submit(server)['status'],'cancelled');self.assertEqual(self.calls,[])

    def test_explicit_archive_frees_active_slot_and_preserves_original_result(self):
        self.restart(capacity=1);server,a = self.bridge();self.queue(server);original = self.submit(server)
        p = self.invoke(server,'preview_signed_task_archive',task_id='a'*32)
        result = self.invoke(server,'archive_signed_task',task_id='a'*32,request_hash=p['request_hash'],
            receipt_hash=p['receipt_hash'],confirm_task_id='a'*32)
        self.assertTrue(result['archived']);self.assertTrue(result['payload_retained'])
        self.queue(server,'b'*32,'new intent');self.submit(server,'b'*32)
        self.assertEqual(self.invoke(server,'refresh_signed_task',task_id='a'*32),original)
        self.assertEqual(len(self.calls),2)

    def test_archive_refuses_uncertain_receipts_without_rewriting_outcome(self):
        a,mid,_ = self.uncertain();server,_ = self.bridge(a)
        p = self.invoke(server,'preview_signed_task_archive',task_id=mid)
        self.assertFalse(p['eligible'])
        self.failed(server,'archive_signed_task',task_id=mid,request_hash=p['request_hash'],receipt_hash=p['receipt_hash'],confirm_task_id=mid)
        self.assertEqual(a.show(mid)['status'],'uncertain');self.assertEqual(self.calls,[])

    def test_current_executor_authorization_gates_submit_and_refresh(self):
        server,a = self.bridge();self.queue(server)
        self.node.revoke(issue_revocation(self.owner,self.group,self.members[self.subjects[2]]['grant_ids'][0]))
        p = a.submit_preview('a'*32)
        self.failed(server,'submit_signed_task',task_id='a'*32,request_hash=p['request_hash'],confirm_task_id='a'*32)
        self.failed(server,'refresh_signed_task',task_id='a'*32)
        self.assertEqual(self.calls,[]);self.assertEqual(a.status(),{'pending':1})

    def test_downloaded_history_survives_expiry_without_granting_remote_access(self):
        server,a = self.bridge();self.queue(server);original = self.submit(server);self.now = 500
        self.assertEqual(self.invoke(server,'get_signed_task',task_id='a'*32),original)
        self.assertEqual(self.submit(server),original)
        self.failed(server,'refresh_signed_task',task_id='a'*32)
        self.assertEqual(self.invoke(server,'signed_task_status')['group_id'],self.group)

    def test_invalid_echo_bytes_and_unknown_local_task_fail_without_network(self):
        server,a = self.bridge()
        with patch.object(a.http,'request',side_effect=AssertionError('network')):
            self.failed(server,'queue_signed_task',task_id='a'*32,input='界'*683)
            self.failed(server,'refresh_signed_task',task_id='f'*32)
        self.assertEqual(a.status(),{});self.assertEqual(self.calls,[])

    def test_receipt_commit_failure_is_sanitized_and_keeps_safe_original_retry(self):
        server,a = self.bridge();self.queue(server)
        a.db.execute("CREATE TRIGGER reject_receipt BEFORE UPDATE ON task_outbox BEGIN SELECT RAISE(ABORT,'SECRET'); END")
        p = a.submit_preview('a'*32)
        self.failed(server,'submit_signed_task',task_id='a'*32,request_hash=p['request_hash'],confirm_task_id='a'*32)
        self.assertEqual(a.status(),{'pending':1});self.assertEqual(len(self.calls),1)
        a.db.execute('DROP TRIGGER reject_receipt');self.submit(server);self.assertEqual(len(self.calls),1)

    def test_two_same_host_mcp_callers_keep_separate_identities_and_results(self):
        sa,a = self.bridge();sb,b = self.bridge(self.client(1))
        self.queue(sa);self.queue(sb,'b'*32,'other caller')
        self.submit(sa);self.submit(sb,'b'*32)
        self.assertNotEqual(a.subject,b.subject)
        self.failed(sb,'get_signed_task',task_id='a'*32)
        self.assertEqual(self.invoke(sa,'signed_task_status')['caller'],self.subjects[0])
        self.assertEqual(self.invoke(sb,'signed_task_status')['caller'],self.subjects[1])
        self.assertEqual(self.node.discover(),[]);self.assertEqual(self.node._policy.current()['members'],self.members)

    def test_private_config_startup_and_local_tools_do_not_contact_network_or_create_groups(self):
        path,_ = self.configuration();before = self.node._registry.db.total_changes
        with patch('tailnet_agents.client.Client.request',side_effect=AssertionError('network')):
            backend = Backend.from_config(str(path));self.addCleanup(backend.close)
            backend.client.clock = lambda:self.now;server,_ = ready(backend)
            self.queue(server);self.invoke(server,'preview_signed_task',task_id='a'*32)
            self.invoke(server,'signed_task_status');self.invoke(server,'list_signed_tasks')
        self.assertEqual(self.node._registry.db.total_changes,before);self.assertEqual(backend.client.group,self.group)

    def test_private_credentials_missing_or_join_only_do_not_create_replacement_state(self):
        for i in (0,3):
            path,config = self.configuration(i=i,state=self.root/f'rejected-{i}.sqlite3')
            if i==0:config['agent_key'] = str(self.root/'missing-original.pem');path.write_text(json.dumps(config))
            with self.assertRaises((OSError,ValueError)):Backend.from_config(str(path))
            self.assertFalse(Path(config['state']).exists())
        path,config = self.configuration();Path(config['grant_file']).chmod(0o644)
        with self.assertRaises(ValueError):Backend.from_config(str(path))

    def test_shared_caller_file_lock_and_pins_prevent_replacement_or_concurrent_cli_use(self):
        a = self.client();mid = a.queue('original CLI intent')['task_id']
        path,config = self.configuration(state=self.root/'caller-0.sqlite3')
        with self.assertRaises(OSError):Backend.from_config(str(path))
        a.close();backend = Backend.from_config(str(path));self.addCleanup(backend.close)
        self.assertEqual(backend.client.show(mid)['state'],'pending');backend.close()
        config['url'] = 'http://127.0.0.1:1';path.write_text(json.dumps(config))
        with self.assertRaises(ValueError):Backend.from_config(str(path))
        a = self.client();self.assertEqual(a.show(mid)['state'],'pending')

    def test_configured_https_executor_validates_ca_and_original_pins(self):
        tls = certificates(self.root);url,_ = self.serve_tasks(self.executor,tls=tls)
        path,_ = self.configuration(url=url,ca=tls['ca'])
        backend = Backend.from_config(str(path));self.addCleanup(backend.close);backend.client.clock = lambda:self.now
        server,_ = ready(backend);self.queue(server);self.assertEqual(self.submit(server)['status'],'completed')

    def test_broken_output_after_queue_commit_keeps_one_stable_intent_for_restart(self):
        server,a = self.bridge()
        class Broken(io.StringIO):
            def write(self,text):raise BrokenPipeError('lost MCP output')
        request = {'jsonrpc':'2.0','id':2,'method':'tools/call','params':{
            'name':'queue_signed_task','arguments':{'task_id':'a'*32,'input':'original'}}}
        with self.assertRaises(BrokenPipeError):serve(server,io.BytesIO((json.dumps(request)+'\n').encode()),Broken())
        token = a.db.execute('SELECT token FROM task_outbox').fetchone()[0];a.close()
        server,a = self.bridge(self.client());self.queue(server,text='original')
        self.assertEqual(a.status(),{'pending':1});self.assertEqual(a.db.execute('SELECT token FROM task_outbox').fetchone()[0],token)

    def process(self,path):
        env = os.environ|{'TAILNET_TASK_MCP_CONFIG':str(path),'TAILNET_REGISTRY_URL':'http://127.0.0.1:1',
            'TAILNET_REGISTRY_TOKEN':'SECRET'*8,'TAILNET_MCP_PEERS':'{}'}
        process = subprocess.Popen([sys.executable,'-m','tailnet_agents.task_mcp'],env=env,
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
        self.addCleanup(lambda:(process.poll() is None and process.terminate(),process.communicate(timeout=10)))
        def rpc(method,params=None,notify=False):
            request = {'jsonrpc':'2.0','method':method}
            if not notify:request['id'] = 7
            if params is not None:request['params'] = params
            process.stdin.write(json.dumps(request)+'\n');process.stdin.flush()
            if notify:return
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout,selectors.EVENT_READ)
                self.assertTrue(selector.select(10),'MCP response timeout')
            line = process.stdout.readline();self.assertTrue(line)
            for grant in self.grants:self.assertNotIn(grant,line)
            self.assertNotIn('PRIVATE KEY',line)
            return json.loads(line)
        initialized = rpc('initialize',{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{}})
        self.assertEqual(initialized['result']['serverInfo']['version'],'0.34.0')
        rpc('notifications/initialized',notify=True)
        def invoke(name,**args):
            response = rpc('tools/call',{'name':name,'arguments':args})
            self.assertNotIn('error',response,response);self.assertFalse(response['result']['isError'],response)
            return response['result']['structuredContent']
        return process,rpc,invoke

    def stop_process(self,process):
        process.stdin.close();process.stdin = None
        stdout,stderr = process.communicate(timeout=10)
        self.assertEqual(process.returncode,0,stderr);self.assertEqual(stdout,'');self.assertEqual(stderr,'')

    def test_real_stdio_process_executes_archives_and_restores_original_identity_and_task(self):
        self.realtime();path,_ = self.configuration();process,rpc,invoke = self.process(path)
        self.assertEqual(len(rpc('tools/list')['result']['tools']),12)
        original = invoke('queue_signed_task',task_id='a'*32,input='real stdio Echo')
        result = invoke('submit_signed_task',task_id='a'*32,request_hash=original['request_hash'],confirm_task_id='a'*32)
        p = invoke('preview_signed_task_archive',task_id='a'*32)
        self.assertTrue(invoke('archive_signed_task',task_id='a'*32,request_hash=p['request_hash'],
            receipt_hash=p['receipt_hash'],confirm_task_id='a'*32)['archived'])
        self.stop_process(process)
        process,_,invoke = self.process(path)
        self.assertEqual(invoke('get_signed_task',task_id='a'*32),result)
        self.assertEqual(invoke('submit_signed_task',task_id='a'*32,request_hash=original['request_hash'],confirm_task_id='a'*32),result)
        self.assertEqual(invoke('signed_task_status')['caller'],self.subjects[0]);self.assertEqual(len(self.calls),1)
        self.stop_process(process)

    def test_real_stdio_queue_retry_after_process_exit_has_one_original_pending_intent(self):
        path,config = self.configuration();process,_,invoke = self.process(path)
        original = invoke('queue_signed_task',task_id='a'*32,input='saved across EOF');self.stop_process(process)
        with sqlite3.connect(config['state']) as db:token = db.execute('SELECT token FROM task_outbox').fetchone()[0]
        process,_,invoke = self.process(path)
        self.assertEqual(invoke('queue_signed_task',task_id='a'*32,input='saved across EOF'),original)
        self.assertEqual(invoke('signed_task_status')['counts'],{'pending':1});self.stop_process(process)
        with sqlite3.connect(config['state']) as db:self.assertEqual(db.execute('SELECT token FROM task_outbox').fetchone()[0],token)
        self.assertEqual(self.calls,[])


if __name__ == '__main__':unittest.main()
