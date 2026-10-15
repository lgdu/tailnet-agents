"""Signed simulated tasks: durable identity, crash uncertainty and caller recovery."""
import copy
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tailnet_agents.admission_server import AdmissionHTTPServer, handler, transport_config
    from tailnet_agents.client import Client
    from tailnet_agents.durable_tasks import (RESULT_TYPE, TASK_TYPE, TaskExecutor, TaskUnavailable,
        digest, make_task, verify_task, verify_receipt)
    from tailnet_agents.group_policy import revise_policy
    from tailnet_agents.identity import (AdmissionError, encode, generate_identity, identity_id, issue_grant,
        prove_possession, public_bytes, sign, verify, verify_grant)
    from tailnet_agents.task_client import TaskClient
    from tailnet_agents.verified_directory import VerifiedDirectory, issue_revocation
    from tests.test_discovery import DiscoveryFixture
    from tests.test_admission_tls import certificates
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    DiscoveryFixture = unittest.TestCase


@unittest.skipUnless(HAS_CRYPTO, 'install identity extra')
class DurableTaskTests(DiscoveryFixture):
    def setUp(self):
        super().setUp()
        self.keys = [self.agent] + [generate_identity(self.root/f'agent-{i}.pem') for i in range(1,4)]
        self.subjects = [identity_id(key.public_key()) for key in self.keys]
        self.permissions = ['join','task.echo']
        self.grants = [issue_grant(self.owner,key.public_key(),self.group,self.permissions if i<3 else ['join'],now=100) for i,key in enumerate(self.keys)]
        self.members = {self.subjects[i]: {'permissions':self.permissions if i<3 else ['join'],
            'grant_ids':[verify_grant(grant,self.owner.public_key(),self.group,now=110)['jti']]} for i,grant in enumerate(self.grants)}
        self.policy = revise_policy(self.owner,self.policy,self.members,now=102)
        self.node = self.directory(database=str(self.root/'directory.sqlite3'))
        self.calls = []
        self.executor = self.open_executor()
        self.url,self.server = self.serve_tasks(self.executor)

    def echo(self, text):
        self.calls.append(text)
        return text

    def open_executor(self, **options):
        executor = TaskExecutor(self.node,self.keys[2],self.grants[2],adapter=options.pop('adapter',self.echo),**options)
        self.addCleanup(executor.close)
        return executor

    def restart(self, **options):
        self.executor.close()
        self.executor = self.open_executor(**options)
        self.server.RequestHandlerClass = handler(self.node,'r'*32,task_executor=self.executor)

    def serve_tasks(self, executor=None, *, tls=None, node=None):
        allowed,context = (None,None) if tls is None else transport_config('127.0.0.1',tls['cert'],tls['key'],['localhost','127.0.0.1'])
        scheme = 'http' if tls is None else 'https'
        server = AdmissionHTTPServer(('127.0.0.1',0),handler(node or self.node,'r'*32,allowed,scheme,task_executor=executor),context)
        thread = threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(lambda: (server.shutdown(),server.server_close(),thread.join()))
        return f'{scheme}://{"localhost" if tls else "127.0.0.1"}:{server.server_port}',server

    def client(self, i=0, *, state=None, url=None, **options):
        client = TaskClient(url or self.url,self.keys[i],self.owner.public_key(),self.grants[i],self.group,
            self.audience,self.keys[2].public_key(),state or self.root/f'caller-{i}.sqlite3',clock=lambda:self.now,**options)
        self.addCleanup(client.close)
        return client

    def request(self, i=0, **options):
        return {'operation':'submit','task':make_task(self.keys[i],self.owner.public_key(),self.group,self.audience,self.subjects[2],
            'Echo task',now=self.now,**options)}

    def authenticated(self, request, i=0, **changes):
        challenge = Client(self.url,'').request('/v1/task-challenges',{'request':request})
        return {'request':request,'grant':self.grants[i],'public_key':encode(public_bytes(self.keys[i].public_key())),
            'nonce':challenge['nonce'],'proof':prove_possession(self.keys[i],self.grants[i],challenge['nonce'],self.audience,context=challenge['context'])} | changes

    def post(self,payload):return Client(self.url,'').request('/v1/agent-tasks',payload)

    def denied(self,action,code=403):
        with self.assertRaises(HTTPError) as caught:action()
        self.assertEqual(caught.exception.code,code)
        return caught.exception

    def count(self):return self.node._registry.db.execute('SELECT COUNT(*) FROM durable_tasks').fetchone()[0]

    def receipt(self,response):return verify(response['receipt'],self.keys[2].public_key(),RESULT_TYPE)

    def revise(self,members=None,*,dissolve=False):
        self.policy = revise_policy(self.owner,self.policy,self.members if members is None else members,now=int(self.now),dissolve=dissolve)
        self.node.apply_policy(self.policy)

    def test_explicit_opt_in_and_existing_policy_and_executor_identity_required(self):
        url,_ = self.serve_tasks()
        self.denied(lambda:Client(url,'r'*32).request('/v1/task-challenges',{'request':self.request()}),404)
        empty = VerifiedDirectory(self.owner.public_key(),self.group,self.audience)
        self.addCleanup(empty.close)
        with self.assertRaises(ValueError):TaskExecutor(empty,self.keys[2],self.grants[2])
        missing = VerifiedDirectory(self.owner.public_key(),self.group,self.audience,require_policy=True,clock=lambda:self.now)
        self.addCleanup(missing.close)
        executor = TaskExecutor(missing,self.keys[2],self.grants[2]);self.addCleanup(executor.close)
        req = self.request();ch = executor.challenge(req)
        proof = prove_possession(self.agent,self.grants[0],ch['nonce'],self.audience,context=ch['context'])
        with self.assertRaises(AdmissionError):executor.execute(req,self.grants[0],self.agent.public_key(),proof,ch['nonce'])
        self.assertIsNone(missing._policy.current());self.assertEqual(self.calls,[])
        with self.assertRaises(AdmissionError):TaskExecutor(missing,self.owner,self.grants[2])

    def test_two_same_host_callers_keep_separate_task_identity_and_private_results(self):
        a,b = self.client(),self.client(1)
        ma,mb = a.queue('same input')['task_id'],b.queue('same input')['task_id']
        self.assertNotEqual(ma,mb)
        for caller in (a,b):
            self.assertEqual(caller.flush()[0]['status'],'completed')
            self.assertEqual(caller.status(),{'completed':1})
        self.denied(lambda:self.post(self.authenticated({'operation':'get','task_id':ma},1)),404)
        self.assertEqual(a.refresh(ma)['output'],'same input')
        self.assertEqual(self.calls,['same input','same input'])
        self.assertEqual(self.node.discover(),[])
        self.assertEqual(self.node._policy.current()['members'],self.members)
        self.assertEqual(self.node._registry.db.execute('SELECT COUNT(*) FROM admission_grants').fetchone()[0],0)

    def test_directory_bearer_and_join_only_grants_cannot_run_or_read_tasks(self):
        self.denied(lambda:Client(self.url,'r'*32).request('/v1/agent-tasks',{'request':self.request()}),400)
        for req in [self.request(3),{'operation':'get','task_id':'a'*32}]:
            self.denied(lambda:self.post(self.authenticated(req,3)))
        self.assertEqual(self.calls,[]);self.assertEqual(self.count(),0)

    def test_foreign_unapproved_grants_and_subject_key_substitution_are_rejected(self):
        payload = self.authenticated(self.request())
        grants = [issue_grant(self.owner,self.agent.public_key(),self.group,self.permissions,now=100),
            issue_grant(Ed25519PrivateKey.generate(),self.agent.public_key(),self.group,self.permissions,now=100),
            issue_grant(self.owner,self.agent.public_key(),'foreign',self.permissions,now=100),self.grants[1]]
        for grant in grants:self.denied(lambda:self.post(payload | {'grant':grant}))
        self.denied(lambda:self.post(payload | {'public_key':encode(public_bytes(self.keys[1].public_key()))}))
        self.assertEqual(self.count(),0)

    def test_signed_task_binds_owner_group_audience_caller_executor_and_kind(self):
        req = self.request();claim = verify(req['task'],self.agent.public_key(),TASK_TYPE)
        for change in [{'owner':self.subjects[1]},{'group_id':'foreign'},{'audience':'foreign'},
            {'caller':self.subjects[1]},{'executor':self.subjects[1]},{'kind':'shell'},{'version':True},
            {'created_at':self.now+31},{'created_at':True},{'task_id':'bad'},{'extra':1}]:
            bad = req | {'task':sign(self.agent,claim | change,TASK_TYPE)}
            self.denied(lambda:self.post(self.authenticated(bad)))
        self.assertEqual(self.calls,[])

    def test_single_use_proof_binds_full_task_and_get_operation(self):
        payload = self.authenticated(self.request())
        first = self.receipt(self.post(payload));self.assertEqual(first['status'],'completed')
        self.denied(lambda:self.post(payload))
        get = self.authenticated({'operation':'get','task_id':first['task_id']})
        self.denied(lambda:self.post(get | {'request':{'operation':'get','task_id':'a'*32}}))
        self.denied(lambda:self.post(get | {'request':self.request()}))
        self.assertEqual(self.receipt(self.post(get))['status'],'completed')
        self.denied(lambda:self.post(get))
        self.assertEqual(len(self.calls),1)

    def test_expired_proof_and_strict_request_bounds_never_invoke_adapter(self):
        payload = self.authenticated(self.request());self.now += 31
        self.denied(lambda:self.post(payload))
        for req in [{'operation':'get','task_id':True},{'operation':'get','task_id':'a'*32,'extra':1},
            {'operation':'submit','task':[]},{'operation':'execute'},{'operation':'submit','task':'x'*16385}]:
            self.denied(lambda:Client(self.url,'').request('/v1/task-challenges',{'request':req}),400)
        a = self.client()
        for text in ['', 'x'*2049,'中'*683]:
            with self.assertRaises(ValueError):a.queue(text)
        a.queue('🙂'*512);self.assertEqual(a.flush()[0]['output'],'🙂'*512)
        self.assertEqual(len(self.calls),1)

    def test_immutable_task_id_deduplicates_but_changed_input_or_caller_conflicts(self):
        req = self.request(identifier='a'*32)
        first = self.post(self.authenticated(req));second = self.post(self.authenticated(req))
        self.assertEqual(first,second)
        claim = verify(req['task'],self.agent.public_key(),TASK_TYPE)
        changed = req | {'task':sign(self.agent,claim | {'input':'changed'},TASK_TYPE)}
        self.denied(lambda:self.post(self.authenticated(changed)),409)
        self.denied(lambda:self.post(self.authenticated(self.request(1,identifier='a'*32),1)),409)
        self.assertEqual(self.count(),1);self.assertEqual(self.calls,['Echo task'])

    def test_capacity_never_evicts_deduplication_and_retains_completed_receipts(self):
        self.restart(capacity=1)
        req = self.request();first = self.post(self.authenticated(req))
        self.denied(lambda:self.post(self.authenticated(self.request())),429)
        self.assertEqual(self.post(self.authenticated(req)),first)
        self.restart(capacity=1)
        self.assertEqual(self.post(self.authenticated(req)),first)
        self.assertEqual(len(self.calls),1)

    def test_caller_expiry_revocation_and_removal_gate_new_work_and_result_reads(self):
        a = self.client();mid = a.queue('saved')['task_id'];a.flush()
        self.node.revoke(issue_revocation(self.owner,self.group,self.members[self.subjects[0]]['grant_ids'][0]))
        self.denied(lambda:a.refresh(mid))
        a.queue('must remain pending');self.denied(lambda:a.flush())
        self.assertEqual(len(self.calls),1)
        self.now = 4000
        with self.assertRaises(AdmissionError):a.flush()

    def test_stale_policy_and_dissolution_stop_execution_without_history_loss(self):
        a = self.client();mid = a.queue('retained')['task_id'];a.flush()
        self.now = 403;self.denied(lambda:a.refresh(mid))
        a.queue('blocked');self.denied(lambda:a.flush())
        self.now = 111;self.revise(dissolve=True)
        self.denied(lambda:a.refresh(mid));self.denied(lambda:a.flush())
        self.restart();self.denied(lambda:a.flush())
        self.assertEqual(self.count(),1);self.assertEqual(len(self.calls),1)

    def test_executor_grant_and_membership_are_independently_required(self):
        a = self.client();a.queue('blocked')
        self.node.revoke(issue_revocation(self.owner,self.group,self.members[self.subjects[2]]['grant_ids'][0]))
        self.denied(lambda:a.flush())
        self.assertEqual(self.calls,[]);self.assertEqual(self.count(),0)

    def test_loss_of_authorization_between_queue_and_claim_keeps_unstarted_task(self):
        original = self.executor._run
        def revoke_then_run(mid,claim,grant):
            self.node.revoke(issue_revocation(self.owner,self.group,self.members[self.subjects[0]]['grant_ids'][0]))
            return original(mid,claim,grant)
        a = self.client();a.queue('no side effect')
        with patch.object(self.executor,'_run',side_effect=revoke_then_run):self.denied(lambda:a.flush())
        self.assertEqual(self.count(),1);self.assertEqual(self.calls,[])
        self.assertEqual(self.node._registry.db.execute('SELECT status FROM durable_tasks').fetchone()[0],'queued')

    def test_revocation_during_execution_keeps_result_but_does_not_return_it(self):
        def effect(text):
            self.calls.append(text)
            self.node.revoke(issue_revocation(self.owner,self.group,self.members[self.subjects[0]]['grant_ids'][0]))
            return text
        self.restart(adapter=effect)
        a = self.client();a.queue('committed but no access');self.denied(lambda:a.flush())
        self.assertEqual(self.node._registry.db.execute('SELECT status FROM durable_tasks').fetchone()[0],'completed')
        self.assertEqual(a.status(),{'pending':1})
        self.denied(lambda:a.flush());self.assertEqual(len(self.calls),1)

    def test_lost_ack_and_both_end_restarts_return_original_result_without_execution(self):
        a = self.client();mid = a.queue('exactly one call')['task_id'];original = a.http.request
        def lost_ack(path,body=None):
            result = original(path,body)
            if path=='/v1/agent-tasks':raise URLError('lost after commit')
            return result
        with patch.object(a.http,'request',side_effect=lost_ack),self.assertRaises(URLError):a.flush()
        self.assertEqual(a.status(),{'pending':1});self.assertEqual(len(self.calls),1);a.close()
        self.executor.close();self.node.close()
        self.node = VerifiedDirectory(self.owner.public_key(),self.group,self.audience,require_policy=True,
            database=str(self.root/'directory.sqlite3'),clock=lambda:self.now)
        self.addCleanup(self.node.close);self.executor = self.open_executor()
        self.server.RequestHandlerClass = handler(self.node,'r'*32,task_executor=self.executor)
        a = self.client();result = a.flush()[0]
        self.assertEqual(result['task_id'],mid);self.assertEqual(result['output'],'exactly one call')
        self.assertEqual(a.flush(),[]);self.assertEqual(len(self.calls),1)
        self.assertEqual(a.show(mid),a.refresh(mid))

    def test_queued_restart_never_executes_until_explicit_fresh_submission(self):
        a = self.client();mid = a.queue('queued only')['task_id']
        with patch.object(self.executor,'_run',side_effect=TaskUnavailable('simulated pre-claim stop')):
            self.denied(lambda:a.flush(),503)
        self.restart();self.assertEqual(self.calls,[])
        result = a.refresh(mid);self.assertEqual(result['status'],'queued');self.assertEqual(self.calls,[])
        # Recovery queries never execute. Explicit retry of the original signed request does.
        result = a.flush()[0]
        self.assertEqual(result['status'],'completed');self.assertEqual(len(self.calls),1)

    def test_real_process_crash_after_side_effect_becomes_uncertain_and_never_reexecutes(self):
        a = self.client();mid = a.queue('crash test')['task_id']
        token = a.db.execute('SELECT token FROM task_outbox').fetchone()[0]
        self.executor.close()
        owner_file = self.root/'owner.pub';owner_file.write_text(encode(public_bytes(self.owner.public_key())))
        marker = self.root/'side-effect.txt'
        script = '''import json,os,sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from tailnet_agents.identity import decode,load_identity,prove_possession
from tailnet_agents.verified_directory import VerifiedDirectory
from tailnet_agents.durable_tasks import TaskExecutor
cfg=json.load(sys.stdin)
owner=Ed25519PublicKey.from_public_bytes(decode(Path(sys.argv[1]).read_text()))
node=VerifiedDirectory(owner,cfg['group'],cfg['audience'],database=sys.argv[2],require_policy=True,clock=lambda:110)
def effect(text):
 with open(sys.argv[5],'a') as output:output.write('effect\\n');output.flush();os.fsync(output.fileno())
 os._exit(73)
executor=TaskExecutor(node,load_identity(sys.argv[3]),cfg['executor_grant'],adapter=effect)
request={'operation':'submit','task':cfg['token']}
challenge=executor.challenge(request)
key=load_identity(sys.argv[4])
proof=prove_possession(key,cfg['caller_grant'],challenge['nonce'],cfg['audience'],context=challenge['context'])
executor.execute(request,cfg['caller_grant'],key.public_key(),proof,challenge['nonce'])
'''
        result = subprocess.run([sys.executable,'-c',script,str(owner_file),str(self.root/'directory.sqlite3'),
            str(self.root/'agent-2.pem'),str(self.agent_path),str(marker)],input=json.dumps({'group':self.group,'audience':self.audience,
            'executor_grant':self.grants[2],'caller_grant':self.grants[0],'token':token}),capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,73,result.stderr)
        self.assertEqual(marker.read_text(),'effect\n')
        self.assertEqual(self.node._registry.db.execute('SELECT status FROM durable_tasks').fetchone()[0],'running')
        self.restart();self.assertEqual(self.calls,[])
        receipt = a.flush()[0]
        self.assertEqual(receipt['task_id'],mid);self.assertEqual(receipt['status'],'uncertain')
        self.assertEqual(receipt['error'],'execution_interrupted');self.assertIsNone(receipt['output'])
        self.restart();self.assertEqual(a.refresh(mid),receipt)
        self.assertEqual(a.flush(),[]);self.assertEqual(marker.read_text(),'effect\n');self.assertEqual(self.calls,[])

    def test_failed_adapter_is_terminal_sanitized_and_not_retried(self):
        def failure(text):self.calls.append(text);raise RuntimeError('SECRET prompt/key')
        self.restart(adapter=failure)
        a = self.client();mid = a.queue('fail once')['task_id'];result = a.flush()[0]
        self.assertEqual(result['status'],'failed');self.assertEqual(result['error'],'execution_failed')
        self.assertNotIn('SECRET',json.dumps(result));self.restart(adapter=failure)
        self.assertEqual(a.refresh(mid),result);self.assertEqual(a.flush(),[]);self.assertEqual(len(self.calls),1)

    def test_invalid_adapter_output_is_failed_without_leaking_output(self):
        self.restart(adapter=lambda _: 'x'*2049)
        a = self.client();a.queue('bounded');result = a.flush()[0]
        self.assertEqual(result['status'],'failed');self.assertIsNone(result['output'])

    def test_insert_or_running_commit_failure_never_invokes_adapter(self):
        a = self.client();a.queue('still safe');db = self.node._registry.db
        db.execute("CREATE TRIGGER reject_task BEFORE INSERT ON durable_tasks BEGIN SELECT RAISE(ABORT,'test'); END")
        self.denied(lambda:a.flush(),503);self.assertEqual(self.calls,[]);self.assertEqual(self.count(),0)
        db.execute('DROP TRIGGER reject_task')
        db.execute("CREATE TRIGGER reject_running BEFORE UPDATE ON durable_tasks WHEN NEW.status='running' BEGIN SELECT RAISE(ABORT,'test'); END")
        self.denied(lambda:a.flush(),503);self.assertEqual(self.calls,[])
        self.assertEqual(db.execute('SELECT status FROM durable_tasks').fetchone()[0],'queued')
        db.execute('DROP TRIGGER reject_running');self.assertEqual(a.flush()[0]['status'],'completed')

    def test_result_commit_failure_preserves_running_then_uncertain_without_retry(self):
        a = self.client();mid = a.queue('one effect')['task_id'];db = self.node._registry.db
        db.execute("CREATE TRIGGER reject_result BEFORE UPDATE ON durable_tasks WHEN NEW.status='completed' BEGIN SELECT RAISE(ABORT,'test'); END")
        self.denied(lambda:a.flush(),503);self.assertEqual(len(self.calls),1)
        self.assertEqual(a.flush()[0]['status'],'running');self.assertEqual(len(self.calls),1)
        self.restart();self.assertEqual(a.refresh(mid)['status'],'uncertain');self.assertEqual(len(self.calls),1)

    def test_caller_receipt_commit_failure_preserves_pending_and_safe_retry(self):
        a = self.client();a.queue('one effect')
        a.db.execute("CREATE TRIGGER reject_receipt BEFORE UPDATE ON task_outbox BEGIN SELECT RAISE(ABORT,'test'); END")
        with self.assertRaises(sqlite3.Error):a.flush()
        self.assertEqual(a.status(),{'pending':1});self.assertEqual(len(self.calls),1)
        a.db.execute('DROP TRIGGER reject_receipt');self.assertEqual(a.flush()[0]['status'],'completed')
        self.assertEqual(len(self.calls),1)

    def test_concurrent_duplicate_submission_invokes_adapter_once_outside_directory_lock(self):
        started,release = threading.Event(),threading.Event()
        def blocked(text):self.calls.append(text);started.set();release.wait(5);return text
        self.restart(adapter=blocked);req = self.request();results=[];errors=[]
        def submit():
            try:results.append(self.receipt(self.post(self.authenticated(req))))
            except Exception as error:errors.append(error)
        thread = threading.Thread(target=submit);thread.start()
        try:
            self.assertTrue(started.wait(3))
            self.assertEqual(self.node.policy_status()['state'],'fresh')
            self.assertEqual(self.receipt(self.post(self.authenticated(req)))['status'],'running')
            self.assertEqual(len(self.calls),1)
        finally:release.set();thread.join(5)
        self.assertFalse(thread.is_alive());self.assertEqual(errors,[]);self.assertEqual(results[0]['status'],'completed')

    def test_executor_shutdown_drains_inflight_execution_and_rejects_new_operations(self):
        started,release = threading.Event(),threading.Event()
        def blocked(text):started.set();release.wait(5);return text
        self.restart(adapter=blocked);a = self.client();a.queue('drain');results=[]
        work = threading.Thread(target=lambda:results.extend(a.flush()));work.start()
        self.assertTrue(started.wait(3))
        stopped = threading.Event()
        closer = threading.Thread(target=lambda:(self.executor.close(),stopped.set()));closer.start()
        try:
            with self.executor.condition:self.assertTrue(self.executor.condition.wait_for(lambda:self.executor.closing,timeout=3))
            self.denied(lambda:Client(self.url,'').request('/v1/task-challenges',{'request':self.request()}),503)
            self.assertFalse(stopped.is_set())
        finally:release.set();work.join(5);closer.join(5)
        self.assertTrue(stopped.is_set());self.assertEqual(results[0]['status'],'completed')

    def test_executor_lock_and_persisted_identity_audience_prevent_replacement(self):
        with self.assertRaises(TaskUnavailable):self.open_executor()
        self.executor.close()
        with self.assertRaises(AdmissionError):TaskExecutor(self.node,self.keys[1],self.grants[1])
        other = VerifiedDirectory(self.owner.public_key(),self.group,'other-audience',require_policy=True,
            database=str(self.root/'directory.sqlite3'),clock=lambda:self.now)
        self.addCleanup(other.close)
        with self.assertRaises(AdmissionError):TaskExecutor(other,self.keys[2],self.grants[2])
        self.restart()
        other2 = VerifiedDirectory(self.owner.public_key(),self.group,self.audience,require_policy=True,
            database=str(self.root/'directory.sqlite3'),clock=lambda:self.now)
        self.addCleanup(other2.close)
        with self.assertRaises(OSError):TaskExecutor(other2,self.keys[2],self.grants[2])

    def test_caller_state_pins_original_identity_executor_origin_group_and_audience(self):
        a = self.client();state = self.root/'caller-0.sqlite3';a.close()
        cases=[(self.url,self.keys[1],self.grants[1],self.group,self.audience,self.keys[2].public_key()),
            ('https://other.example',self.agent,self.grants[0],self.group,self.audience,self.keys[2].public_key()),
            (self.url,self.agent,self.grants[0],self.group,'other',self.keys[2].public_key()),
            (self.url,self.agent,self.grants[0],self.group,self.audience,self.keys[1].public_key())]
        for url,key,grant,group,audience,executor in cases:
            with self.assertRaises(AdmissionError):TaskClient(url,key,self.owner.public_key(),grant,group,audience,executor,state)
        grant = issue_grant(self.owner,self.agent.public_key(),'foreign',self.permissions,now=100)
        with self.assertRaises(AdmissionError):TaskClient(self.url,self.agent,self.owner.public_key(),grant,'foreign',self.audience,self.keys[2].public_key(),state)
        self.assertEqual(self.client().subject,self.subjects[0])

    def test_caller_state_private_file_and_exclusive_lock_are_required(self):
        a = self.client();state=self.root/'caller-0.sqlite3'
        self.assertEqual(state.stat().st_mode & 0o777,0o600)
        with self.assertRaises(OSError):self.client()
        link=self.root/'link.sqlite3';link.symlink_to(state)
        with self.assertRaises(OSError):self.client(state=link)
        a.close();state.chmod(0o644)
        with self.assertRaises(ValueError):self.client()
        state.chmod(0o600)

    def test_manual_caller_and_executor_grant_renewal_resumes_original_pending_task(self):
        a = self.client();mid=a.queue('old original task')['task_id'];a.close();self.executor.close();self.now=4000
        for i in (0,2):
            self.grants[i]=issue_grant(self.owner,self.keys[i].public_key(),self.group,self.permissions,now=self.now)
            self.members[self.subjects[i]]['grant_ids']=[verify_grant(self.grants[i],self.owner.public_key(),self.group,now=self.now)['jti']]
        self.revise();self.restart();a=self.client()
        self.assertEqual(a.flush()[0]['task_id'],mid);self.assertEqual(len(self.calls),1)

    def test_offline_queue_and_flush_bound_keep_original_order(self):
        a=self.client()
        with patch.object(a.http,'request',side_effect=URLError('offline')):
            ids=[a.queue(str(i))['task_id'] for i in range(3)]
            with self.assertRaises(URLError):a.flush()
        self.assertEqual(a.status(),{'pending':3})
        self.assertEqual(a.flush(limit=1)[0]['task_id'],ids[0])
        a.close();a=self.client()
        self.assertEqual([r['task_id'] for r in a.flush()],ids[1:]);self.assertEqual(self.calls,['0','1','2'])

    def test_wrong_challenge_is_rejected_before_signing_or_posting_proof(self):
        a=self.client();a.queue('pending')
        with patch.object(a.http,'request',return_value={'nonce':'n','context':'wrong'}) as network,self.assertRaises(ValueError):a.flush()
        self.assertEqual(network.call_count,1);self.assertEqual(a.status(),{'pending':1})

    def test_caller_rejects_tampered_wrong_executor_and_foreign_receipts_atomically(self):
        a=self.client();mid=a.queue('pending')['task_id']
        token=a.db.execute('SELECT token FROM task_outbox').fetchone()[0]
        good=self.post(self.authenticated({'operation':'submit','task':token}));claim=self.receipt(good)
        responses=[{'receipt':'bad'},{'receipt':sign(self.keys[1],claim,RESULT_TYPE)}]
        for change in [{'owner':self.subjects[1]},{'group_id':'foreign'},{'audience':'foreign'},{'executor':self.subjects[1]},
            {'caller':self.subjects[1]},{'task_id':'a'*32},{'request_hash':'bad'},{'status':'done'},{'output':None},
            {'version':True},{'issued_at':True},{'error':'SECRET'}]:
            responses.append({'receipt':sign(self.keys[2],claim | change,RESULT_TYPE)})
        for response in responses:
            with patch.object(a,'_request',return_value=response),self.assertRaises(ValueError):a.flush()
            self.assertEqual(a.status(),{'pending':1})
        self.assertEqual(a.flush()[0]['task_id'],mid);self.assertEqual(len(self.calls),1)

    def test_saved_terminal_receipt_cannot_be_replaced_by_signed_older_or_conflicting_state(self):
        a=self.client();mid=a.queue('stable')['task_id'];result=a.flush()[0]
        for change in [{'status':'running','output':None},{'status':'completed','output':'different'}]:
            with patch.object(a,'_request',return_value={'receipt':sign(self.keys[2],result | change,RESULT_TYPE)}),self.assertRaises(ValueError):a.refresh(mid)
            self.assertEqual(a.show(mid),result)

    def test_https_ca_hostname_and_nonloopback_http_checks_apply_to_tasks(self):
        tls=certificates(self.root);url,_=self.serve_tasks(self.executor,tls=tls)
        a=self.client(url=url,state=self.root/'tls.sqlite3',ca_file=tls['ca']);a.queue('TLS')
        self.assertEqual(a.flush()[0]['output'],'TLS')
        b=self.client(1,url=url,state=self.root/'untrusted.sqlite3')
        b.queue('no CA')
        with self.assertRaises(URLError):b.flush()
        c=self.client(1,url=url.replace('localhost','127.0.0.1'),state=self.root/'wrong-host.sqlite3',ca_file=tls['ca']);c.queue('wrong host')
        with self.assertRaises(URLError):c.flush()
        with self.assertRaises(ValueError):self.client(url='http://100.64.0.1:8771',state=self.root/'bad.sqlite3')

    def test_multiple_executors_on_same_ip_use_independent_keys_databases_and_clients(self):
        node=VerifiedDirectory(self.owner.public_key(),self.group,self.audience,require_policy=True,
            database=str(self.root/'second-executor.sqlite3'),clock=lambda:self.now)
        self.addCleanup(node.close);node.apply_policy(self.policy)
        executor=TaskExecutor(node,self.keys[1],self.grants[1]);self.addCleanup(executor.close)
        url,_=self.serve_tasks(executor,node=node)
        client=TaskClient(url,self.agent,self.owner.public_key(),self.grants[0],self.group,self.audience,
            self.keys[1].public_key(),self.root/'second-caller.sqlite3',clock=lambda:self.now)
        self.addCleanup(client.close)
        a=self.client();a.queue('explicit task a');client.queue('explicit task b')
        self.assertEqual(a.flush()[0]['executor'],self.subjects[2])
        self.assertEqual(client.flush()[0]['executor'],self.subjects[1])
        req=self.request();challenge=Client(url,'').request('/v1/task-challenges',{'request':req})
        proof=prove_possession(self.agent,self.grants[0],challenge['nonce'],self.audience,context=challenge['context'])
        self.denied(lambda:Client(url,'').request('/v1/agent-tasks',{'request':req,'grant':self.grants[0],
            'public_key':encode(public_bytes(self.agent.public_key())),'nonce':challenge['nonce'],'proof':proof}))
        self.assertEqual(self.count(),1)
        self.assertEqual(node._registry.db.execute('SELECT COUNT(*) FROM durable_tasks').fetchone()[0],1)

    def test_real_service_and_task_client_clis_persist_original_task_and_signed_result(self):
        now=int(time.time());grants=[issue_grant(self.owner,key.public_key(),self.group,self.permissions,now=now) for key in self.keys[:3]]
        members={self.subjects[i]:{'permissions':self.permissions,'grant_ids':[verify_grant(grant,self.owner.public_key(),self.group,now=now)['jti']]} for i,grant in enumerate(grants)}
        policy=revise_policy(self.owner,self.policy,members,now=now)
        authority=self.root/'owner.pub';authority.write_text(encode(public_bytes(self.owner.public_key())))
        executor_pub=self.root/'executor.pub';executor_pub.write_text(encode(public_bytes(self.keys[2].public_key())))
        policy_file=self.root/'policy.jwt';policy_file.write_text(policy)
        for i,grant in enumerate(grants):(self.root/f'grant-{i}').write_text(grant)
        text=self.root/'input.txt';text.write_text('CLI Echo')
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        command=[sys.executable,'-m','tailnet_agents.admission_server','--authority-public-key',str(authority),'--group-id',self.group,
            '--audience',self.audience,'--database',str(self.root/'cli-directory.sqlite3'),'--policy-file',str(policy_file),
            '--tasks','--task-agent-key',str(self.root/'agent-2.pem'),'--task-grant-file',str(self.root/'grant-2'),'--port',str(port)]
        env=os.environ | {'TAILNET_VERIFIED_READ_TOKEN':'r'*32}
        service=subprocess.Popen(command,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.addCleanup(lambda:(service.poll() is None and service.terminate(),service.communicate(timeout=10)))
        url=f'http://127.0.0.1:{port}';deadline=time.monotonic()+10
        while True:
            try:Client(url,'').request('/healthz');break
            except URLError:
                if time.monotonic()>deadline:self.fail('task service did not start')
                time.sleep(.02)
        def run(*operation,success=True):
            result=subprocess.run([sys.executable,'-m','tailnet_agents.task_client','--url',url,'--agent-key',str(self.agent_path),
                '--authority-public-key',str(authority),'--grant-file',str(self.root/'grant-0'),'--group-id',self.group,'--audience',self.audience,
                '--executor-public-key',str(executor_pub),'--state',str(self.root/'cli-caller.sqlite3'),*operation],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0 if success else 1,result.stderr)
            for grant in grants:self.assertNotIn(grant,result.stdout+result.stderr)
            self.assertNotIn('PRIVATE KEY',result.stdout+result.stderr)
            return json.loads(result.stdout) if success else result
        mid=run('queue','--input-file',str(text))['task_id'];self.assertEqual(run('status'),{'pending':1})
        receipt=run('flush')[0];self.assertEqual(receipt['output'],'CLI Echo')
        self.assertEqual(run('refresh','--task-id',mid),receipt);self.assertEqual(run('show','--task-id',mid),receipt)
        self.assertEqual(run('flush'),[])
        run('refresh','--task-id','a'*32,success=False)
        invalid=subprocess.run(command[:-2]+['--port','0','--task-agent-key',str(self.agent_path)],env=env,capture_output=True,text=True,timeout=10)
        self.assertNotEqual(invalid.returncode,0)
        for grant in grants:self.assertNotIn(grant,invalid.stderr)
