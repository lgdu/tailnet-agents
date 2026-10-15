"""Pre-execution cancellation, durable caller barriers and advisory local reviews."""
from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import URLError
import test_durable_tasks as fixtures

try:
    from tailnet_agents.durable_tasks import (TaskExecutor,TaskUnavailable,RESULT_TYPE,digest,verify_receipt)
    from tailnet_agents.task_client import TaskClient
    from tailnet_agents import task_operations as operations
    from tailnet_agents.identity import (AdmissionError,encode,identity_id,generate_identity,issue_grant,public_bytes,sign,verify,verify_grant)
    from tailnet_agents.group_policy import revise_policy
    from tailnet_agents.verified_directory import VerifiedDirectory,issue_revocation
    from tailnet_agents.admission_server import handler
    from tests.test_discovery import DiscoveryFixture
    from tests.test_admission_tls import certificates
    HAS_CRYPTO=fixtures.HAS_CRYPTO
except ImportError:
    HAS_CRYPTO=False;DiscoveryFixture=unittest.TestCase


@unittest.skipUnless(HAS_CRYPTO,'install identity extra')
class TaskOperationTests(DiscoveryFixture):
    echo=fixtures.DurableTaskTests.echo
    open_executor=fixtures.DurableTaskTests.open_executor
    restart=fixtures.DurableTaskTests.restart
    serve_tasks=fixtures.DurableTaskTests.serve_tasks
    client=fixtures.DurableTaskTests.client
    authenticated=fixtures.DurableTaskTests.authenticated
    post=fixtures.DurableTaskTests.post
    denied=fixtures.DurableTaskTests.denied
    count=fixtures.DurableTaskTests.count

    def setUp(self):
        super().setUp()
        self.keys=[self.agent]+[generate_identity(self.root/f'agent-{i}.pem') for i in range(1,4)]
        self.subjects=[identity_id(key.public_key()) for key in self.keys]
        self.permissions=['join','task.echo']
        self.grants=[issue_grant(self.owner,key.public_key(),self.group,self.permissions if i<3 else ['join'],now=100) for i,key in enumerate(self.keys)]
        self.members={self.subjects[i]:{'permissions':self.permissions if i<3 else ['join'],
            'grant_ids':[verify_grant(grant,self.owner.public_key(),self.group,now=110)['jti']]} for i,grant in enumerate(self.grants)}
        self.policy=revise_policy(self.owner,self.policy,self.members,now=102)
        self.node=self.directory(database=str(self.root/'directory.sqlite3'));self.calls=[]
        self.executor=self.open_executor();self.url,self.server=self.serve_tasks(self.executor)

    def queued(self,a=None):
        a=a or self.client();mid=a.queue('original intent')['task_id']
        token=a.db.execute('SELECT token FROM task_outbox WHERE task_id=?',(mid,)).fetchone()[0]
        return a,mid,token

    def cancel(self,a,mid):
        preview=a.cancel_preview(mid)
        return a.cancel(mid,preview['request_hash'],mid)

    def wire(self,operation,token,i=0):
        return self.post(self.authenticated({'operation':operation,'task':token},i=i))

    def uncertain(self,a=None):
        a,mid,token=self.queued(a)
        with patch.object(self.executor,'_run',side_effect=TaskUnavailable('pause')):self.denied(lambda:self.wire('submit',token),503)
        with self.node._registry.db:self.node._registry.db.execute("UPDATE durable_tasks SET status='running' WHERE task_id=?",(mid,))
        self.restart();self.assertEqual(a.refresh(mid)['status'],'uncertain')
        return a,mid,token

    def review(self,a,mid,*,request_id='a'*32,decision='unresolved',note='Checked external evidence; result remains uncertain.'):
        return a.review(mid,a.review_preview(mid)['receipt_hash'],decision,note,request_id,mid)

    def test_cancel_absent_intent_persists_tombstone_and_late_submit_never_executes(self):
        a,mid,token=self.queued();ack=self.cancel(a,mid)
        self.assertEqual(ack['status'],'cancelled');self.assertEqual(ack['error'],'execution_cancelled')
        self.assertTrue(ack['cancellation_requested']);self.assertIsNone(ack['output'])
        original=self.node._registry.db.execute('SELECT receipt FROM durable_tasks').fetchone()[0]
        self.assertEqual(self.wire('submit',token)['receipt'],original)
        self.assertEqual(self.wire('cancel',token)['receipt'],original)
        self.restart();self.assertEqual(self.wire('submit',token)['receipt'],original)
        self.assertEqual(a.flush(),[]);self.assertEqual(self.calls,[])
        self.assertEqual(a.show(mid),a.refresh(mid));self.assertEqual(a.status(),{'cancelled':1})

    def test_preview_and_wrong_confirmation_do_not_contact_or_sign_or_persist_intent(self):
        a,mid,_=self.queued();before=a.db.total_changes
        with patch.object(a.http,'request',side_effect=AssertionError('network')):
            preview=a.cancel_preview(mid);self.assertTrue(preview['sends_original_task']);self.assertTrue(preview['eligible'])
            for fingerprint,confirmation in [('0'*64,mid),(preview['request_hash'],'b'*32)]:
                with self.assertRaises(ValueError):a.cancel(mid,fingerprint,confirmation)
            with self.assertRaises(KeyError):a.cancel_preview('f'*32)
        self.assertEqual(a.db.total_changes,before);self.assertEqual(self.count(),0)

    def test_queued_cancellation_wins_before_running_marker_and_returns_same_receipt(self):
        a,mid,token=self.queued();entered,release=threading.Event(),threading.Event();real=self.executor._run
        def hold(*args):entered.set();release.wait(5);return real(*args)
        with patch.object(self.executor,'_run',hold),ThreadPoolExecutor(1) as pool:
            future=pool.submit(self.wire,'submit',token)
            try:
                self.assertTrue(entered.wait(3));ack=self.cancel(a,mid)
            finally:release.set()
            response=future.result(timeout=5)
        self.assertEqual(verify(response['receipt'],self.keys[2].public_key(),RESULT_TYPE)['status'],'cancelled')
        self.assertEqual(a.show(mid),ack);self.assertEqual(self.calls,[])

    def test_running_cannot_be_stopped_and_failed_cancel_refresh_never_reenables_flush(self):
        a,mid,token=self.queued();entered,release=threading.Event(),threading.Event()
        def hold(text):self.calls.append(text);entered.set();release.wait(5);return text
        self.restart(adapter=hold)
        with ThreadPoolExecutor(1) as pool:
            future=pool.submit(self.wire,'submit',token)
            try:
                self.assertTrue(entered.wait(3));self.denied(lambda:self.cancel(a,mid),409)
                self.assertEqual(a.refresh(mid)['status'],'running');self.assertEqual(a.status(),{'cancel_pending':1})
                with patch.object(a.http,'request',side_effect=AssertionError('resubmit')):self.assertEqual(a.flush(),[])
                with self.assertRaises(FileExistsError):self.cancel(a,mid)
            finally:release.set()
            future.result(timeout=5)
        self.assertEqual(a.refresh(mid)['status'],'completed');self.assertEqual(self.calls,['original intent'])
        self.assertEqual(a.status(),{'completed':1})

    def test_completed_failed_and_uncertain_results_are_not_relabelled_cancelled(self):
        a,mid,token=self.queued();a.flush();before=a.show(mid)
        self.denied(lambda:self.wire('cancel',token),409);self.assertEqual(a.show(mid),before)
        with self.assertRaises(FileExistsError):self.cancel(a,mid)
        def fail(_):raise ValueError('SECRET')
        self.restart(adapter=fail);_,other,other_token=self.queued(a);a.flush()
        self.denied(lambda:self.wire('cancel',other_token),409);self.assertEqual(a.show(other)['status'],'failed')
        _,unknown,unknown_token=self.uncertain(a)
        self.denied(lambda:self.wire('cancel',unknown_token),409);self.assertEqual(a.show(unknown)['status'],'uncertain')

    def test_cancel_authentication_scope_and_original_intent_are_required(self):
        a,mid,token=self.queued()
        self.denied(lambda:self.wire('cancel',token,i=1));self.denied(lambda:self.wire('cancel',token,i=3))
        request={'operation':'submit','task':token};auth=self.authenticated(request);auth['request']['operation']='cancel'
        self.denied(lambda:self.post(auth));self.assertEqual(self.count(),0)
        payload=self.authenticated({'operation':'cancel','task':token});self.post(payload);self.denied(lambda:self.post(payload))
        changed=a.key
        from tailnet_agents.durable_tasks import make_task
        conflict=make_task(changed,self.owner.public_key(),self.group,self.audience,self.subjects[2],'different',identifier=mid,now=110)
        self.denied(lambda:self.wire('cancel',conflict),409)
        self.assertEqual(self.calls,[])

    def test_cancel_schema_and_foreign_executor_or_group_fail_without_execution(self):
        a,mid,token=self.queued()
        for request in ({'operation':'cancel','task_id':mid},{'operation':'cancel','task':token,'extra':1},{'operation':'cancel','task':False}):
            from tailnet_agents.client import Client
            self.denied(lambda:Client(self.url,'').request('/v1/task-challenges',{'request':request}),400)
        from tailnet_agents.durable_tasks import TASK_TYPE
        claim=verify(token,a.key.public_key(),TASK_TYPE)
        for mutation in ({'group_id':'foreign'},{'executor':self.subjects[1]},{'audience':'other'}):
            bad=sign(a.key,claim|mutation,TASK_TYPE);self.denied(lambda:self.wire('cancel',bad))
        self.assertEqual(self.count(),0)

    def test_revocation_policy_expiry_and_dissolution_deny_cancel_without_renewal(self):
        a,mid,token=self.queued();self.now=402;self.denied(lambda:self.wire('cancel',token));self.assertEqual(self.count(),0)
        self.now=110
        jti=verify_grant(self.grants[0],self.owner.public_key(),self.group,now=110)['jti']
        self.node.revoke(issue_revocation(self.owner,self.group,jti));self.denied(lambda:self.wire('cancel',token))
        terminal=revise_policy(self.owner,self.policy,{},dissolve=True,now=110);self.node.apply_policy(terminal)
        self.denied(lambda:self.wire('cancel',token));self.assertEqual(self.count(),0)

    def test_lost_cancel_ack_survives_caller_restart_and_cannot_be_submitted_by_flush(self):
        a,mid,token=self.queued();real=a.http.request
        def lost(path,body=None):
            value=real(path,body)
            if path=='/v1/agent-tasks':raise URLError('lost cancellation ACK')
            return value
        with patch.object(a.http,'request',lost),self.assertRaises(URLError):self.cancel(a,mid)
        receipt=self.node._registry.db.execute('SELECT receipt FROM durable_tasks').fetchone()[0]
        a.close();a=self.client()
        self.assertEqual(a.status(),{'cancel_pending':1});self.assertTrue(a.show(mid)['cancellation_requested'])
        self.assertTrue(a.list_tasks()['tasks'][0]['cancellation_requested'])
        with patch.object(a.http,'request',side_effect=AssertionError('resubmit')):self.assertEqual(a.flush(),[])
        self.assertEqual(self.cancel(a,mid)['status'],'cancelled')
        self.assertEqual(a.db.execute('SELECT receipt FROM task_outbox').fetchone()[0],receipt)
        with patch.object(a.http,'request',side_effect=AssertionError('unnecessary I/O')):self.assertEqual(self.cancel(a,mid),a.show(mid))

    def test_network_failure_and_queued_refresh_preserve_cancellation_barrier(self):
        a,mid,token=self.queued()
        with patch.object(self.executor,'_run',side_effect=TaskUnavailable('pause')):self.denied(a.flush,503)
        with patch.object(a.http,'request',side_effect=URLError('offline')),self.assertRaises(URLError):self.cancel(a,mid)
        self.assertEqual(a.refresh(mid)['status'],'queued');self.assertEqual(a.status(),{'cancel_pending':1})
        a.close();a=self.client()
        with patch.object(a.http,'request',side_effect=AssertionError('resubmit')):self.assertEqual(a.flush(),[])
        self.assertEqual(self.calls,[])

    def test_unexpected_signed_cancel_ack_does_not_count_as_cancellation(self):
        a,mid,token=self.queued();receipt=self.executor._receipt(mid,self.subjects[0],token,'queued')
        with patch.object(a,'_request',return_value={'receipt':receipt}),self.assertRaises(ValueError):self.cancel(a,mid)
        self.assertEqual(a.status(),{'cancel_pending':1});self.assertEqual(a.show(mid)['state'],'pending')

    def test_cancelled_receipt_is_terminal_and_cannot_be_replaced_by_a_new_signature(self):
        a,mid,token=self.queued();original=self.cancel(a,mid)
        self.now=111;changed=self.executor._receipt(mid,self.subjects[0],token,'cancelled')
        with patch.object(a,'_request',return_value={'receipt':changed}),self.assertRaises(ValueError):a.refresh(mid)
        self.assertEqual(a.show(mid),original)

    def test_cancelling_one_same_host_caller_does_not_cancel_or_block_other_identity(self):
        a,mid,_=self.queued();b=self.client(i=1);_,other,_=self.queued(b)
        self.cancel(a,mid)
        result=b.flush()[0]
        self.assertEqual(result['task_id'],other);self.assertEqual(result['status'],'completed')
        self.assertEqual(a.show(mid)['status'],'cancelled');self.assertNotIn('cancellation_requested',b.show(other))

    def test_failed_local_intent_commit_prevents_network(self):
        a,mid,_=self.queued()
        a.db.execute("CREATE TRIGGER no_cancel BEFORE INSERT ON task_cancellations BEGIN SELECT RAISE(ABORT,'disk'); END")
        with patch.object(a.http,'request',side_effect=AssertionError('network')),self.assertRaises(sqlite3.Error):self.cancel(a,mid)
        self.assertEqual(a.status(),{'pending':1});self.assertEqual(self.count(),0)

    def test_remote_storage_failure_is_not_acknowledged_and_retry_is_safe(self):
        a,mid,_=self.queued()
        self.node._registry.db.execute("CREATE TRIGGER no_cancel BEFORE INSERT ON durable_tasks BEGIN SELECT RAISE(ABORT,'disk'); END")
        self.denied(lambda:self.cancel(a,mid),503);self.assertEqual(self.count(),0);self.assertEqual(a.status(),{'cancel_pending':1})
        self.node._registry.db.execute('DROP TRIGGER no_cancel')
        self.assertEqual(self.cancel(a,mid)['status'],'cancelled');self.assertEqual(self.calls,[])

    def test_local_receipt_commit_failure_retains_barrier_and_original_server_receipt(self):
        a,mid,_=self.queued()
        a.db.execute("CREATE TRIGGER no_receipt BEFORE UPDATE ON task_outbox BEGIN SELECT RAISE(ABORT,'disk'); END")
        with self.assertRaises(sqlite3.Error):self.cancel(a,mid)
        original=self.node._registry.db.execute('SELECT receipt FROM durable_tasks').fetchone()[0]
        self.assertEqual(a.status(),{'cancel_pending':1});a.db.execute('DROP TRIGGER no_receipt')
        self.assertEqual(self.cancel(a,mid)['status'],'cancelled')
        self.assertEqual(a.db.execute('SELECT receipt FROM task_outbox').fetchone()[0],original)

    def test_signing_failure_rolls_back_cancel_without_erasing_intent(self):
        a,mid,_=self.queued()
        with patch.object(self.executor,'_receipt',side_effect=ValueError('SECRET')):error=self.denied(lambda:self.cancel(a,mid),400)
        self.assertNotIn('SECRET',error.read().decode());error.close()
        self.assertEqual(self.count(),0);self.assertEqual(a.status(),{'cancel_pending':1})
        self.assertEqual(self.cancel(a,mid)['status'],'cancelled')

    def test_authorization_expiring_after_commit_retains_cancelled_tombstone(self):
        a,mid,token=self.queued();real=self.executor._receipt
        def expire(*args,**kwargs):value=real(*args,**kwargs);self.now=402;return value
        with patch.object(self.executor,'_receipt',expire):self.denied(lambda:self.cancel(a,mid))
        self.assertEqual(self.node._registry.db.execute('SELECT status FROM durable_tasks').fetchone()[0],'cancelled')
        self.now=110;self.assertEqual(self.cancel(a,mid)['status'],'cancelled');self.assertEqual(self.calls,[])

    def test_duplicate_cancellations_and_capacity_do_not_reexecute_or_prune_tombstones(self):
        a,mid,token=self.queued();self.executor.capacity=1
        payloads=[self.authenticated({'operation':'cancel','task':token}) for _ in range(2)]
        with ThreadPoolExecutor(2) as pool:results=list(pool.map(self.post,payloads))
        self.assertEqual(results[0],results[1]);self.assertEqual(self.count(),1)
        _,other,_=self.queued(a);self.denied(lambda:self.cancel(a,other),429)
        self.assertEqual(self.count(),1);self.assertEqual(self.wire('submit',token),results[0]);self.assertEqual(self.calls,[])

    def test_cancel_tls_same_host_and_original_executor_pin_remain_enforced(self):
        paths=certificates(self.root);url,_=self.serve_tasks(self.executor,tls=paths)
        a=self.client(url=url,ca_file=paths['ca'],state=self.root/'tls.sqlite3');_,mid,_=self.queued(a)
        self.assertEqual(self.cancel(a,mid)['executor'],self.subjects[2])
        bad=self.client(url=url,state=self.root/'bad-tls.sqlite3');_,other,_=self.queued(bad)
        with self.assertRaises(OSError):self.cancel(bad,other)
        self.assertEqual(bad.status(),{'cancel_pending':1})

    def test_caller_format_upgrade_retains_original_identity_intent_and_context(self):
        a,mid,token=self.queued();path=self.root/'caller-0.sqlite3'
        context=json.loads(a.db.execute('SELECT context FROM task_caller_context').fetchone()[0]);a.close()
        self.assertEqual(context[-1],operations.CALLER_FORMAT)
        with sqlite3.connect(path) as db:db.execute('UPDATE task_caller_context SET context=?',(json.dumps(context[:-1]),))
        a=self.client();self.assertEqual(a.db.execute('SELECT token FROM task_outbox').fetchone()[0],token)
        self.assertEqual(a.show(mid)['executor'],self.subjects[2])
        self.assertEqual(json.loads(a.db.execute('SELECT context FROM task_caller_context').fetchone()[0]),context)
        a.close()
        with sqlite3.connect(path) as db:db.execute('UPDATE task_caller_context SET context=?',(json.dumps(context[:-1]+['unknown-future-format']),))
        with self.assertRaises(AdmissionError):self.client()

    def test_persisted_cancellation_hash_corruption_fails_closed_on_restart(self):
        a,mid,_=self.queued()
        with patch.object(a.http,'request',side_effect=URLError('offline')),self.assertRaises(URLError):self.cancel(a,mid)
        a.close()
        with sqlite3.connect(self.root/'caller-0.sqlite3') as db:db.execute('UPDATE task_cancellations SET request_hash=?',('0'*64,))
        with self.assertRaises(AdmissionError):self.client()

    def test_uncertainty_reviews_are_signed_local_advisory_and_never_change_receipt(self):
        a,mid,_=self.uncertain();before=a.db.execute('SELECT receipt FROM task_outbox').fetchone()[0]
        with patch.object(a.http,'request',side_effect=AssertionError('network')):
            preview=a.review_preview(mid);self.assertEqual(preview['task_status'],'uncertain')
            record=self.review(a,mid,decision='no_effect_observed')
            self.assertEqual(a.flush(),[]);self.assertEqual(a.reviews(mid)['task_status'],'uncertain')
        token=a.db.execute('SELECT token FROM task_reviews').fetchone()[0]
        self.assertEqual(verify(token,self.keys[0].public_key(),operations.REVIEW_TYPE),record)
        self.assertEqual(record['receipt_hash'],digest(before));self.assertEqual(record['executor'],self.subjects[2])
        self.assertEqual(a.db.execute('SELECT receipt FROM task_outbox').fetchone()[0],before)
        self.assertEqual(a.show(mid)['status'],'uncertain');self.assertEqual(self.calls,[])

    def test_review_requires_known_uncertain_receipt_and_exact_confirmation(self):
        a,mid,_=self.queued()
        with self.assertRaises(ValueError):a.review_preview(mid)
        with self.assertRaises(KeyError):a.review_preview('f'*32)
        _,mid,_=self.uncertain(a);preview=a.review_preview(mid)
        for changes in ({'receipt_hash':'0'*64},{'decision':'completed'},{'note':''},{'note':'界'*683},{'request_id':'bad'},{'confirmation':'b'*32}):
            values={'receipt_hash':preview['receipt_hash'],'decision':'unresolved','note':'evidence','request_id':'a'*32,'confirmation':mid}|changes
            with self.subTest(changes=list(changes)),self.assertRaises(ValueError):a.review(mid,**values)
        self.assertEqual(a.reviews(mid)['reviews'],[])

    def test_review_request_retry_is_stable_changed_payload_conflicts_and_clock_rollback_cannot_resign(self):
        a,mid,_=self.uncertain()
        with patch('tailnet_agents.task_operations.sign',wraps=sign) as signer:
            record=self.review(a,mid);self.now=1
            self.assertEqual(self.review(a,mid),record)
            with self.assertRaises(FileExistsError):self.review(a,mid,note='changed')
            with self.assertRaises(ValueError):self.review(a,mid,request_id='b'*32)
            self.assertEqual(signer.call_count,1)

    def test_reviews_survive_restart_and_remain_available_after_expiry_and_dissolution(self):
        a,mid,_=self.uncertain();record=self.review(a,mid);a.close()
        self.node.apply_policy(revise_policy(self.owner,self.policy,{},now=110,dissolve=True));self.now=10000
        a=self.client()
        with patch.object(a.http,'request',side_effect=AssertionError('network')):
            self.assertEqual(a.reviews(mid)['reviews'][0]['review'],record)
            self.assertEqual(self.review(a,mid,request_id='b'*32,decision='effect_observed')['decision'],'effect_observed')
            self.assertEqual(a.show(mid)['status'],'uncertain');self.assertEqual(a.flush(),[])

    def test_review_pagination_preserves_append_only_history_and_task_binding(self):
        a,mid,_=self.uncertain()
        for i,decision in enumerate(operations.DECISIONS):self.review(a,mid,request_id=f'{i+1:032x}',decision=decision)
        first=a.reviews(mid,limit=2);self.assertTrue(first['has_more'])
        last=a.reviews(mid,after=first['next_after'],limit=2);self.assertFalse(last['has_more'])
        self.assertEqual([entry['review']['decision'] for entry in first['reviews']+last['reviews']],list(operations.DECISIONS))
        self.assertEqual(a.show(mid)['status'],'uncertain')
        for options in ({'after':True},{'after':-1},{'limit':0},{'limit':101}):
            with self.assertRaises(ValueError):a.reviews(mid,**options)

    def test_review_signature_receipt_and_original_context_tampering_are_rejected(self):
        a,mid,_=self.uncertain();record=self.review(a,mid)
        for changes in ({'executor':self.subjects[1]},{'group_id':'other'},{'receipt_hash':'0'*64},{'version':True},{'issued_at':True}):
            forged=sign(a.key,record|changes,operations.REVIEW_TYPE)
            with self.subTest(changes=list(changes)),self.assertRaises(ValueError):operations.verify_review(a,forged,mid)
        forged=sign(self.keys[1],record,operations.REVIEW_TYPE)
        with a.db:a.db.execute('UPDATE task_reviews SET token=?',(forged,))
        with self.assertRaises(ValueError):a.reviews(mid)
        with a.db:a.db.execute('UPDATE task_reviews SET token=?,request_id=?',(sign(a.key,record,operations.REVIEW_TYPE),'b'*32))
        with self.assertRaises(ValueError):a.reviews(mid)

    def test_review_transaction_failure_and_global_request_id_conflict_do_not_change_tasks(self):
        a,mid,_=self.uncertain()
        a.db.execute("CREATE TRIGGER no_review BEFORE INSERT ON task_reviews BEGIN SELECT RAISE(ABORT,'disk'); END")
        with self.assertRaises(sqlite3.Error):self.review(a,mid)
        self.assertEqual(a.reviews(mid)['reviews'],[]);a.db.execute('DROP TRIGGER no_review')
        self.review(a,mid)
        _,other,_=self.uncertain(a)
        with self.assertRaises(FileExistsError):self.review(a,other)
        self.assertEqual(a.show(mid)['status'],'uncertain');self.assertEqual(a.show(other)['status'],'uncertain')

    def test_real_cli_explicit_cancel_and_advisory_review_without_private_output(self):
        self.now=int(time.time());self.executor.close()
        self.grants=[issue_grant(self.owner,key.public_key(),self.group,self.permissions,now=self.now) for key in self.keys]
        members={self.subjects[i]:{'permissions':self.permissions,'grant_ids':[verify_grant(grant,self.owner.public_key(),self.group,now=self.now)['jti']]}
                 for i,grant in enumerate(self.grants)}
        self.policy=revise_policy(self.owner,self.policy,members,now=self.now);self.node.apply_policy(self.policy)
        self.executor=self.open_executor();self.server.RequestHandlerClass=handler(self.node,'r'*32,task_executor=self.executor)
        a,mid,_=self.queued();a.close()
        owner=self.root/'owner.pub';executor=self.root/'executor.pub';grant=self.root/'caller.grant';note=self.root/'note.txt'
        owner.write_text(encode(public_bytes(self.owner.public_key())));executor.write_text(encode(public_bytes(self.keys[2].public_key())))
        grant.write_text(self.grants[0]);note.write_text('External evidence checked; no automatic replay.')
        base=[sys.executable,'-m','tailnet_agents.task_client','--url',self.url,'--agent-key',str(self.agent_path),
              '--authority-public-key',str(owner),'--grant-file',str(grant),'--group-id',self.group,'--audience',self.audience,
              '--executor-public-key',str(executor),'--state',str(self.root/'caller-0.sqlite3')]
        def cli(*arguments):
            result=subprocess.run(base+list(arguments),capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr);self.assertNotIn(self.grants[0],result.stdout)
            return json.loads(result.stdout)
        preview=cli('cancel-preview','--task-id',mid)
        self.assertEqual(cli('cancel','--task-id',mid,'--request-hash',preview['request_hash'],'--confirm-task-id',mid)['status'],'cancelled')
        self.assertEqual(cli('flush'),[])
        a=self.client();_,other,_=self.uncertain(a);a.close()
        preview=cli('review-preview','--task-id',other)
        before=self.node._registry.db.total_changes
        record=cli('review','--task-id',other,'--receipt-hash',preview['receipt_hash'],'--decision','unresolved',
                   '--note-file',str(note),'--request-id','a'*32,'--confirm-task-id',other)
        self.assertEqual(cli('reviews','--task-id',other)['reviews'][0]['review'],record)
        self.assertEqual(cli('show','--task-id',other)['status'],'uncertain')
        self.assertEqual(self.node._registry.db.total_changes,before)
