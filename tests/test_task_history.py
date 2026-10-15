"""Explicit task archives, bounded history and public-key scoped quotas."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
from urllib.error import URLError
import test_durable_tasks as fixtures
import test_task_operations as operation_fixtures

try:
    from tailnet_agents.durable_tasks import TaskExecutor, TaskUnavailable, digest, make_task
    from tailnet_agents.task_history import EXECUTOR_FORMAT, quotas
    from tailnet_agents.identity import (AdmissionError, encode, generate_identity, identity_id,
        issue_grant, public_bytes, verify_grant)
    from tailnet_agents.group_policy import revise_policy
    from tailnet_agents.verified_directory import issue_revocation
    from tests.test_discovery import DiscoveryFixture
    from tests.test_admission_tls import certificates
    HAS_CRYPTO = fixtures.HAS_CRYPTO
except ImportError:
    HAS_CRYPTO = False
    DiscoveryFixture = unittest.TestCase


@unittest.skipUnless(HAS_CRYPTO, 'install identity extra')
class TaskHistoryTests(DiscoveryFixture):
    echo = fixtures.DurableTaskTests.echo
    open_executor = fixtures.DurableTaskTests.open_executor
    restart = fixtures.DurableTaskTests.restart
    serve_tasks = fixtures.DurableTaskTests.serve_tasks
    client = fixtures.DurableTaskTests.client
    authenticated = fixtures.DurableTaskTests.authenticated
    post = fixtures.DurableTaskTests.post
    denied = fixtures.DurableTaskTests.denied
    count = fixtures.DurableTaskTests.count
    queued = operation_fixtures.TaskOperationTests.queued
    cancel = operation_fixtures.TaskOperationTests.cancel
    wire = operation_fixtures.TaskOperationTests.wire
    uncertain = operation_fixtures.TaskOperationTests.uncertain

    def setUp(self):
        super().setUp()
        self.keys = [self.agent] + [generate_identity(self.root/f'agent-{i}.pem') for i in range(1, 4)]
        self.subjects = [identity_id(key.public_key()) for key in self.keys]
        self.permissions = ['join', 'task.echo']
        self.grants = [issue_grant(self.owner, key.public_key(), self.group,
            self.permissions if i < 3 else ['join'], now=100) for i, key in enumerate(self.keys)]
        self.members = {self.subjects[i]: {'permissions': self.permissions if i < 3 else ['join'],
            'grant_ids': [verify_grant(grant, self.owner.public_key(), self.group, now=110)['jti']]}
            for i, grant in enumerate(self.grants)}
        self.policy = revise_policy(self.owner, self.policy, self.members, now=102)
        self.node = self.directory(database=str(self.root/'directory.sqlite3'))
        self.calls = []
        self.executor = self.open_executor()
        self.url, self.server = self.serve_tasks(self.executor)

    def complete(self, a=None):
        a, mid, token = self.queued(a)
        self.wire('submit', token, i=0 if a.subject == self.subjects[0] else 1)
        a.refresh(mid)
        return a, mid, token

    def archive(self, a, mid):
        p = a.archive_preview(mid)
        return a.archive(mid, p['request_hash'], p['receipt_hash'], mid)

    def request_archive(self, a, mid):
        token = a.db.execute('SELECT token FROM task_outbox WHERE task_id=?', (mid,)).fetchone()[0]
        return {'operation': 'archive', 'task': token, 'receipt_hash': a.archive_preview(mid)['receipt_hash']}

    def archived(self):
        return self.node._registry.db.execute('SELECT COUNT(*) FROM archived_tasks').fetchone()[0]

    def test_archive_moves_complete_original_records_and_returns_unchanged_result(self):
        a, mid, token = self.complete()
        original = self.node._registry.db.execute('SELECT * FROM durable_tasks').fetchone()
        before = a.show(mid)
        result = self.archive(a, mid)
        self.assertTrue(result['archived']);self.assertTrue(result['payload_retained'])
        self.assertEqual(self.count(), 0);self.assertEqual(self.archived(), 1)
        self.assertEqual(self.node._registry.db.execute('SELECT * FROM archived_tasks').fetchone(), original)
        self.assertEqual(a.refresh(mid), before);self.assertEqual(a.show(mid), before)
        self.assertEqual(self.wire('submit', token), {'receipt': original[4]})
        self.assertEqual(self.calls, ['original intent']);self.assertEqual(a.flush(), [])

    def test_archive_preview_and_confirmation_are_local_and_bind_both_hashes(self):
        a, mid, _ = self.complete();before = a.db.total_changes
        with patch.object(a.http, 'request', side_effect=AssertionError('network')):
            p = a.archive_preview(mid)
            self.assertTrue(p['eligible']);self.assertFalse(p['remote_state_checked'])
            for request_hash, receipt_hash, confirmation in (
                    ('0'*64, p['receipt_hash'], mid), (p['request_hash'], '0'*64, mid),
                    (p['request_hash'], p['receipt_hash'], 'f'*32)):
                with self.assertRaises(ValueError):a.archive(mid, request_hash, receipt_hash, confirmation)
        self.assertEqual(a.db.total_changes, before);self.assertEqual(self.archived(), 0)

    def test_archive_releases_active_capacity_and_restart_retains_deduplication(self):
        self.restart(capacity=1)
        a, mid, token = self.complete();original = a.show(mid)
        _, other, _ = self.queued(a);self.denied(lambda:a.flush(), 429)
        self.archive(a, mid);self.assertEqual(a.flush()[0]['task_id'], other)
        self.restart(capacity=1)
        self.assertEqual(a.refresh(mid), original);self.wire('submit', token)
        self.assertEqual(len(self.calls), 2);self.assertEqual(self.archived(), 1)

    def test_global_history_quota_counts_active_and_archived_records(self):
        self.restart(capacity=1, history_capacity=2)
        a, mid, token = self.complete();self.archive(a, mid)
        _, other, _ = self.complete(a);self.archive(a, other)
        self.queued(a);self.denied(lambda:a.flush(), 429)
        self.assertEqual(self.archived(), 2);self.assertEqual(self.count(), 0)
        self.wire('submit', token);self.assertEqual(len(self.calls), 2)
        self.assertTrue(self.archive(a, mid)['archived'])

    def test_active_quota_is_by_caller_key_for_two_agents_on_same_host(self):
        self.restart(capacity=4, caller_capacity=1)
        a, mid, _ = self.complete();b = self.client(1)
        self.queued(a);self.denied(lambda:a.flush(), 429)
        _, other, _ = self.complete(b)
        self.assertNotEqual(a.subject, b.subject);self.assertEqual(self.count(), 2)
        self.archive(a, mid);self.assertEqual(a.flush()[0]['status'], 'completed')
        self.assertEqual(b.refresh(other)['status'], 'completed')
        self.assertEqual(self.node.discover(), [])
        self.assertEqual(self.node._policy.current()['members'], self.members)

    def test_caller_history_quota_survives_archive_without_blocking_other_keys(self):
        self.restart(capacity=4, caller_history_capacity=1)
        a, mid, _ = self.complete();self.archive(a, mid)
        self.queued(a);self.denied(lambda:a.flush(), 429)
        b, other, _ = self.complete(self.client(1));self.archive(b, other)
        self.assertEqual(self.archived(), 2);self.assertEqual(len(self.calls), 2)

    def test_lowered_quotas_preserve_existing_reads_retries_and_archival(self):
        a, first, token = self.complete();_, second, _ = self.complete(a)
        self.restart(capacity=1, history_capacity=1, caller_capacity=1, caller_history_capacity=1)
        self.wire('submit', token);self.archive(a, first);self.archive(a, second)
        self.queued(a);self.denied(lambda:a.flush(), 429)
        self.assertEqual(self.archived(), 2);self.assertEqual(len(self.calls), 2)

    def test_defaults_and_invalid_quota_configuration_are_bounded_and_strict(self):
        self.assertEqual(quotas(256, 10000, None, None), {'capacity':256, 'history_capacity':10000,
            'caller_capacity':64, 'caller_history_capacity':1000})
        for name in ('capacity', 'history_capacity', 'caller_capacity', 'caller_history_capacity'):
            for bad in (0, -1, True, 1.5, '2', 100001):
                with self.subTest(name=name, bad=bad), self.assertRaises(ValueError):
                    self.open_executor(**{name:bad})

    def test_cancelled_archive_keeps_tombstone_and_late_submit_or_cancel_returns_it(self):
        a, mid, token = self.queued();self.cancel(a, mid)
        receipt = a.db.execute('SELECT receipt FROM task_outbox').fetchone()[0]
        self.archive(a, mid);self.restart()
        for operation in ('submit', 'cancel'):
            self.assertEqual(self.wire(operation, token), {'receipt':receipt})
        self.assertTrue(a.show(mid)['cancellation_requested']);self.assertEqual(a.flush(), [])
        self.assertEqual(self.calls, []);self.assertEqual(self.archived(), 1)

    def test_failed_archive_preserves_failure_and_never_invokes_again(self):
        def fail(text):self.calls.append(text);raise ValueError('private failure')
        self.restart(adapter=fail)
        a, mid, token = self.complete();self.assertEqual(a.show(mid)['status'], 'failed')
        self.archive(a, mid);self.restart(adapter=fail);self.wire('submit', token)
        self.assertEqual(a.refresh(mid)['error'], 'execution_failed');self.assertEqual(len(self.calls), 1)

    def test_pending_queued_running_and_uncertain_tasks_cannot_be_archived(self):
        a, mid, token = self.queued()
        self.assertFalse(a.archive_preview(mid)['eligible'])
        with self.assertRaises(FileExistsError):self.archive(a, mid)
        request = {'operation':'archive', 'task':token, 'receipt_hash':'0'*64}
        self.denied(lambda:self.post(self.authenticated(request)), 404)
        with patch.object(self.executor, '_run', side_effect=TaskUnavailable('pause')):
            self.denied(lambda:self.wire('submit', token), 503)
        self.denied(lambda:self.post(self.authenticated(request)), 409)
        with self.node._registry.db:self.node._registry.db.execute("UPDATE durable_tasks SET status='running'")
        self.denied(lambda:self.post(self.authenticated(request)), 409)
        self.restart();self.assertEqual(a.refresh(mid)['status'], 'uncertain')
        self.assertFalse(a.archive_preview(mid)['eligible'])
        with self.assertRaises(FileExistsError):self.archive(a, mid)
        request['receipt_hash'] = a.archive_preview(mid)['receipt_hash']
        self.denied(lambda:self.post(self.authenticated(request)), 409)
        self.assertEqual(self.archived(), 0);self.assertEqual(self.calls, [])

    def test_lost_archive_ack_and_caller_restart_are_idempotent(self):
        a, mid, _ = self.complete();original = a.show(mid);send = a._request
        def lost(request):send(request);raise URLError('lost response')
        with patch.object(a, '_request', side_effect=lost), self.assertRaises(URLError):self.archive(a, mid)
        self.assertEqual(self.archived(), 1);a.close();a = self.client()
        self.assertTrue(self.archive(a, mid)['archived']);self.assertEqual(a.refresh(mid), original)
        self.assertEqual(self.archived(), 1);self.assertEqual(len(self.calls), 1)

    def test_local_receipt_commit_failure_leaves_original_and_remote_retry_safe(self):
        a, mid, _ = self.complete();original = a.show(mid)
        a.db.execute("CREATE TRIGGER reject_archive_ack BEFORE UPDATE ON task_outbox BEGIN SELECT RAISE(ABORT,'test'); END")
        with self.assertRaises(sqlite3.Error):self.archive(a, mid)
        self.assertEqual(self.archived(), 1);self.assertEqual(a.show(mid), original)
        a.db.execute('DROP TRIGGER reject_archive_ack');self.archive(a, mid)
        self.assertEqual(a.show(mid), original);self.assertEqual(a.flush(), [])

    def test_archive_insert_failure_rolls_back_and_keeps_active_deduplication(self):
        a, mid, token = self.complete();db = self.node._registry.db
        db.execute("CREATE TRIGGER reject_archive BEFORE INSERT ON archived_tasks BEGIN SELECT RAISE(ABORT,'test'); END")
        self.denied(lambda:self.archive(a, mid), 503)
        self.assertEqual(self.count(), 1);self.assertEqual(self.archived(), 0)
        self.wire('submit', token);self.assertEqual(len(self.calls), 1)
        db.execute('DROP TRIGGER reject_archive');self.archive(a, mid)

    def test_archive_delete_failure_rolls_back_insert_and_returns_no_ack(self):
        a, mid, _ = self.complete();db = self.node._registry.db
        db.execute("CREATE TRIGGER reject_delete BEFORE DELETE ON durable_tasks BEGIN SELECT RAISE(ABORT,'test'); END")
        self.denied(lambda:self.archive(a, mid), 503)
        self.assertEqual(self.count(), 1);self.assertEqual(self.archived(), 0)
        db.execute('DROP TRIGGER reject_delete');self.archive(a, mid)
        self.assertEqual(self.count(), 0);self.assertEqual(self.archived(), 1)

    def test_ignored_archive_delete_rolls_back_instead_of_committing_overlapping_ids(self):
        a, mid, _ = self.complete();db = self.node._registry.db
        db.execute("CREATE TRIGGER ignore_delete BEFORE DELETE ON durable_tasks BEGIN SELECT RAISE(IGNORE); END")
        self.denied(lambda:self.archive(a, mid), 503)
        self.assertEqual(self.count(), 1);self.assertEqual(self.archived(), 0)
        db.execute('DROP TRIGGER ignore_delete');self.archive(a, mid)

    def test_archive_reuses_original_signature_without_signing_another_result(self):
        a, mid, _ = self.complete();receipt = a.db.execute('SELECT receipt FROM task_outbox').fetchone()[0]
        with patch('tailnet_agents.durable_tasks.sign', side_effect=AssertionError('resign')):
            self.archive(a, mid);self.assertEqual(a.refresh(mid)['status'], 'completed')
        self.assertEqual(self.node._registry.db.execute('SELECT receipt FROM archived_tasks').fetchone()[0], receipt)

    def test_concurrent_archive_get_and_duplicate_submit_never_lose_or_reexecute_task(self):
        a, mid, token = self.complete();request = self.request_archive(a, mid)
        read = {'operation':'get', 'task_id':mid};submit = {'operation':'submit', 'task':token}
        requests = [request, read, submit, request, submit, read]
        payloads = [self.authenticated(r) for r in requests]
        with ThreadPoolExecutor(6) as pool:results = list(pool.map(self.post, payloads))
        receipts = {r['receipt'] for r in results}
        self.assertEqual(len(receipts), 1);self.assertEqual(self.archived(), 1)
        self.assertEqual(self.count(), 0);self.assertEqual(len(self.calls), 1)

    def test_foreign_caller_cannot_archive_or_read_an_archived_result(self):
        a, mid, _ = self.complete();request = self.request_archive(a, mid)
        self.denied(lambda:self.post(self.authenticated(request, i=1)))
        self.denied(lambda:self.post(self.authenticated(request, i=3)))
        self.assertEqual(self.archived(), 0);self.archive(a, mid)
        self.denied(lambda:self.post(self.authenticated({'operation':'get', 'task_id':mid}, i=1)), 404)

    def test_conflicting_original_intent_or_receipt_hash_cannot_replace_archive(self):
        a, mid, _ = self.complete();request = self.request_archive(a, mid)
        self.denied(lambda:self.post(self.authenticated(request | {'receipt_hash':'0'*64})), 409)
        self.archive(a, mid)
        for i in (0, 1):
            token = make_task(self.keys[i], self.owner.public_key(), self.group, self.audience,
                self.subjects[2], 'changed input', identifier=mid, now=self.now)
            self.denied(lambda:self.wire('submit', token, i=i), 409)
        self.assertEqual(self.archived(), 1);self.assertEqual(len(self.calls), 1)

    def test_archive_operation_is_proof_bound_and_replayed_nonce_is_denied(self):
        a, mid, _ = self.complete();request = self.request_archive(a, mid)
        payload = self.authenticated(request);payload['request'] = {'operation':'get', 'task_id':mid}
        self.denied(lambda:self.post(payload));self.assertEqual(self.archived(), 0)
        payload = self.authenticated(request);self.post(payload);self.denied(lambda:self.post(payload))
        self.assertEqual(self.archived(), 1)

    def test_archive_schema_rejects_missing_extra_or_invalid_hash_fields(self):
        a, mid, _ = self.complete();request = self.request_archive(a, mid)
        bad = [request | {'extra':1}, {'operation':'archive', 'task_id':mid},
            *[request | {'receipt_hash':value} for value in (None, True, 'A'*64, 'f'*63)],
            request | {'task':False}]
        from tailnet_agents.client import Client
        for value in bad:
            self.denied(lambda:Client(self.url, '').request('/v1/task-challenges', {'request':value}), 400)
        self.assertEqual(self.archived(), 0)

    def test_current_caller_and_executor_authorization_still_gate_archival_and_reads(self):
        a, mid, _ = self.complete()
        self.now = 500;self.denied(lambda:self.archive(a, mid))
        self.now = 110;self.archive(a, mid)
        self.node.revoke(issue_revocation(self.owner, self.group, self.members[self.subjects[2]]['grant_ids'][0]))
        self.denied(lambda:a.refresh(mid));self.denied(lambda:self.archive(a, mid))
        self.assertEqual(a.show(mid)['status'], 'completed');self.assertEqual(self.archived(), 1)

    def test_post_commit_authorization_failure_preserves_archive_and_safe_retry(self):
        a, mid, _ = self.complete();authorize = self.executor._authorize
        def expire(grant, subject):
            if self.archived():self.now = 500
            return authorize(grant, subject)
        with patch.object(self.executor, '_authorize', side_effect=expire):self.denied(lambda:self.archive(a, mid))
        self.assertEqual(self.archived(), 1);self.assertEqual(self.count(), 0)
        self.now = 110;self.archive(a, mid);self.assertEqual(len(self.calls), 1)

    def test_archive_ack_must_be_true_and_original_terminal_receipt_is_immutable(self):
        a, mid, _ = self.complete();original = a.show(mid)
        receipt = a.db.execute('SELECT receipt FROM task_outbox').fetchone()[0]
        for response in ({'receipt':receipt}, {'receipt':receipt, 'archived':False},
                {'receipt':receipt, 'archived':1}, {'receipt':'broken', 'archived':True}):
            with patch.object(a, '_request', return_value=response), self.assertRaises(ValueError):self.archive(a, mid)
        self.assertEqual(a.show(mid), original);self.assertEqual(self.archived(), 0)

    def test_https_archive_preserves_original_pins_and_results(self):
        tls = certificates(self.root);url, _ = self.serve_tasks(self.executor, tls=tls)
        a = self.client(url=url, ca_file=str(tls['ca']))
        mid = a.queue('TLS archive')['task_id'];a.flush()
        self.archive(a, mid);self.assertEqual(a.refresh(mid)['output'], 'TLS archive')
        self.assertEqual(self.archived(), 1);self.assertEqual(len(self.calls), 1)

    def test_two_same_host_executors_keep_independent_archives_and_capacity(self):
        from tailnet_agents.task_client import TaskClient
        other = self.directory(database=str(self.root/'second-executor.sqlite3'))
        executor = TaskExecutor(other, self.keys[1], self.grants[1], capacity=1)
        self.addCleanup(executor.close)
        url, _ = self.serve_tasks(executor, node=other)
        b = TaskClient(url, self.keys[0], self.owner.public_key(), self.grants[0], self.group,
            self.audience, self.keys[1].public_key(), self.root/'second-caller.sqlite3', clock=lambda:self.now)
        self.addCleanup(b.close)
        mid = b.queue('second executor')['task_id'];b.flush();self.archive(b, mid)
        self.assertEqual(other._registry.db.execute('SELECT COUNT(*) FROM archived_tasks').fetchone()[0], 1)
        self.assertEqual(self.archived(), 0);self.assertEqual(self.count(), 0)
        a, first, _ = self.complete();self.archive(a, first)
        self.assertEqual(b.refresh(mid)['output'], 'second executor')
        self.assertNotEqual(a.executor, b.executor)

    def test_legacy_executor_context_upgrades_without_replacing_identity_or_tasks(self):
        a, mid, token = self.complete();self.executor.close()
        with self.node._registry.db:self.node._registry.db.execute("UPDATE task_executor_context SET adapter='echo-v1'")
        self.executor = self.open_executor();self.restart()
        context = self.node._registry.db.execute('SELECT executor,audience,adapter FROM task_executor_context').fetchone()
        self.assertEqual(context, (self.subjects[2], self.audience, EXECUTOR_FORMAT))
        self.archive(a, mid);self.wire('submit', token)
        self.assertEqual(len(self.calls), 1);self.assertEqual(self.node.group_id, self.group)

    def test_unknown_executor_format_is_rejected_without_clearing_history(self):
        a, mid, _ = self.complete();self.archive(a, mid);self.executor.close()
        with self.node._registry.db:self.node._registry.db.execute("UPDATE task_executor_context SET adapter='future-format'")
        with self.assertRaises(AdmissionError):self.open_executor()
        self.assertEqual(self.archived(), 1);self.assertEqual(a.show(mid)['status'], 'completed')

    def test_corrupt_or_overlapping_archive_fails_closed_on_read_and_restart(self):
        a, mid, token = self.complete();self.archive(a, mid);db = self.node._registry.db
        with db:db.execute("UPDATE archived_tasks SET status='cancelled'")
        self.denied(lambda:a.refresh(mid))
        self.executor.close()
        with self.assertRaises(AdmissionError):self.open_executor()
        with db:
            db.execute("UPDATE archived_tasks SET status='completed'")
            db.execute('INSERT INTO durable_tasks SELECT * FROM archived_tasks')
        with self.assertRaises(AdmissionError):self.open_executor()
        self.assertEqual(self.archived(), 1);self.assertEqual(self.count(), 1)

    def test_real_cli_archive_preview_confirmation_and_restart(self):
        self.executor.close();self.now = int(time.time())
        self.grants = [issue_grant(self.owner, key.public_key(), self.group, self.permissions, now=self.now) for key in self.keys]
        self.members = {self.subjects[i]:{'permissions':self.permissions,
            'grant_ids':[verify_grant(grant,self.owner.public_key(),self.group,now=self.now)['jti']]}
            for i, grant in enumerate(self.grants)}
        self.policy = revise_policy(self.owner,self.policy,self.members,now=self.now);self.node.apply_policy(self.policy)
        self.restart();a, mid, _ = self.complete();a.close()
        owner, executor, grant = (self.root/name for name in ('owner.pub','executor.pub','caller.grant'))
        owner.write_text(encode(public_bytes(self.owner.public_key())));executor.write_text(encode(public_bytes(self.keys[2].public_key())))
        grant.write_text(self.grants[0])
        base = [sys.executable,'-m','tailnet_agents.task_client','--url',self.url,'--agent-key',str(self.agent_path),
            '--authority-public-key',str(owner),'--grant-file',str(grant),'--group-id',self.group,'--audience',self.audience,
            '--executor-public-key',str(executor),'--state',str(self.root/'caller-0.sqlite3')]
        def cli(*args):
            result = subprocess.run(base+list(args),capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr);self.assertNotIn(self.grants[0],result.stdout)
            return json.loads(result.stdout)
        p = cli('archive-preview','--task-id',mid)
        result = cli('archive','--task-id',mid,'--request-hash',p['request_hash'],
            '--receipt-hash',p['receipt_hash'],'--confirm-task-id',mid)
        self.assertTrue(result['archived']);self.assertEqual(cli('show','--task-id',mid)['status'],'completed')
        self.assertEqual(cli('flush'),[]);self.assertEqual(self.archived(),1)

    def test_server_quota_flags_require_task_opt_in_and_validate_before_state_creation(self):
        state = self.root/'uncreated.sqlite3'
        base = [sys.executable,'-m','tailnet_agents.admission_server','--authority-public-key','missing',
            '--group-id',self.group,'--audience',self.audience,'--database',str(state)]
        env = os.environ | {'TAILNET_VERIFIED_READ_TOKEN':'r'*32}
        for args in (['--task-capacity','1'], ['--tasks','--require-policy','--task-agent-key','missing',
                '--task-grant-file','missing','--task-history-capacity','0']):
            result = subprocess.run(base+args,env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,2);self.assertFalse(state.exists())

    def test_real_service_cli_enforces_all_four_quota_flags(self):
        from tailnet_agents.client import Client
        self.now = int(time.time())
        self.grants[:3] = [issue_grant(self.owner, key.public_key(), self.group, self.permissions, now=self.now) for key in self.keys[:3]]
        members = {self.subjects[i]:{'permissions':self.permissions,
            'grant_ids':[verify_grant(grant,self.owner.public_key(),self.group,now=self.now)['jti']]}
            for i, grant in enumerate(self.grants[:3])}
        policy = revise_policy(self.owner,self.policy,members,now=self.now)
        owner, policy_file, grant_file = (self.root/name for name in ('service-owner.pub','service-policy.jwt','service-executor.grant'))
        owner.write_text(encode(public_bytes(self.owner.public_key())));policy_file.write_text(policy);grant_file.write_text(self.grants[2])
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port = sock.getsockname()[1]
        command = [sys.executable,'-m','tailnet_agents.admission_server','--authority-public-key',str(owner),
            '--group-id',self.group,'--audience',self.audience,'--database',str(self.root/'quota-service.sqlite3'),
            '--policy-file',str(policy_file),'--tasks','--task-agent-key',str(self.root/'agent-2.pem'),
            '--task-grant-file',str(grant_file),'--port',str(port),'--task-capacity','1',
            '--task-history-capacity','2','--task-caller-capacity','1','--task-caller-history-capacity','1']
        service = subprocess.Popen(command,env=os.environ|{'TAILNET_VERIFIED_READ_TOKEN':'r'*32},
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.addCleanup(lambda:(service.poll() is None and service.terminate(),service.communicate(timeout=10)))
        url = f'http://127.0.0.1:{port}';deadline = time.monotonic()+10
        while True:
            try:Client(url,'').request('/healthz');break
            except URLError:
                if service.poll() is not None or time.monotonic() > deadline:self.fail('quota service did not start')
                time.sleep(.02)
        a = self.client(url=url, state=self.root/'quota-caller-a.sqlite3')
        mid = a.queue('a original')['task_id'];a.flush()
        b = self.client(1,url=url,state=self.root/'quota-caller-b.sqlite3')
        other = b.queue('b original')['task_id'];self.denied(lambda:b.flush(),429)
        a.queue('a history full');self.denied(lambda:a.flush(),429)
        self.archive(a,mid);self.denied(lambda:a.flush(),429)
        self.assertEqual(b.flush()[0]['task_id'],other);self.archive(b,other)
        b.queue('total history full');self.denied(lambda:b.flush(),429)
        self.assertEqual(a.refresh(mid)['output'],'a original')
        self.assertEqual(b.refresh(other)['output'],'b original')


if __name__ == '__main__':unittest.main()
