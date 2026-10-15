"""Explicit metadata inspection with synthetic identities and actual HTTP/TLS."""
import copy
from concurrent.futures import ThreadPoolExecutor
from http.client import IncompleteRead
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request,urlopen
import test_durable_tasks as fixtures

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tailnet_agents.adapters import EchoAdapter,echo_contract,contract_hash
    from tailnet_agents.adapter_probe import DESCRIPTOR_TYPE,probe,verify_descriptor
    from tailnet_agents.client import Client
    from tailnet_agents.durable_tasks import TaskExecutor,TaskUnavailable
    from tailnet_agents.group_policy import revise_policy
    from tailnet_agents.identity import (AdmissionError,encode,generate_identity,identity_id,issue_grant,public_bytes,sign,verify,verify_grant)
    from tailnet_agents.admission_server import handler
    from tailnet_agents.verified_directory import VerifiedDirectory,issue_revocation
    from tests.test_discovery import DiscoveryFixture
    from tests.test_admission_tls import certificates
    HAS_CRYPTO=True
except ImportError:
    HAS_CRYPTO=False;DiscoveryFixture=unittest.TestCase


@unittest.skipUnless(HAS_CRYPTO,'install identity extra')
class AdapterProbeTests(DiscoveryFixture):
    serve_tasks=fixtures.DurableTaskTests.serve_tasks
    client=fixtures.DurableTaskTests.client
    request=fixtures.DurableTaskTests.request
    authenticated=fixtures.DurableTaskTests.authenticated
    post=fixtures.DurableTaskTests.post
    denied=fixtures.DurableTaskTests.denied

    def setUp(self):
        super().setUp()
        self.keys=[self.agent]+[generate_identity(self.root/f'probe-{i}.pem') for i in (1,2)]
        self.subjects=[identity_id(key.public_key()) for key in self.keys]
        self.permissions=['join','task.echo'];self.calls=[]
        self.grants=[issue_grant(self.owner,key.public_key(),self.group,self.permissions,now=100) for key in self.keys]
        self.members={self.subjects[i]:{'permissions':self.permissions,'grant_ids':[verify_grant(grant,self.owner.public_key(),self.group,now=110)['jti']]}
                      for i,grant in enumerate(self.grants)}
        self.policy=revise_policy(self.owner,self.policy,self.members,now=102)
        self.node=self.directory(database=str(self.root/'directory.sqlite3'))
        self.executor=TaskExecutor(self.node,self.keys[2],self.grants[2]);self.addCleanup(self.executor.close)
        self.url,self.server=self.serve_tasks(self.executor)

    def inspect(self,**options):
        return probe(options.pop('url',self.url),options.pop('token','r'*32),options.pop('owner',self.owner.public_key()),
            options.pop('group',self.group),options.pop('audience',self.audience),options.pop('key',self.keys[2].public_key()),
            clock=lambda:self.now,**options)

    def descriptor(self,nonce='a'*64):
        return Client(self.url,'r'*32).request('/v1/task-adapter-probe',{'nonce':nonce})['descriptor']

    def verified(self,token,nonce='a'*64,**changes):
        return verify_descriptor(token,self.keys[2].public_key(),self.owner.public_key(),self.group,self.audience,
                                 self.url,nonce,now=changes.pop('now',self.now),**changes)

    def test_nonce_bound_probe_describes_echo_without_execution_or_database_changes(self):
        before=self.node._registry.db.total_changes
        with patch.object(EchoAdapter,'__call__',side_effect=AssertionError('must not execute')):result=self.inspect()
        self.assertEqual(result['status'],'compatible_metadata');self.assertEqual(result['executor'],self.subjects[2])
        self.assertEqual(result['contract_hash'],contract_hash(echo_contract()));self.assertEqual(result['execution'],'not_attempted')
        self.assertEqual(result['execution_authorization'],'not_checked');self.assertEqual(result['group_id'],self.group)
        self.assertEqual(self.node._registry.db.total_changes,before)
        self.assertEqual(self.node.discover(),[]);self.assertEqual(self.node.export_policy()['policy'],self.policy)
        self.assertEqual(self.node._registry.db.execute('SELECT COUNT(*) FROM durable_tasks').fetchone()[0],0)

    def test_read_credential_is_required_before_probe_or_signature_work(self):
        with patch.object(self.executor,'probe',side_effect=AssertionError('unauthorized inspection')):
            self.denied(lambda:self.inspect(token='x'*32))
        self.denied(lambda:Client(self.url,'').request('/v1/task-adapter-probe',{'nonce':'a'*64}))

    def test_route_is_disabled_without_explicit_task_executor(self):
        url,_=self.serve_tasks()
        self.denied(lambda:self.inspect(url=url),404)

    def test_probe_schema_query_method_host_and_origin_are_strict(self):
        for payload in ({},{'nonce':True},{'nonce':'a'*63},{'nonce':'A'*64},{'nonce':'a'*64,'task':'run'}):
            self.denied(lambda:Client(self.url,'r'*32).request('/v1/task-adapter-probe',payload),400)
        for path in ('/v1/task-adapter-probe?nonce=x','/v1/task-adapter-probe/'):
            self.denied(lambda:Client(self.url,'r'*32).request(path,{'nonce':'a'*64}),404)
        self.denied(lambda:Client(self.url,'r'*32).request('/v1/task-adapter-probe'),404)
        for header in ({'Host':'foreign.example'},{'Origin':'https://foreign.example'}):
            req=Request(self.url+'/v1/task-adapter-probe',data=json.dumps({'nonce':'a'*64}).encode(),
                        headers={'Authorization':'Bearer '+'r'*32}|header)
            self.denied(lambda:urlopen(req,timeout=2))

    def test_custom_callback_cannot_claim_reference_contract_or_run_describe_hooks(self):
        class Product:
            def __call__(self,text):raise AssertionError('product execution')
            def describe(self):raise AssertionError('implicit product startup')
        with patch.object(self.executor,'adapter',Product()):self.denied(self.inspect,503)

    def test_probe_cannot_restart_a_closed_executor(self):
        self.executor.close();self.denied(self.inspect,503)
        self.assertEqual(self.node._registry.db.execute('SELECT COUNT(*) FROM durable_tasks').fetchone()[0],0)

    def test_stale_or_missing_policy_denies_metadata_instead_of_renewing(self):
        self.now=402;self.denied(self.inspect)
        self.assertEqual(self.node.export_policy()['policy'],self.policy)
        self.now=110
        with self.node._registry.db:self.node._registry.db.execute('DELETE FROM group_policy')
        self.denied(self.inspect);self.assertIsNone(self.node.export_policy()['policy'])

    def test_revoked_executor_or_insufficient_scope_cannot_advertise(self):
        with patch.object(self.executor,'grant',issue_grant(self.owner,self.keys[2].public_key(),self.group,['join'],now=100)):
            self.denied(self.inspect)
        jti=verify_grant(self.grants[2],self.owner.public_key(),self.group,now=110)['jti']
        self.node.revoke(issue_revocation(self.owner,self.group,jti));self.denied(self.inspect)

    def test_removed_executor_and_terminal_group_cannot_advertise(self):
        removed=self.members.copy();removed.pop(self.subjects[2])
        token=revise_policy(self.owner,self.policy,removed,now=110);self.node.apply_policy(token);self.denied(self.inspect)
        terminal=revise_policy(self.owner,token,{},now=110,dissolve=True);self.node.apply_policy(terminal);self.denied(self.inspect)

    def test_descriptor_expiry_is_clipped_to_fractional_policy_deadline(self):
        self.now=401.5;result=self.inspect()
        self.assertEqual(result['valid_until'],402);self.assertEqual(result['checked_at'],401.5)
        self.now=402;self.denied(self.inspect)

    def test_descriptor_expiry_is_clipped_to_executor_grant_deadline(self):
        grant=issue_grant(self.owner,self.keys[2].public_key(),self.group,self.permissions,now=100,lifetime=11)
        members=copy.deepcopy(self.members);members[self.subjects[2]]['grant_ids']=[verify_grant(grant,self.owner.public_key(),self.group,now=110)['jti']]
        self.node.apply_policy(revise_policy(self.owner,self.policy,members,now=110));self.executor.grant=grant
        self.now=110.5;self.assertEqual(self.inspect()['valid_until'],111)
        self.now=111;self.denied(self.inspect)

    def test_signature_and_all_original_context_bindings_are_verified(self):
        claim=verify(self.descriptor(),self.keys[2].public_key(),DESCRIPTOR_TYPE)
        for mutation in ({'version':True},{'owner':self.subjects[0]},{'group_id':'other'},{'audience':'other'},
                         {'executor':self.subjects[1]},{'source':'https://other.example'},{'nonce':'b'*64},{'extra':True}):
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                self.verified(sign(self.keys[2],claim|mutation,DESCRIPTOR_TYPE))
        with self.assertRaises(ValueError):self.verified(sign(Ed25519PrivateKey.generate(),claim,DESCRIPTOR_TYPE))

    def test_descriptor_freshness_and_timestamp_types_are_strict(self):
        claim=verify(self.descriptor(),self.keys[2].public_key(),DESCRIPTOR_TYPE)
        for mutation in ({'issued_at':True},{'expires_at':True},{'expires_at':110},{'expires_at':126},
                         {'issued_at':116,'expires_at':125},{'issued_at':-1},{'expires_at':2**53}):
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.verified(sign(self.keys[2],claim|mutation,DESCRIPTOR_TYPE))
        for now in (float('nan'),float('inf'),True,-1):
            with self.subTest(now=str(now)),self.assertRaises(ValueError):self.verified(self.descriptor(),now=now)

    def test_replayed_descriptor_fails_new_client_nonce(self):
        old=self.descriptor()
        with patch('tailnet_agents.adapter_probe.secrets.token_hex',return_value='b'*64),patch.object(Client,'request',return_value={'descriptor':old}):
            with self.assertRaises(ValueError):self.inspect()

    def test_expiry_during_transport_is_rechecked_after_response(self):
        real=Client.request
        def slow(client,*args,**kwargs):
            value=real(client,*args,**kwargs);self.now=126;return value
        with patch.object(Client,'request',slow),self.assertRaises(ValueError):self.inspect()

    def test_unknown_contracts_and_response_fields_are_not_trusted(self):
        claim=verify(self.descriptor(),self.keys[2].public_key(),DESCRIPTOR_TYPE)
        for contract in (echo_contract()|{'product':'codex'},echo_contract()|{'automatic_retry':True},None):
            with self.subTest(contract=contract),self.assertRaises(ValueError):self.verified(sign(self.keys[2],claim|{'contract':contract},DESCRIPTOR_TYPE))
        for response in ({},{'descriptor':self.descriptor(),'grant':'SECRET'},[],{'descriptor':False}):
            with patch.object(Client,'request',return_value=response),self.assertRaises(ValueError):self.inspect()

    def test_wrong_pins_group_or_audience_do_not_become_compatible(self):
        for options in ({'owner':Ed25519PrivateKey.generate().public_key()},{'key':self.keys[1].public_key()},
                        {'group':'other'},{'audience':'other'}):
            with self.subTest(options=list(options)),self.assertRaises(ValueError):self.inspect(**options)

    def test_invalid_context_and_credentials_fail_before_network(self):
        with patch.object(Client,'request',side_effect=AssertionError('network')):
            for options in ({'group':''},{'audience':True},{'token':'short'},{'token':'x'*32+'\n'},{'key':self.owner.public_key()}):
                with self.subTest(options=list(options)),self.assertRaises(ValueError):self.inspect(**options)

    def test_concurrent_probes_have_fresh_nonces_without_mutating_task_state(self):
        before=self.node._registry.db.total_changes
        real=Client.request;nonces=[]
        def tracked(client,path,body=None,**kwargs):nonces.append(body['nonce']);return real(client,path,body,**kwargs)
        with patch.object(Client,'request',tracked),ThreadPoolExecutor(4) as pool:results=list(pool.map(lambda _:self.inspect(),range(8)))
        self.assertEqual(len(set(nonces)),8);self.assertTrue(all(row['executor']==self.subjects[2] for row in results))
        self.assertEqual(self.node._registry.db.total_changes,before)

    def test_probe_does_not_submit_resume_or_recover_existing_tasks(self):
        caller=self.client();caller.queue('queued before probe')
        with patch.object(self.executor,'_run',side_effect=TaskUnavailable('pause')):self.denied(caller.flush,503)
        before=self.node._registry.db.total_changes
        with patch.object(EchoAdapter,'__call__',side_effect=AssertionError('task')):self.inspect()
        self.assertEqual(self.node._registry.db.total_changes,before)
        self.assertEqual(self.node._registry.db.execute('SELECT status FROM durable_tasks').fetchone()[0],'queued')
        self.assertEqual(caller.status(),{'pending':1})

    def test_same_host_executors_remain_distinct_and_restart_keeps_original_binding(self):
        other=self.directory(database=str(self.root/'other.sqlite3'));self.addCleanup(other.close)
        executor=TaskExecutor(other,self.keys[1],self.grants[1]);self.addCleanup(executor.close)
        url,_=self.serve_tasks(executor,node=other)
        a,b=self.inspect(),self.inspect(url=url,key=self.keys[1].public_key())
        self.assertNotEqual(a['executor'],b['executor']);self.assertEqual(a['group_id'],b['group_id'])
        self.executor.close();self.node.close()
        self.node=VerifiedDirectory(self.owner.public_key(),self.group,self.audience,require_policy=True,
            database=str(self.root/'directory.sqlite3'),clock=lambda:self.now);self.addCleanup(self.node.close)
        self.executor=TaskExecutor(self.node,self.keys[2],self.grants[2]);self.addCleanup(self.executor.close)
        self.server.RequestHandlerClass=handler(self.node,'r'*32,task_executor=self.executor)
        restored=self.inspect();self.assertEqual(restored['executor'],a['executor']);self.assertEqual(restored['group_id'],self.group)

    def test_tls_ca_hostname_and_source_binding_are_checked(self):
        paths=certificates(self.root);url,_=self.serve_tasks(self.executor,tls=paths)
        self.assertEqual(self.inspect(url=url,ca_file=paths['ca'])['source'],url)
        for options in ({'url':url},{'url':url.replace('localhost','127.0.0.1'),'ca_file':paths['ca']}):
            with self.subTest(options=list(options)),self.assertRaises(OSError):self.inspect(**options)

    def test_ambient_proxy_and_redirect_cannot_receive_probe_credential(self):
        received=[]
        class Trap(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(inner):received.append(inner.headers.get('Authorization'));inner.send_response(500);inner.end_headers()
        trap=ThreadingHTTPServer(('127.0.0.1',0),Trap);thread=threading.Thread(target=trap.serve_forever,daemon=True);thread.start()
        self.addCleanup(lambda:(trap.shutdown(),trap.server_close(),thread.join()))
        destination=f'http://127.0.0.1:{trap.server_port}'
        with patch.dict(os.environ,{'HTTP_PROXY':destination,'HTTPS_PROXY':destination,'NO_PROXY':''}):self.inspect()
        class Redirect(Trap):
            def do_POST(inner):inner.send_response(307);inner.send_header('Location',destination+'/v1/task-adapter-probe');inner.end_headers()
        self.server.RequestHandlerClass=Redirect
        self.denied(self.inspect,307);self.assertEqual(received,[])

    def test_cli_uses_only_public_pins_reports_metadata_and_sanitizes_errors(self):
        self.now=int(time.time());self.executor.close()
        self.grants=[issue_grant(self.owner,key.public_key(),self.group,self.permissions,now=self.now) for key in self.keys]
        members={self.subjects[i]:{'permissions':self.permissions,'grant_ids':[verify_grant(grant,self.owner.public_key(),self.group,now=self.now)['jti']]}
                 for i,grant in enumerate(self.grants)}
        self.node.apply_policy(revise_policy(self.owner,self.policy,members,now=self.now))
        self.executor=TaskExecutor(self.node,self.keys[2],self.grants[2]);self.addCleanup(self.executor.close)
        self.server.RequestHandlerClass=handler(self.node,'r'*32,task_executor=self.executor)
        owner=self.root/'owner.pub';executor=self.root/'executor.pub'
        owner.write_text(encode(public_bytes(self.owner.public_key())));executor.write_text(encode(public_bytes(self.keys[2].public_key())))
        command=[sys.executable,'-m','tailnet_agents.adapters','probe','--url',self.url,'--authority-public-key',str(owner),
            '--group-id',self.group,'--audience',self.audience,'--executor-public-key',str(executor),'--token-env','ADAPTER_TEST_TOKEN']
        before=self.node._registry.db.total_changes
        result=subprocess.run(command,capture_output=True,text=True,timeout=5,env=os.environ|{'ADAPTER_TEST_TOKEN':'r'*32})
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stderr,'')
        self.assertEqual(json.loads(result.stdout)['status'],'compatible_metadata');self.assertNotIn('r'*32,result.stdout)
        self.assertEqual(self.node._registry.db.total_changes,before)
        result=subprocess.run(command,capture_output=True,text=True,timeout=5,env=os.environ|{'ADAPTER_TEST_TOKEN':'SECRET'+'x'*32})
        self.assertEqual(result.returncode,1);self.assertEqual(result.stdout,'');self.assertNotIn('SECRET',result.stderr)
        self.assertIn('No task was submitted',result.stderr)

    def test_truncated_transport_is_failure_without_claiming_compatibility(self):
        with patch.object(Client,'request',side_effect=IncompleteRead(b'SECRET',20)):
            with self.assertRaises(IncompleteRead):self.inspect()
        self.assertEqual(self.node._registry.db.execute('SELECT COUNT(*) FROM durable_tasks').fetchone()[0],0)
