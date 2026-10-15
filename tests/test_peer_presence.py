import copy
import json
import os
import selectors
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch
import test_agent_runtime as fixtures

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tailnet_agents.agent_runtime import AgentRuntime
    from tailnet_agents.admission_server import handler, AdmissionHTTPServer, transport_config
    from tailnet_agents.client import Client
    from tailnet_agents.group_policy import revise_policy
    from tailnet_agents.identity import AdmissionError, identity_id, sign, verify_grant, encode, public_bytes
    from tailnet_agents.presence import PRESENCE_TYPE, make_presence, verify_presence
    from tailnet_agents.policy_delivery import PolicyTarget, load_policy_targets
    from tailnet_agents.peer_presence import PresenceSynchronizer, read_peer_presence
    from tailnet_agents.verified_directory import VerifiedDirectory, issue_revocation
    from test_admission_tls import certificates
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@unittest.skipUnless(HAS_CRYPTO, 'install identity extra')
class PeerPresenceTests(unittest.TestCase):
    directory = fixtures.AgentRuntimeTests.directory
    serve = fixtures.AgentRuntimeTests.serve
    runtime = fixtures.AgentRuntimeTests.runtime
    presence = fixtures.AgentRuntimeTests.presence
    client = fixtures.AgentRuntimeTests.client
    rejected = fixtures.AgentRuntimeTests.rejected
    approve_second = fixtures.AgentRuntimeTests.approve_second

    def setUp(self):
        fixtures.AgentRuntimeTests.setUp(self)
        self.target = self.directory()
        self.export_url = self.export_server(self.node)
        self.source = PolicyTarget('source-a', self.export_url, self.group, 'r'*32)
        self.sync = PresenceSynchronizer(self.target, [self.source])
        self.addCleanup(self.sync.stop)

    def export_server(self, node, *, enabled=True, synchronizer=None, tls=None):
        allowed, context = (None, None) if tls is None else transport_config('127.0.0.1',tls['cert'],tls['key'],['localhost','127.0.0.1'])
        scheme = 'https' if tls else 'http'
        server = AdmissionHTTPServer(('127.0.0.1',0),handler(node,'r'*32,allowed,scheme,presence_export=enabled,presence_synchronizer=synchronizer),context)
        thread = threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        def stop(): server.shutdown();server.server_close();thread.join()
        self.addCleanup(stop)
        return f'{scheme}://'+('localhost' if tls else '127.0.0.1')+':'+str(server.server_port)

    def view(self, node=None, **options):
        return (node or self.target).peer_presence_status(**options)

    def entry(self, node=None):
        return self.view(node)['entries'][0]

    def pull(self):
        return self.sync.sync_once()

    def register(self):
        runtime = self.runtime()
        self.assertEqual(runtime.step()['state'],'registered')
        return runtime

    def test_construction_is_offline_and_source_export_is_opt_in_read_protected(self):
        with patch.object(self.source.client,'request') as request:
            sync = PresenceSynchronizer(self.target,[self.source]);sync.stop();request.assert_not_called()
        self.rejected(404,lambda:Client(self.url,'r'*32).request('/v1/presence-export'))
        for path in ('/v1/presence-export','/v1/peer-presence','/v1/presence-sync'):
            self.rejected(403,lambda:Client(self.export_url,'wrong').request(path))
        self.assertEqual(self.node.export_policy()['policy'],self.policy)
        self.assertEqual(self.target.discover(),[])

    def test_replication_verifies_grant_and_preserves_origin_without_local_registration(self):
        self.register()
        before = self.target.export_policy()
        self.assertEqual(self.pull()['sources'][0]['state'],'synced')
        entry = self.entry()
        self.assertEqual(entry['state'],'online')
        self.assertEqual(entry['subject'],self.subject)
        self.assertEqual(entry['observations'][0]['source'],self.source.public())
        self.assertEqual(self.target.discover(),[])
        self.assertEqual(self.target.presence_status()['entries'],[])
        self.assertEqual(self.target.export_policy(),before)
        for table in ('agents','admission_grants'):
            self.assertEqual(self.target._registry.db.execute('SELECT COUNT(*) FROM '+table).fetchone(),(0,))
        self.assertNotIn(self.grant,json.dumps(self.view()))
        self.assertNotIn(self.grant,json.dumps(self.node.presence_status()))

    def test_identical_polls_and_changed_receipt_times_cannot_extend_lease(self):
        self.register();self.pull()
        deadline = self.entry()['observations'][0]['expires_at']
        self.now += 4
        self.pull()
        observation = self.entry()['observations'][0]
        self.assertEqual(observation['expires_at'],deadline)
        self.assertEqual(observation['observed_at'],110)
        self.assertEqual(observation['received_at'],114)
        self.now = deadline
        self.assertEqual(self.entry()['state'],'expired')
        self.pull()
        self.assertEqual(self.entry()['state'],'expired')

    def test_authorization_uses_local_policy_and_learned_revocations_on_every_read(self):
        self.register();self.pull()
        self.target.revoke(issue_revocation(self.owner,self.group,self.jti))
        self.assertEqual(self.entry()['state'],'unauthorized')
        self.pull()
        self.assertEqual(self.entry()['state'],'unauthorized')
        self.assertEqual(self.node.presence_status()['entries'][0]['state'],'online')

    def test_policy_removal_expiry_and_dissolution_never_grant_membership(self):
        self.register();self.pull()
        self.target.apply_policy(revise_policy(self.owner,self.policy,{},now=111))
        self.assertEqual(self.entry()['state'],'unauthorized')
        self.target.apply_policy(revise_policy(self.owner,self.target.export_policy()['policy'],{},dissolve=True,now=112))
        self.assertEqual(self.entry()['state'],'unauthorized')
        self.assertEqual(self.target.policy_status()['state'],'dissolved')
        self.assertEqual(self.target.discover(),[])
        self.now = 401
        self.assertEqual(self.entry(self.node)['state'],'unauthorized')

    def test_missing_local_policy_remains_unapproved_after_pull(self):
        self.register()
        empty = VerifiedDirectory(self.owner.public_key(),self.group,'empty',require_policy=True,clock=lambda:self.now)
        self.addCleanup(empty.close)
        sync = PresenceSynchronizer(empty,[self.source]);self.addCleanup(sync.stop)
        sync.sync_once()
        self.assertEqual(self.entry(empty)['state'],'unauthorized')
        self.assertEqual(empty.export_policy(),{'policy':None})
        self.assertEqual(empty.discover(),[])

    def test_offline_dominates_old_online_even_after_replay_and_reconnect(self):
        runtime = self.register();self.pull()
        online = self.node.export_presence()
        self.assertEqual(runtime.step(offline=True)['state'],'offline')
        self.pull()
        self.assertEqual(self.entry()['state'],'offline')
        self.target.apply_peer_presence(self.source,online)
        self.assertEqual(self.entry()['state'],'offline')
        self.assertEqual(runtime.step()['state'],'registered')
        self.pull()
        self.assertEqual(self.entry()['state'],'online')
        self.assertEqual(self.entry()['head']['sequence'],3)

    def test_target_restart_retains_original_group_cache_deadline_and_high_water(self):
        path = str(self.root/'replica.sqlite3')
        target = self.directory(database=path)
        sync = PresenceSynchronizer(target,[self.source]);self.addCleanup(sync.stop)
        runtime = self.register();sync.sync_once()
        old = self.node.export_presence()
        self.assertEqual(runtime.step(offline=True)['state'],'offline');sync.sync_once()
        target.close()
        restored = VerifiedDirectory(self.owner.public_key(),self.group,'restored',database=path,require_policy=True,clock=lambda:self.now)
        self.addCleanup(restored.close)
        restored.configure_presence_sources([self.source])
        restored.apply_peer_presence(self.source,old)
        self.assertEqual(self.entry(restored)['state'],'offline')
        self.assertEqual(restored.group_id,self.group)
        self.assertEqual(restored.export_policy()['policy'],self.policy)
        self.assertEqual(restored.discover(),[])

    def test_new_generation_supersedes_other_sources_and_removing_source_does_not_rollback(self):
        runtime = self.register();self.pull()
        older = self.node.export_presence()
        runtime.close()
        runtime = self.runtime()
        self.assertEqual(runtime.step()['state'],'registered')
        other = PolicyTarget('source-b',self.url,self.group,'r'*32)
        self.target.configure_presence_sources([self.source,other])
        self.target.apply_peer_presence(other,self.node.export_presence())
        self.assertEqual(self.entry()['head']['generation'],2)
        self.target.configure_presence_sources([self.source])
        self.target.apply_peer_presence(self.source,older)
        self.assertEqual(self.entry()['state'],'superseded')
        self.assertEqual(self.entry()['head']['generation'],2)

    def test_boot_and_equal_sequence_equivocation_stay_conflicted_until_new_generation(self):
        runtime = self.register();self.pull()
        original = self.node.export_presence()
        for changes in ({'boot_id':'b'*32,'sequence':99},{'state':'offline'}):
            page = copy.deepcopy(original)
            row = page['entries'][0]
            claims = verify_presence(row['presence'],self.agent.public_key(),self.owner.public_key(),self.group,row['record'])
            row['presence'] = sign(self.agent,claims|changes,PRESENCE_TYPE)
            row['state'] = changes.get('state','online')
            self.target.apply_peer_presence(self.source,page)
            self.assertEqual(self.entry()['state'],'conflict')
        self.assertEqual(runtime.step()['state'],'registered');self.pull()
        self.assertEqual(self.entry()['state'],'conflict')
        runtime.close();self.runtime().step();self.pull()
        self.assertEqual(self.entry()['state'],'online')
        self.assertEqual(self.entry()['head']['generation'],2)

    def test_same_host_identities_page_independently_and_local_vs_peer_are_distinct(self):
        key,grant = self.approve_second()
        self.target.apply_policy(self.node.export_policy()['policy'])
        self.register()
        self.runtime('second',key=key,grant=grant).step()
        self.pull()
        first = self.view(limit=1)
        second = self.view(limit=1,after=first['next_after'])
        self.assertTrue(first['has_more']);self.assertFalse(second['has_more'])
        self.assertNotEqual(first['entries'][0]['subject'],second['entries'][0]['subject'])
        self.assertEqual(first['entries'][0]['observations'][0]['record']['endpoint'],second['entries'][0]['observations'][0]['record']['endpoint'])
        self.assertEqual(self.entry(self.node)['observations'][0]['source']['id'],'local')

    def test_all_sources_are_polled_even_when_first_is_healthy_or_fails(self):
        self.register()
        failed = PolicyTarget('failed',self.url,self.group,'wrong'*8)
        sync = PresenceSynchronizer(self.target,[self.source,failed]);self.addCleanup(sync.stop)
        states = sync.sync_once()['sources']
        self.assertEqual([state['state'] for state in states],['synced','error'])
        self.assertEqual(self.entry()['state'],'online')
        sync = PresenceSynchronizer(self.target,[failed,self.source]);self.addCleanup(sync.stop)
        self.assertEqual([state['state'] for state in sync.sync_once()['sources']],['error','synced'])

    def test_export_does_not_forward_cached_peers_or_leak_grants_to_normal_readers(self):
        self.register();self.pull()
        self.assertEqual(self.target.export_presence()['entries'],[])
        url = self.export_server(self.target)
        for path in ('/v1/presence','/v1/peer-presence','/v1/presence-sync'):
            self.assertNotIn(self.grant,json.dumps(Client(url,'r'*32).request(path)))
        self.assertIn(self.grant,json.dumps(Client(self.export_url,'r'*32).request('/v1/presence-export')))

    def test_bad_page_is_atomic_and_rejects_signature_grant_binding_scope_and_deadline(self):
        self.register();page = self.node.export_presence()
        mutations = [lambda p:p.update(group_id='foreign'),lambda p:p.update(has_more=True,next_after=''),
            lambda p:p['entries'][0].update(grant='bad'),lambda p:p['entries'][0].update(presence='bad'),
            lambda p:p['entries'][0]['record'].update(endpoint='https://changed.example'),
            lambda p:p['entries'][0].update(expires_at=999999),lambda p:p.update(observed_at=116)]
        for mutate in mutations:
            changed=copy.deepcopy(page);mutate(changed)
            with self.assertRaises(ValueError):self.target.apply_peer_presence(self.source,changed)
            self.assertEqual(self.view()['entries'],[])
            self.assertEqual(self.target._registry.db.execute('SELECT COUNT(*) FROM presence_heads').fetchone(),(0,))

    def test_receiver_sql_failure_rolls_back_cache_and_heads_together(self):
        runtime = self.register();self.pull()
        before=self.view()
        self.now += 1;runtime.step()
        with self.target._registry.db:
            self.target._registry.db.execute("CREATE TRIGGER fail_cache BEFORE INSERT ON peer_presence BEGIN SELECT RAISE(ABORT,'test failure'); END")
        self.assertEqual(self.pull()['sources'][0]['state'],'error')
        after=self.view();after['observed_at']=before['observed_at']
        self.assertEqual(after,before)

    def test_source_restart_invalidates_observed_lease_and_same_claim_cannot_rearm_it(self):
        self.register();self.pull()
        original=self.node.export_presence()
        page=copy.deepcopy(original);page['entries'][0].update(expires_at=0,state='expired')
        self.target.apply_peer_presence(self.source,page)
        self.target.apply_peer_presence(self.source,original)
        self.assertEqual(self.entry()['state'],'expired')
        self.assertEqual(self.entry()['observations'][0]['expires_at'],0)

    def test_stop_blocks_late_network_apply_without_holding_directory_lock(self):
        self.register()
        original,entered,release=self.source.client.request,threading.Event(),threading.Event()
        def delayed(*args,**kwargs):
            response=original(*args,**kwargs);entered.set();release.wait(4);return response
        with patch.object(self.source.client,'request',side_effect=delayed):
            thread=threading.Thread(target=self.sync.sync_once);thread.start()
            try:
                self.assertTrue(entered.wait(3))
                self.assertEqual(self.target.export_policy()['policy'],self.policy)
                self.sync.stop()
            finally:release.set();thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.view()['entries'],[])

    def test_bad_configuration_and_queries_fail_without_discovery_or_group_creation(self):
        for sources in ([PolicyTarget('local',self.export_url,self.group,'r'*32)],
                        [PolicyTarget('other',self.export_url,'foreign','r'*32)],
                        [self.source,self.source]):
            with self.assertRaises(ValueError):PresenceSynchronizer(self.target,sources)
        for interval in (0,True,float('nan'),float('inf')):
            with self.assertRaises(ValueError):PresenceSynchronizer(self.target,[self.source],interval)
        for path in ('/v1/presence-export?limit=0','/v1/peer-presence?after=bad','/v1/presence-sync?extra=1'):
            self.rejected(400,lambda:Client(self.export_url,'r'*32).request(path))

    def test_https_source_checks_ca_and_hostname(self):
        self.register();paths=certificates(str(self.root));url=self.export_server(self.node,tls=paths)
        for endpoint,ca,expected in ((url,None,'error'),(url.replace('localhost','127.0.0.1'),paths['ca'],'error'),(url,paths['ca'],'synced')):
            source=PolicyTarget('tls',endpoint,self.group,'r'*32,ca)
            sync=PresenceSynchronizer(self.target,[source]);self.addCleanup(sync.stop)
            self.assertEqual(sync.sync_once()['sources'][0]['state'],expected)

    def test_periodic_sync_reconnects_and_status_does_not_expose_credentials(self):
        self.register()
        self.sync.interval=0.03
        self.sync.start()
        deadline=time.monotonic()+3
        while not self.view()['entries'] and time.monotonic()<deadline:self.sync.stopped.wait(0.03)
        self.assertEqual(self.entry()['state'],'online')
        self.sync.stop()
        self.assertEqual(self.sync.status()['state'],'stopped')
        self.assertNotIn('r'*32,json.dumps(self.sync.status()))

    def test_real_service_cli_replicates_with_original_group_and_export_off_by_default(self):
        self.now=int(time.time())
        # Existing keys/group are retained; only human-signed authorization is renewed.
        from tailnet_agents.identity import issue_grant
        self.grant=issue_grant(self.owner,self.agent.public_key(),self.group,['join'],now=self.now)
        credential=verify_grant(self.grant,self.owner.public_key(),self.group,now=self.now)['jti']
        self.policy=revise_policy(self.owner,self.policy,{self.subject:{'permissions':['join'],'grant_ids':[credential]}},now=self.now)
        self.node.apply_policy(self.policy)
        self.register()
        pin=self.root/'owner.pub';pin.write_text(encode(public_bytes(self.owner.public_key())))
        policy=self.root/'policy';policy.write_text(self.policy)
        config=self.root/'sources.json';config.write_text(json.dumps([{'id':'source-a','url':self.export_url,'group_id':self.group,'token_env':'TEST_PRESENCE_SOURCE_TOKEN'}]))
        command=[sys.executable,'-m','tailnet_agents.admission_server','--port','0','--authority-public-key',str(pin),'--group-id',self.group,'--audience','replica','--database',str(self.root/'cli.sqlite3'),'--policy-file',str(policy),'--presence-sources-file',str(config),'--presence-sync-interval','1']
        process=subprocess.Popen(command,env=os.environ|{'TAILNET_VERIFIED_READ_TOKEN':'t'*32,'TEST_PRESENCE_SOURCE_TOKEN':'r'*32},stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout,selectors.EVENT_READ);self.assertTrue(selector.select(8))
            url=process.stdout.readline().strip().split()[-1]
            client=Client(url,'t'*32)
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                page=client.request('/v1/peer-presence')
                if page['entries']:break
                time.sleep(0.05)
            self.assertEqual(page['entries'][0]['state'],'online')
            self.assertEqual(client.request('/v1/agents'),{'agents':[]})
            self.rejected(404,lambda:client.request('/v1/presence-export'))
            result=subprocess.run([sys.executable,'-m','tailnet_agents.peer_presence','--url',url,'--authority-public-key',str(pin),'--group-id',self.group],env=os.environ|{'TAILNET_VERIFIED_READ_TOKEN':'t'*32},capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(result.stdout)['entries'][0]['subject'],self.subject)
        finally:
            process.send_signal(signal.SIGINT)
            try:process.communicate(timeout=8)
            except subprocess.TimeoutExpired:process.kill();process.communicate(timeout=5)

    def test_local_policy_deadline_is_persisted_and_renewal_cannot_rearm_old_claim(self):
        target=self.directory(policy_max_age=30)
        sync=PresenceSynchronizer(target,[self.source]);self.addCleanup(sync.stop)
        runtime=self.register();sync.sync_once()
        self.assertEqual(self.entry(target)['observations'][0]['expires_at'],131)
        self.now=132
        target.apply_policy(revise_policy(self.owner,self.policy,self.members,now=132))
        sync.sync_once()
        self.assertEqual(self.entry(target)['state'],'expired')
        self.assertEqual(self.entry(target)['observations'][0]['expires_at'],131)
        runtime.step();sync.sync_once()
        self.assertEqual(self.entry(target)['state'],'online')

    def test_partition_expires_original_deadline_then_recovers_with_new_sequence(self):
        runtime=self.register();self.pull()
        old=self.node.export_presence()
        with patch.object(self.source.client,'request',side_effect=OSError('unavailable')):
            self.assertEqual(self.pull()['sources'][0]['state'],'error')
            self.now=140
            self.assertEqual(self.entry()['state'],'expired')
        self.now=141;runtime.step();self.pull()
        self.assertEqual(self.entry()['state'],'online')
        self.target.apply_peer_presence(self.source,old)
        self.assertEqual(self.entry()['head']['sequence'],2)

    def test_grant_subject_and_permission_scope_are_independently_verified(self):
        from tailnet_agents.identity import issue_grant
        self.register();page=self.node.export_presence()
        other=Ed25519PrivateKey.generate()
        page['entries'][0]['grant']=issue_grant(self.owner,other.public_key(),self.group,['join'],now=100)
        with self.assertRaises(ValueError):self.target.apply_peer_presence(self.source,page)
        grant=issue_grant(self.owner,self.agent.public_key(),self.group,['join','discover'],now=100)
        credential=verify_grant(grant,self.owner.public_key(),self.group,now=self.now)['jti']
        self.target.apply_policy(revise_policy(self.owner,self.policy,{self.subject:{'permissions':['join'],'grant_ids':[credential]}},now=110))
        page['entries'][0]['grant']=grant
        self.target.apply_peer_presence(self.source,page)
        self.assertEqual(self.entry()['state'],'unauthorized')

    def test_bounded_scan_continues_next_poll_and_rescans_from_start_after_completion(self):
        key,grant=self.approve_second()
        self.target.apply_policy(self.node.export_policy()['policy'])
        self.register();self.runtime('second',key=key,grant=grant).step()
        def one_row(path):
            from urllib.parse import parse_qs,urlparse
            after=parse_qs(urlparse(path).query,keep_blank_values=True)['after'][0]
            return self.node.export_presence(after,1)
        sync=PresenceSynchronizer(self.target,[self.source],max_pages=1);self.addCleanup(sync.stop)
        with patch.object(self.source.client,'request',side_effect=one_row):
            self.assertEqual(sync.sync_once()['sources'][0]['state'],'catching_up')
            self.assertEqual(len(self.view()['entries']),1)
            self.assertEqual(sync.sync_once()['sources'][0]['state'],'synced')
            self.assertEqual(len(self.view()['entries']),2)
            self.assertEqual(sync.sync_once()['sources'][0]['state'],'catching_up')

    def test_reader_validates_heads_sources_signatures_and_conservatively_expires(self):
        self.register();self.pull()
        client=Client(self.export_url,'r'*32)
        page=self.view()
        with patch.object(client,'request',return_value=copy.deepcopy(page)), patch('tailnet_agents.peer_presence.time.time',return_value=140):
            self.assertEqual(read_peer_presence(client,self.owner.public_key(),self.group)['entries'][0]['state'],'expired')
        mutations=[lambda p:p['entries'][0]['head'].update(generation=True),
            lambda p:p['entries'][0]['observations'][0]['source'].update(group_id='foreign'),
            lambda p:p['entries'][0]['observations'][0].update(presence='bad'),
            lambda p:p['entries'][0]['observations'][0].update(expires_at=99999),
            lambda p:p['policy'].update(state='stale'),lambda p:p.update(next_after='')]
        for mutate in mutations:
            changed=copy.deepcopy(page);mutate(changed)
            with patch.object(client,'request',return_value=changed),self.assertRaises(ValueError):
                read_peer_presence(client,self.owner.public_key(),self.group)


if __name__=='__main__':unittest.main()
