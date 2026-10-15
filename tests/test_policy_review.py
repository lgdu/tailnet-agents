"""Configured-source diagnosis, persistent signed evidence and explicit renewal."""
import copy
import json
from http.client import IncompleteRead
import sqlite3
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from urllib.error import URLError
import test_policy_delivery as fixtures

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tailnet_agents.chat import ChatStore
    from tailnet_agents.client import Client
    from tailnet_agents.group_policy import POLICY_TYPE, revise_policy
    from tailnet_agents.identity import AdmissionError, encode, sign, verify
    from tailnet_agents.policy_delivery import PolicyTarget, policy_hash
    from tailnet_agents.policy_review import digest
    from tailnet_agents.verified_directory import VerifiedDirectory
    from tailnet_agents.admission_server import handler, transport_config, AdmissionHTTPServer
    from test_admission_tls import certificates
    HAS_CRYPTO=True
except ImportError:
    HAS_CRYPTO=False


@unittest.skipUnless(HAS_CRYPTO,'install identity extra')
class PolicyReviewTests(unittest.TestCase):
    setUp=fixtures.PolicyDeliveryTests.setUp
    serve=fixtures.PolicyDeliveryTests.serve
    create=fixtures.PolicyDeliveryTests.create
    export=fixtures.PolicyDeliveryTests.export
    change=fixtures.PolicyDeliveryTests.change
    grant=fixtures.PolicyDeliveryTests.grant
    rejected=fixtures.PolicyDeliveryTests.rejected

    def group_source(self, *, group=None, name='source-a', age=300, initial=True):
        group=self.create() if group is None else group
        node=VerifiedDirectory(self.owner.public_key(),group,'directory',require_policy=True,
            clock=lambda:self.now,policy_max_age=age)
        self.addCleanup(node.close)
        calls=[]
        class Tracked(handler(node,'r'*32)):
            def do_GET(inner):calls.append(('GET',inner.path));super().do_GET()
            def do_POST(inner):calls.append(('POST',inner.path));super().do_POST()
        url=self.serve(Tracked)
        target=PolicyTarget(name,url,group,'r'*32)
        if initial:node.apply_policy(self.export(group)['policy'])
        return group,node,target,calls

    def configure(self,*targets):self.store.configure_policy_targets(targets)

    def payload(self,group):
        policy=self.export(group)
        return {'group_id':group,'expected_revision':policy['claims']['revision'],'policy_hash':policy['policy_hash']}

    def review(self,group,*,renew=False):
        return self.clients['owner'].request('/api/policy-renew-preview' if renew else '/api/policy-source-check',self.payload(group))

    def consent(self,preview,request_id='renewal'):
        return {key:value for key,value in preview.items() if key!='owner'} | {'request_id':request_id}

    def confirm(self,preview,**changes):
        return self.clients['owner'].request('/api/policy-renew-confirm',self.consent(preview) | changes)

    def replace(self,node,token):
        with node._registry.db:node._registry.db.execute('INSERT INTO group_policy VALUES(1,?) ON CONFLICT(id) DO UPDATE SET token=excluded.token',(token,))

    def variant(self,group,**changes):
        claims=self.export(group)['claims'] | changes
        return sign(self.owner,claims,POLICY_TYPE)

    def test_opening_management_exports_and_listing_targets_never_contacts_sources(self):
        group,node,target,calls=self.group_source();self.configure(target)
        for path in ('/api/groups','/api/group-policy?group_id='+group,'/api/policy-targets?group_id='+group):self.clients['owner'].request(path)
        self.assertEqual(calls,[]);self.assertEqual(self.export(group)['claims']['revision'],1)
        self.assertTrue(self.export(group)['evidence']['can_renew'])

    def test_reads_every_configured_source_only_get_with_independent_age_and_no_application(self):
        group,a,ta,ca=self.group_source(age=10)
        _,b,tb,cb=self.group_source(group=group,name='source-b',age=300)
        self.configure(ta,tb);self.now=111
        before=self.export(group)['policy'];result=self.review(group)['report']
        self.assertEqual([row['target']['id'] for row in result['sources']],['source-a','source-b'])
        self.assertEqual([row['freshness']['state'] for row in result['sources']],['stale','fresh'])
        self.assertEqual([row['relation'] for row in result['sources']],['same','same'])
        self.assertEqual(ca,[('GET','/v1/policies'),('GET','/v1/policy-sync'),('GET','/v1/policies')]);self.assertEqual(cb,ca)
        self.assertEqual(self.export(group)['policy'],before)
        self.assertEqual(a.discover(),[]);self.assertEqual(b.discover(),[])
        self.assertEqual(self.store.groups('owner')[0]['id'],group)

    def test_missing_or_unreachable_source_does_not_create_policy_or_permissions(self):
        group,node,target,calls=self.group_source(initial=False);self.configure(target)
        result=self.review(group,renew=True)
        self.assertEqual(result['report']['sources'][0]['state'],'missing')
        self.assertIsNotNone(result['preview']);self.assertIsNone(node.export_policy()['policy'])
        with patch.object(target.client,'request',side_effect=URLError('SECRET '+target.client.token)):
            failed=self.review(group,renew=True)
        self.assertEqual(failed['report']['sources'][0]['state'],'error')
        self.assertIsNotNone(failed['preview'])
        self.assertNotIn('SECRET',json.dumps(failed));self.assertNotIn(target.client.token,json.dumps(failed))
        self.assertEqual(self.export(group)['claims']['members'],{})

    def test_only_signing_admin_creator_can_check_or_preview_before_network(self):
        group,node,target,calls=self.group_source();self.configure(target)
        for actor in ('other','participant','observer'):
            for route in ('policy-source-check','policy-renew-preview','policy-renew-confirm'):
                self.rejected(403,lambda:self.clients[actor].request('/api/'+route,self.payload(group)))
        self.assertEqual(calls,[])
        foreign=self.create(name='Other group',request_id='another')
        result=self.review(foreign)['report'];self.assertEqual(result['sources'],[])
        self.assertEqual(calls,[])

    def test_malformed_requests_and_stale_local_consent_fail_before_network(self):
        group,node,target,calls=self.group_source();self.configure(target);body=self.payload(group)
        for bad in [body | {'expected_revision':True},body | {'extra':1},body | {'policy_hash':'bad'}]:
            self.rejected(400,lambda:self.clients['owner'].request('/api/policy-source-check',bad))
        self.rejected(409,lambda:self.clients['owner'].request('/api/policy-source-check',body | {'expected_revision':2}))
        self.assertEqual(calls,[])

    def test_newer_signed_source_is_retained_and_blocks_renewal_without_adoption(self):
        group,node,target,calls=self.group_source();self.configure(target)
        token=self.export(group)['policy'];higher=revise_policy(self.owner,token,{},now=101);node.apply_policy(higher)
        result=self.review(group,renew=True)
        self.assertEqual(result['report']['sources'][0]['relation'],'ahead')
        self.assertIn('remote_ahead',result['report']['evidence']['conflicts']);self.assertIsNone(result['preview'])
        self.assertEqual(self.export(group)['policy'],token)
        self.rejected(409,lambda:self.change(group,'renew',1,request_id='blocked'))
        self.assertEqual(node.export_policy()['policy'],higher)

    def test_behind_source_is_diagnostic_and_explicit_renewal_keeps_members_and_grant_ids(self):
        group,node,target,calls=self.group_source();self.configure(target)
        remote_before=node.export_policy()['policy']
        self.change(group,'approve',1,grant=self.grant(group));before=self.export(group)
        self.now=110;result=self.review(group,renew=True)
        self.assertEqual(result['report']['sources'][0]['relation'],'behind')
        self.assertEqual(self.export(group)['claims']['revision'],2)
        self.now=115;ack=self.confirm(result['preview'])
        current=self.export(group)
        self.assertEqual(ack['revision'],3);self.assertEqual(current['claims']['issued_at'],110)
        self.assertEqual(current['claims']['members'],before['claims']['members'])
        self.assertEqual(current['group_id'],group);self.assertEqual(len(current['audit']),3)
        self.assertEqual(node.export_policy()['policy'],remote_before)
        self.assertEqual(node._policy.current()['revision'],1)
        self.assertTrue(all(method=='GET' for method,_ in calls))

    def test_equivalent_serialization_is_not_equivocation(self):
        group,node,target,calls=self.group_source();self.configure(target)
        token=self.export(group)['policy'];claims=self.export(group)['claims']
        header=token.split('.')[0];payload=encode(json.dumps(claims,indent=1).encode());signed=header+'.'+payload
        equivalent=signed+'.'+encode(self.owner.sign(signed.encode()))
        self.replace(node,equivalent)
        result=self.review(group,renew=True)
        self.assertEqual(result['report']['sources'][0]['relation'],'equivalent')
        self.assertEqual(result['report']['evidence']['conflicts'],[]);self.assertIsNotNone(result['preview'])
        self.assertEqual(self.export(group)['policy'],token)

    def test_same_revision_conflict_survives_source_removal_and_process_restart(self):
        group,node,target,calls=self.group_source();self.configure(target)
        self.replace(node,self.variant(group,name='Owner fork'))
        result=self.review(group,renew=True)
        self.assertEqual(result['report']['sources'][0]['relation'],'conflict')
        self.assertIn('equivocation',result['report']['evidence']['conflicts']);self.assertIsNone(result['preview'])
        self.configure();self.store.close()
        self.store=ChatStore(self.database,policy_authority=self.authority);self.addCleanup(self.store.close)
        self.assertIn('equivocation',self.store.policy_export('owner',group)['evidence']['conflicts'])
        with self.assertRaises(FileExistsError):self.store.policy_change('owner',group,'renew',{'request_id':'restart','expected_revision':1})
        self.assertEqual(self.store.groups('owner')[0]['id'],group)

    def test_conflict_blocks_all_new_local_policy_revisions_including_dissolution(self):
        group,node,target,calls=self.group_source();self.configure(target)
        self.change(group,'approve',1,grant=self.grant(group))
        self.replace(node,self.variant(group,name='Fork'));self.review(group)
        self.rejected(409,lambda:self.change(group,'renew',2,request_id='r'))
        self.rejected(409,lambda:self.change(group,'remove',2,request_id='remove',subject=self.subject))
        fresh=self.grant(group)
        self.rejected(409,lambda:self.change(group,'approve',2,request_id='approve-again',grant=fresh))
        self.rejected(409,lambda:self.clients['owner'].request('/api/group-dissolve',{'group_id':group,'confirm_name':'Human approved'}))
        self.assertEqual(self.export(group)['claims']['revision'],2)

    def test_learned_dissolution_is_not_cleared_by_failing_or_removed_source(self):
        group,node,target,calls=self.group_source();self.configure(target)
        node.apply_policy(revise_policy(self.owner,self.export(group)['policy'],{},dissolve=True,now=101))
        result=self.review(group,renew=True);self.assertIsNone(result['preview'])
        self.assertTrue(result['report']['evidence']['terminal_known'])
        self.configure();again=self.review(group,renew=True)
        self.assertIsNone(again['preview']);self.assertIn('known_dissolution',again['report']['evidence']['conflicts'])
        self.assertEqual(self.export(group)['claims']['state'],'active')

    def test_cross_revision_time_rollback_and_post_terminal_history_are_diagnosed(self):
        group,a,ta,ca=self.group_source()
        _,b,tb,cb=self.group_source(group=group,name='source-b');self.configure(ta,tb)
        self.replace(a,self.variant(group,revision=2,issued_at=110,state='dissolved'))
        self.replace(b,self.variant(group,revision=3,issued_at=105))
        reasons=self.review(group)['report']['evidence']['conflicts']
        self.assertIn('time_rollback',reasons);self.assertIn('after_dissolution',reasons)
        self.assertIn('known_dissolution',reasons)

    def test_partial_read_failure_still_remembers_verified_higher_policy(self):
        group,node,target,calls=self.group_source()
        _,other,healthy,good_calls=self.group_source(group=group,name='healthy');self.configure(target,healthy)
        higher=self.export(group)['policy']
        for revision,error in enumerate((URLError('SECRET'),IncompleteRead(b'SECRET',20)),2):
            with self.subTest(error=type(error).__name__):
                higher=revise_policy(self.owner,higher,{},now=99+revision)
                with patch.object(target.client,'request',side_effect=[{'policy':higher},error]):result=self.review(group,renew=True)
                self.assertEqual([row['state'] for row in result['report']['sources']],['error','read'])
                self.assertIsNone(result['preview']);self.assertIn('remote_ahead',result['report']['evidence']['conflicts'])
                self.assertEqual(result['report']['evidence']['head_revision'],revision)
                self.assertNotIn('SECRET',json.dumps(result))
        self.assertEqual(len(good_calls),6)
        self.assertEqual(self.export(group)['claims']['revision'],1)

    def test_wrong_authority_group_and_tampered_signature_never_create_evidence(self):
        group,node,target,calls=self.group_source();self.configure(target);base=self.export(group)
        bad=[sign(Ed25519PrivateKey.generate(),base['claims'],POLICY_TYPE),
            sign(self.owner,base['claims'] | {'group_id':'foreign'},POLICY_TYPE),base['policy'][:-4]+'bad']
        for token in bad:
            with patch.object(target.client,'request',return_value={'policy':token}):result=self.review(group,renew=True)
            self.assertEqual(result['report']['sources'][0]['state'],'error')
            self.assertEqual(result['report']['evidence']['statements'],1)
            self.assertIsNotNone(result['preview'])

    def test_malformed_freshness_is_not_a_confirmed_source(self):
        group,node,target,calls=self.group_source();self.configure(target)
        real=target.client.request
        for status in [{'state':'fresh','max_age':True},{'state':'fresh','max_age':300,'revision':True,'issued_at':100,'expires_at':400}]:
            def respond(path,body=None):return {'policy':status} if path=='/v1/policy-sync' else real(path,body)
            with patch.object(target.client,'request',side_effect=respond):result=self.review(group)
            self.assertEqual(result['report']['sources'][0]['state'],'error')
            self.assertIsNone(result['report']['sources'][0]['freshness'])

    def test_policy_change_during_source_read_is_reported_and_both_signed_statements_retained(self):
        group,node,target,calls=self.group_source();self.configure(target)
        original=node.export_policy()['policy'];higher=revise_policy(self.owner,original,{},now=101)
        real=target.client.request;reads=[0]
        def changing(path,body=None):
            if path=='/v1/policies':
                reads[0]+=1
                if reads[0]==2:self.replace(node,higher)
            return real(path,body)
        with patch.object(target.client,'request',side_effect=changing):result=self.review(group,renew=True)
        self.assertEqual(result['report']['sources'][0]['state'],'changing')
        self.assertEqual(result['report']['evidence']['statements'],2);self.assertIsNone(result['preview'])

    def test_expiry_during_last_read_is_rechecked_against_signed_deadline(self):
        group,node,target,calls=self.group_source(age=10);self.configure(target);real=target.client.request;reads=[0]
        self.now=109
        def expire(path,body=None):
            response=real(path,body)
            if path=='/v1/policies':
                reads[0]+=1
                if reads[0]==2:self.now=111
            return response
        with patch.object(target.client,'request',side_effect=expire):row=self.review(group)['report']['sources'][0]
        self.assertEqual(row['freshness']['state'],'stale');self.assertEqual(row['freshness']['expires_at'],110)

    def test_future_policy_is_attributed_and_blocks_fork_without_adoption(self):
        group,node,target,calls=self.group_source();self.configure(target)
        self.replace(node,self.variant(group,revision=2,issued_at=1000))
        result=self.review(group,renew=True)
        self.assertEqual(result['report']['sources'][0]['freshness']['state'],'future')
        self.assertIsNone(result['preview']);self.assertEqual(self.export(group)['claims']['issued_at'],100)

    def test_previews_do_not_sign_and_confirmation_is_bound_to_fixed_time_and_original_members(self):
        group=self.create();self.now=200
        before=self.export(group);result=self.review(group,renew=True);preview=result['preview']
        self.assertEqual(before,self.export(group));self.assertEqual(preview['issued_at'],200)
        self.assertEqual(preview['preview_expires_at'],260)
        self.now=210;ack=self.confirm(preview)
        after=self.export(group)
        self.assertEqual(ack['revision'],2);self.assertEqual(after['claims']['issued_at'],200)
        self.assertEqual(after['claims']['members'],before['claims']['members'])
        self.assertEqual(after['group_id'],before['group_id'])

    def test_expired_preview_clock_rollback_and_altered_consent_cannot_sign(self):
        group=self.create();self.now=110;preview=self.review(group,renew=True)['preview']
        self.now=170;self.rejected(400,lambda:self.confirm(preview))
        self.now=109;self.rejected(400,lambda:self.confirm(preview))
        self.now=111
        for changes in [{'issued_at':True},{'extra':1}]:self.rejected(400,lambda:self.confirm(preview,**changes))
        for changes in [{'issued_at':111},{'policy_hash':'a'*64},{'evidence_hash':'a'*64},{'targets_fingerprint':'a'*64},{'consent_hash':'a'*64}]:
            self.rejected(409,lambda:self.confirm(preview,**changes))
        self.assertEqual(self.export(group)['claims']['revision'],1)

    def test_source_configuration_or_new_evidence_invalidates_prior_preview(self):
        group,node,target,calls=self.group_source();self.configure(target)
        preview=self.review(group,renew=True)['preview'];self.configure()
        self.rejected(409,lambda:self.confirm(preview))
        self.configure(target);preview=self.review(group,renew=True)['preview']
        node.apply_policy(revise_policy(self.owner,self.export(group)['policy'],{},now=101));self.review(group)
        self.rejected(409,lambda:self.confirm(preview))
        self.assertEqual(self.export(group)['claims']['revision'],1)

    def test_local_policy_mutation_invalidates_prior_preview(self):
        group=self.create();preview=self.review(group,renew=True)['preview']
        self.change(group,'renew',1,request_id='different-operation')
        self.rejected(409,lambda:self.confirm(preview))
        self.assertEqual(self.export(group)['claims']['revision'],2)

    def test_lost_ack_retry_after_expiry_or_new_evidence_returns_original_result(self):
        group,node,target,calls=self.group_source();self.configure(target)
        preview=self.review(group,renew=True)['preview'];first=self.confirm(preview)
        higher=revise_policy(self.owner,self.export(group)['policy'],{},now=101);node.apply_policy(higher);self.review(group)
        self.now=1000;second=self.confirm(preview)
        self.assertEqual(first,second);self.assertEqual(self.export(group)['claims']['revision'],2)
        self.assertEqual(len(self.export(group)['audit']),2)
        self.rejected(409,lambda:self.confirm(preview,issued_at=101))

    def test_request_id_reuse_between_legacy_and_reviewed_actions_is_conflict(self):
        group=self.create();preview=self.review(group,renew=True)['preview']
        self.change(group,'renew',1,request_id='renewal')
        self.rejected(409,lambda:self.confirm(preview))

    def test_local_policy_change_mid_scan_discards_result_and_network_never_holds_store_lock(self):
        group,node,target,calls=self.group_source();self.configure(target)
        started,release=threading.Event(),threading.Event();real=target.client.request
        def blocked(path,body=None):started.set();release.wait(5);return real(path,body)
        with patch.object(target.client,'request',side_effect=blocked),ThreadPoolExecutor(2) as pool:
            read=pool.submit(self.review,group)
            try:
                self.assertTrue(started.wait(3))
                write=pool.submit(self.change,group,'renew',1,'concurrent')
                self.assertEqual(write.result(timeout=2)['revision'],2)
            finally:release.set()
            self.rejected(409,lambda:read.result(timeout=5))
        self.assertEqual(self.export(group)['claims']['revision'],2)

    def test_reconfigured_source_mid_scan_discards_response(self):
        group,node,target,calls=self.group_source();self.configure(target);real=target.client.request;changed=[False]
        def replace(path,body=None):
            if not changed[0]:changed[0]=True;self.configure()
            return real(path,body)
        with patch.object(target.client,'request',side_effect=replace):self.rejected(409,lambda:self.review(group))
        self.assertEqual(self.export(group)['evidence']['statements'],1)

    def test_concurrent_preview_confirm_uses_revision_and_request_deduplication(self):
        group=self.create();preview=self.review(group,renew=True)['preview']
        with ThreadPoolExecutor(2) as pool:results=list(pool.map(lambda _:self.confirm(preview),range(2)))
        self.assertEqual(results[0],results[1]);self.assertEqual(self.export(group)['claims']['revision'],2)

    def test_dissolved_group_cannot_preview_and_retry_of_prior_confirm_does_not_reopen_it(self):
        group=self.create();preview=self.review(group,renew=True)['preview'];ack=self.confirm(preview)
        self.clients['owner'].request('/api/group-dissolve',{'group_id':group,'confirm_name':'Human approved'})
        self.assertIsNone(self.review(group,renew=True)['preview']);self.assertEqual(self.confirm(preview),ack)
        self.assertEqual(self.export(group)['claims']['state'],'dissolved')

    def test_preview_clock_before_current_policy_is_refused(self):
        group=self.create();self.now=99
        self.rejected(400,lambda:self.review(group,renew=True))
        self.assertEqual(self.export(group)['claims']['revision'],1)

    def test_source_report_contains_no_raw_policy_grants_or_credentials(self):
        group,node,target,calls=self.group_source();self.configure(target)
        self.change(group,'approve',1,grant=self.grant(group));node.apply_policy(self.export(group)['policy'])
        serialized=json.dumps(self.review(group,renew=True))
        self.assertNotIn(self.export(group)['policy'],serialized);self.assertNotIn(target.client.token,serialized)
        self.assertNotIn('grant_ids',serialized);self.assertNotIn(self.subject,serialized)
        self.assertEqual(self.export(group)['evidence']['statements'],2)

    def test_persisted_evidence_tampering_fails_closed_on_restart(self):
        group=self.create();self.store.close()
        with sqlite3.connect(self.database) as db:db.execute("UPDATE ui_policy_evidence SET semantic_hash=?",('a'*64,))
        with self.assertRaises(AdmissionError):ChatStore(self.database,policy_authority=self.authority)

    def test_source_evidence_transaction_failure_never_partially_records_a_scan(self):
        group,a,ta,ca=self.group_source()
        _,b,tb,cb=self.group_source(group=group,name='source-b');self.configure(ta,tb)
        self.replace(a,self.variant(group,revision=2,issued_at=101))
        self.replace(b,self.variant(group,revision=3,issued_at=102))
        self.store.db.execute("CREATE TRIGGER reject_evidence BEFORE INSERT ON ui_policy_evidence WHEN NEW.revision=3 BEGIN SELECT RAISE(ABORT,'test storage'); END")
        payload=self.payload(group);payload.pop('group_id')
        with self.assertRaises(sqlite3.Error):self.store.policy_review('owner',group,payload)
        self.assertEqual(self.export(group)['evidence']['statements'],1)
        self.store.db.execute('DROP TRIGGER reject_evidence')
        self.assertEqual(self.review(group)['report']['evidence']['statements'],3)
        self.assertEqual(self.export(group)['claims']['revision'],1)

    def test_tls_ca_and_hostname_checks_apply_to_source_inspection(self):
        group=self.create();node=VerifiedDirectory(self.owner.public_key(),group,'directory',require_policy=True,clock=lambda:self.now)
        self.addCleanup(node.close);node.apply_policy(self.export(group)['policy'])
        paths=certificates(self.root);allowed,context=transport_config('127.0.0.1',paths['cert'],paths['key'],['localhost','127.0.0.1'])
        server=AdmissionHTTPServer(('127.0.0.1',0),handler(node,'r'*32,allowed,'https'),context)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),thread.join()))
        good=PolicyTarget('tls',f'https://localhost:{server.server_port}',group,'r'*32,paths['ca'])
        self.configure(good);self.assertEqual(self.review(group)['report']['sources'][0]['state'],'read')
        for target in [PolicyTarget('untrusted',good.url,group,'r'*32),
            PolicyTarget('hostname',good.url.replace('localhost','127.0.0.1'),group,'r'*32,paths['ca'])]:
            self.configure(target);self.assertEqual(self.review(group)['report']['sources'][0]['state'],'error')
