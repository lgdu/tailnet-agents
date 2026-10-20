"""Human-confirmed local uncertainty notes and original-consent recovery."""
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from urllib.error import HTTPError

from tests import test_task_ui as fixtures
from tailnet_agents.chat import ChatStore
from tailnet_agents.task_mcp import Backend
from tailnet_agents.task_ui import TaskBridge
from tailnet_agents.ui import handler
from tailnet_agents import task_storage as storage


@unittest.skipUnless(fixtures.HAS_CRYPTO, 'install identity extra')
class TaskReviewUITests(unittest.TestCase):
    def setUp(self):
        self.c = fixtures.TaskUIIdentityTests('test_single_task_submit_and_repeat_confirmation_never_batch_or_replay')
        self.addCleanup(self.c.doCleanups)
        self.c.setUp()

    def uncertain(self, client=None, mid='a'*32):
        from tailnet_agents.durable_tasks import TaskUnavailable
        c = self.c
        client = client or c.client
        client.queue_once(mid, 'original uncertain input')
        preview = client.submit_preview(mid)
        with patch.object(c.f.executor, '_run', side_effect=TaskUnavailable('pause')):
            with self.assertRaises(HTTPError) as caught:
                client.submit(mid, preview['request_hash'], mid)
            caught.exception.close()
        with c.f.node._registry.db:
            c.f.node._registry.db.execute("UPDATE durable_tasks SET status='running' WHERE task_id=?", (mid,))
        c.f.restart()
        self.assertEqual(client.refresh(mid)['status'], 'uncertain')

    def preview(self, **extra):
        return self.c.preview('review', decision='unresolved', note='Original evidence', **extra)

    def read(self, **extra):
        c = self.c
        return c.humans['owner'].request('/api/task-read', {'group_id':c.group,
            'binding_id':'caller', 'operation':'reviews', 'task_id':'a'*32, **extra})

    def reopen(self, **limits):
        c = self.c
        c.bridge.close()
        c.store.close()
        c.store = ChatStore(c.database, policy_authority=fixtures.PolicyAuthority(c.f.owner, 'owner', clock=lambda:c.f.now))
        c.client = c.f.client()
        c.bridge = TaskBridge(c.store, [('caller','owner',Backend(c.client))], clock=lambda:c.f.now, **limits)
        c.server.RequestHandlerClass = handler(c.store,c.users,task_bridge=c.bridge)

    def test_preview_and_reads_are_local_and_never_create_a_note_or_task(self):
        c = self.c
        self.uncertain()
        original = c.client.show('a'*32)
        with patch.object(c.client.http,'request',side_effect=AssertionError('network')):
            p = self.preview()
            self.assertTrue(p['eligible'])
            self.assertFalse(p['network'])
            self.assertEqual(p['effect'],'advisory_local_record_only')
            self.assertEqual(p['input'],'original uncertain input')
            self.assertEqual(self.read()['reviews'],[])
        self.assertEqual(c.client.show('a'*32),original)
        self.assertEqual(c.f.calls,[])

    def test_each_decision_appends_caller_signed_advice_without_changing_uncertainty(self):
        c = self.c
        self.uncertain()
        before = c.client.db.execute('SELECT token,state,receipt FROM task_outbox').fetchone()
        with patch.object(c.client.http,'request',side_effect=AssertionError('network')):
            for decision in ('effect_observed','no_effect_observed','unresolved'):
                p = c.preview('review',decision=decision,note='人工观察 <script>data</script>')
                result = c.confirm(p)
                self.assertEqual(result['decision'],decision)
                self.assertEqual(result['request_id'],p['consent_id'])
                self.assertEqual(result['receipt_hash'],p['receipt_hash'])
                self.assertEqual(result['task_status'],'uncertain')
                self.assertEqual(result['effect'],'advisory_local_record_only')
            self.assertEqual(len(self.read()['reviews']),3)
            self.assertEqual(c.client.flush(),[])
        self.assertEqual(c.client.db.execute('SELECT token,state,receipt FROM task_outbox').fetchone(),before)
        for operation in ('submit','cancel','archive'):
            p = c.preview(operation)
            self.assertFalse(p['eligible'])
            c.denied(409,lambda:c.confirm(p))
        self.assertEqual(c.f.calls,[])

    def test_exact_fields_and_utf8_note_boundaries_are_checked_before_admission(self):
        c = self.c
        self.uncertain()
        payload = {'binding_id':'caller','operation':'review','task_id':'a'*32,'request_id':'f'*32,
                   'decision':'unresolved','note':'界'*682+'ab'}
        p = c.bridge.preview('owner',c.group,payload)
        self.assertEqual(len(p['note'].encode()),2048)
        count = c.store.db.execute('SELECT COUNT(*) FROM ui_task_consents').fetchone()[0]
        for change in ({'note':''},{'note':'界'*683},{'note':[]},{'decision':'resolved'},
                       {'decision':True},{'decision':[]},{'receipt_hash':'0'*64},
                       {'request_hash':'0'*64},{'input':'hidden task'},{'human':'other'}):
            c.denied(400,lambda:c.humans['owner'].request('/api/task-preview',
                {'group_id':c.group,**payload,**change,'request_id':'e'*32}))
        self.assertEqual(c.store.db.execute('SELECT COUNT(*) FROM ui_task_consents').fetchone()[0],count)
        self.assertEqual(self.read()['reviews'],[])

    def test_pending_completed_and_cancelled_tasks_cannot_acquire_review_notes(self):
        c = self.c
        c.client.queue_once('a'*32,'pending')
        c.denied(400,self.preview)
        p = c.client.submit_preview('a'*32)
        c.client.submit('a'*32,p['request_hash'],'a'*32)
        c.denied(400,self.preview)
        c.client.queue_once('b'*32,'cancelled')
        p = c.client.cancel_preview('b'*32)
        c.client.cancel('b'*32,p['request_hash'],'b'*32)
        c.denied(400,lambda:c.preview('review','b'*32,decision='unresolved',note='no authority'))
        self.assertEqual(c.client.db.execute('SELECT COUNT(*) FROM task_reviews').fetchone()[0],0)

    def test_other_humans_and_groups_cannot_preview_confirm_or_read_notes(self):
        c = self.c
        self.uncertain()
        p = self.preview()
        for human in ('other','participant','observer'):
            c.denied(403,lambda:c.humans[human].request('/api/task-confirm',c.confirmation(p)))
            c.denied(403,lambda:c.humans[human].request('/api/task-read',
                {'group_id':c.group,'binding_id':'caller','operation':'reviews','task_id':'a'*32}))
            c.denied(403,lambda:c.humans[human].request('/api/task-preview',
                {'group_id':c.group,'binding_id':'caller','operation':'review','task_id':'a'*32,
                 'request_id':'f'*32,'decision':'unresolved','note':'not mine'}))
        group = c.store.create_group('Other','owner',[],request_id='other')['id']
        c.denied(403,lambda:c.humans['owner'].request('/api/task-confirm',c.confirmation(p)|{'group_id':group}))
        self.assertEqual(self.read()['reviews'],[])

    def test_original_preview_id_binds_exact_note_and_decision(self):
        c = self.c
        self.uncertain()
        payload = {'binding_id':'caller','operation':'review','task_id':'a'*32,'request_id':'f'*32,
                   'decision':'unresolved','note':'original'}
        p = c.bridge.preview('owner',c.group,payload)
        self.assertEqual(c.bridge.preview('owner',c.group,payload),p)
        for change in ({'note':'changed'},{'decision':'effect_observed'}):
            with self.assertRaises(FileExistsError):c.bridge.preview('owner',c.group,payload|change)

    def test_review_expiry_and_observed_rollback_are_sticky(self):
        c = self.c
        self.uncertain()
        for now in (109,170):
            c.f.now = 110
            p = self.preview()
            c.f.now = now
            c.denied(409,lambda:c.confirm(p))
            c.f.now = 110
            c.denied(409,lambda:c.confirm(p))
        self.assertEqual(self.read()['reviews'],[])

    def test_ui_policy_change_invalidates_first_review_confirmation(self):
        c = self.c
        self.uncertain()
        p = self.preview()
        with c.store.lock,c.store.db:
            revision=c.store.policy_authority.current(c.store.db,c.group)[1]['revision']
            c.store.policy_authority.change(c.store.db,c.group,'renew',{'expected_revision':revision,'request_id':'review-renew'})
        c.denied(409,lambda:c.confirm(p))
        self.assertEqual(self.read()['reviews'],[])

    def test_confirmation_cannot_replace_note_receipt_or_original_task_id(self):
        c = self.c
        self.uncertain()
        p = self.preview()
        for change in ({'note':'changed'},{'decision':'effect_observed'}, {'receipt_hash':'0'*64},
                       {'request_id':'f'*32},{'confirm_task_id':'b'*32}):
            c.denied(400,lambda:c.humans['owner'].request('/api/task-confirm',c.confirmation(p)|change))
        self.assertEqual(self.read()['reviews'],[])

    def test_failed_ui_authorization_commit_cannot_create_a_caller_review(self):
        c = self.c
        self.uncertain()
        p = self.preview()
        with c.store.db:
            c.store.db.execute("CREATE TRIGGER reject_review_start BEFORE UPDATE ON ui_task_consents BEGIN SELECT RAISE(ABORT,'SECRET'); END")
        self.assertNotIn('SECRET',c.denied(502,lambda:c.confirm(p)))
        self.assertEqual(self.read()['reviews'],[])

    def test_caller_insert_rollback_retains_original_started_human_authorization(self):
        c = self.c
        self.uncertain()
        p = self.preview()
        with c.client.db:
            c.client.db.execute("CREATE TRIGGER reject_note BEFORE INSERT ON task_reviews BEGIN SELECT RAISE(ABORT,'SECRET'); END")
        self.assertNotIn('SECRET',c.denied(502,lambda:c.confirm(p)))
        self.assertEqual(self.read()['reviews'],[])
        with c.client.db:c.client.db.execute('DROP TRIGGER reject_note')
        c.f.now = 180
        self.assertEqual(c.confirm(p)['note'],'Original evidence')

    def test_lost_result_commit_recovers_original_signature_after_restart_above_quota(self):
        c = self.c
        self.uncertain()
        p = self.preview()
        with c.store.db:
            c.store.db.execute("CREATE TRIGGER reject_review_ack BEFORE UPDATE ON ui_task_consents WHEN NEW.state='done' BEGIN SELECT RAISE(ABORT,'SECRET'); END")
        c.denied(502,lambda:c.confirm(p))
        original = c.client.db.execute('SELECT token FROM task_reviews').fetchone()[0]
        self.reopen(consent_capacity=1,consent_byte_capacity=1)
        c.client.storage_limits = storage.limits({'review_capacity':1,'byte_capacity':1})
        with c.store.db:c.store.db.execute('DROP TRIGGER reject_review_ack')
        c.f.now = 180
        with patch.object(c.client.http,'request',side_effect=AssertionError('network')):
            result = c.confirm(p)
            self.assertEqual(c.confirm(p),result)
        self.assertEqual(c.client.db.execute('SELECT token FROM task_reviews').fetchall(),[(original,)])
        self.assertEqual(c.client.show('a'*32)['status'],'uncertain')

    def test_caller_review_capacity_denial_recovers_same_consent_after_limit_increase(self):
        c = self.c
        self.uncertain()
        c.confirm(self.preview())
        c.client.storage_limits = storage.limits({'review_capacity':1})
        p = self.preview()
        c.denied(429,lambda:c.confirm(p))
        self.assertEqual(len(self.read()['reviews']),1)
        c.client.storage_limits = storage.limits({'review_capacity':2})
        c.f.now = 180
        self.assertEqual(c.confirm(p)['request_id'],p['consent_id'])
        self.assertEqual(len(self.read()['reviews']),2)

    def test_full_ui_budget_preserves_saved_review_preview_and_confirm_recovery(self):
        c = self.c
        self.uncertain()
        p = self.preview()
        c.bridge.consent_limits = storage.limits({'capacity':1,'byte_capacity':1},consent=True)
        c.denied(429,self.preview)
        self.assertEqual(c.confirm(p)['note'],'Original evidence')
        self.assertEqual(c.confirm(p)['request_id'],p['consent_id'])

    def test_concurrent_confirmations_append_exactly_one_review(self):
        c = self.c
        self.uncertain()
        p = self.preview()
        with ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(lambda _:c.confirm(p),range(4)))
        self.assertTrue(all(result==results[0] for result in results))
        self.assertEqual(len(self.read()['reviews']),1)

    def test_read_pages_validate_each_signature_and_reject_overrides(self):
        c = self.c
        self.uncertain()
        for _ in range(3):c.confirm(self.preview())
        first = self.read(limit=2)
        self.assertTrue(first['has_more'])
        self.assertEqual(len(first['reviews']),2)
        self.assertEqual(len(self.read(after=first['next_after'],limit=2)['reviews']),1)
        for change in ({'after':True},{'limit':101},{'url':'https://elsewhere'},{'human':'other'}):
            c.denied(400,lambda:self.read(**change))
        token = c.client.db.execute('SELECT token FROM task_reviews ORDER BY position').fetchone()[0]
        parts = token.split('.')
        parts[2] = ('A' if parts[2][0]!='A' else 'B')+parts[2][1:]
        with c.client.db:c.client.db.execute('UPDATE task_reviews SET token=? WHERE position=1',('.'.join(parts),))
        c.denied(400,self.read)

    def test_same_host_callers_keep_independent_review_and_consent_history(self):
        c = self.c
        self.uncertain()
        other = c.f.client(i=1)
        self.uncertain(other,'b'*32)
        c.bridge = TaskBridge(c.store,[('caller','owner',Backend(c.client)),('second','owner',Backend(other))],clock=lambda:c.f.now)
        c.server.RequestHandlerClass = handler(c.store,c.users,task_bridge=c.bridge)
        c.confirm(self.preview())
        self.assertEqual(other.reviews('b'*32)['reviews'],[])
        with self.assertRaises(KeyError):c.bridge.read('owner',c.group,
            {'binding_id':'second','operation':'reviews','task_id':'a'*32})
        self.assertEqual(c.bridge.read('owner',c.group,{'binding_id':'second','operation':'history'})['consents'],[])

    def test_changed_valid_uncertain_receipt_cannot_rebind_a_saved_review(self):
        c = self.c
        self.uncertain()
        p = self.preview()
        row = c.client.db.execute('SELECT token FROM task_outbox').fetchone()
        c.f.now = 111
        receipt = c.f.executor._receipt('a'*32,c.client.subject,row[0],'uncertain')
        with c.client.db:c.client.db.execute('UPDATE task_outbox SET receipt=?',(receipt,))
        c.denied(400,lambda:c.confirm(p))
        self.assertEqual(self.read()['reviews'],[])

    def test_dissolution_keeps_completed_notes_readable_but_blocks_new_or_started_notes(self):
        c = self.c
        self.uncertain()
        p = self.preview()
        result = c.confirm(p)
        unfinished = self.preview()
        c.store.dissolve_group('owner',c.group,c.store.group_info('owner',c.group)['name'])
        self.assertEqual(c.confirm(p),result)
        self.assertEqual(len(self.read()['reviews']),1)
        c.denied(403,self.preview)
        c.denied(403,lambda:c.confirm(unfinished))

    def test_preview_restart_restores_exact_note_without_automatically_signing(self):
        c = self.c
        self.uncertain()
        p = self.preview()
        self.reopen()
        history = c.bridge.read('owner',c.group,{'binding_id':'caller','operation':'history'})
        self.assertEqual(history['consents'][0]['preview']['note'],'Original evidence')
        self.assertEqual(self.read()['reviews'],[])
        self.assertEqual(c.confirm(p)['request_id'],p['consent_id'])
        self.assertEqual(c.f.calls,[])
