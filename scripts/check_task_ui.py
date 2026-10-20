"""Chromium checks for explicit human authorization of original signed Echo tasks."""
import argparse
from pathlib import Path
import shutil
import sys
from unittest.mock import patch
from urllib.error import HTTPError, URLError

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tests'))
from playwright.sync_api import sync_playwright, expect
from test_task_ui import TaskUIIdentityTests
from tailnet_agents import task_storage as storage
from tailnet_agents.durable_tasks import TaskUnavailable

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--browser',default=shutil.which('chromium') or shutil.which('google-chrome'))
parser.add_argument('--artifacts',type=Path)
args=parser.parse_args()
case=TaskUIIdentityTests('test_single_task_submit_and_repeat_confirmation_never_batch_or_replay')
try:
    case.setUp()
    second=case.store.create_group('Separate group','owner',[],request_id='second')['id']
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path=args.browser,headless=True)
        page=browser.new_page(viewport={'width':1360,'height':1000});errors=[]
        page.on('pageerror',lambda error:errors.append(str(error)))
        page.goto(case.url);page.evaluate('window.realDateNow=Date.now;Date.now=()=>110000')
        page.locator('#token').fill('o'*32);page.locator('#login-form button').click()
        expect(page.locator('#workspace')).to_be_visible();page.locator('#group-select').select_option(case.group)
        page.locator('#task-open').click();expect(page.locator('#task-binding option')).to_have_count(1)
        assert case.client.list_tasks()['tasks']==[] and case.f.calls==[]
        page.locator('#task-id').fill('a'*32);page.locator('#task-input').fill('<script>window.taskInjected=true</script>')
        page.locator('#task-preview').click();expect(page.locator('#task-preview-text')).to_contain_text('consent_id')
        assert case.client.list_tasks()['tasks']==[]
        page.locator('#task-confirm-id').fill('b'*32);expect(page.locator('#task-confirm')).to_be_disabled()
        page.locator('#task-input').fill('Original human Echo');expect(page.locator('#task-confirm')).to_be_disabled()
        page.locator('#task-preview').click();expect(page.locator('#task-preview-text')).to_contain_text('Original human Echo')
        page.locator('#task-confirm-id').fill('a'*32)
        page.evaluate('Date.now=()=>171000');expect(page.locator('#task-confirm')).to_be_disabled()
        page.evaluate('Date.now=()=>110000');expect(page.locator('#task-confirm')).to_be_disabled()
        repreview=[]
        def hold_repreview(route):
            repreview.append((route,route.fetch()));page.evaluate("document.body.dataset.repreviewHeld='yes'")
        page.route('**/api/task-preview',hold_repreview)
        page.locator('#task-preview').click();expect(page.locator('body')).to_have_attribute('data-repreview-held','yes')
        expect(page.locator('#task-preview-text')).to_be_empty()
        expect(page.locator('#task-confirm-id')).to_be_disabled()
        route,response=repreview.pop();route.fulfill(response=response);page.unroute('**/api/task-preview',hold_repreview)
        expect(page.locator('#task-preview-text')).to_contain_text('Original human Echo')
        page.locator('#task-confirm-id').fill('a'*32);expect(page.locator('#task-confirm')).to_be_enabled()
        page.locator('#task-confirm').click();expect(page.locator('#task-result')).to_contain_text('pending')
        assert len(case.client.list_tasks()['tasks'])==1 and case.f.calls==[]
        # A lost HTTP acknowledgment leaves one original intent. The page retries
        # the durable consent, never allocates another task ID.
        page.locator('#task-operation').select_option('submit');page.locator('#task-preview').click()
        expect(page.locator('#task-preview-text')).to_contain_text('request_hash')
        page.locator('#task-confirm-id').fill('a'*32)
        held=[]
        def lose(route):
            response=route.fetch();held.append(response);route.abort()
        page.route('**/api/task-confirm',lose)
        page.locator('#task-confirm').click();expect(page.locator('#task-retry')).to_be_visible()
        expect(page.locator('#task-status')).to_contain_text('结果未确认')
        assert case.f.calls==['Original human Echo']
        page.unroute('**/api/task-confirm',lose);page.locator('#task-retry').click()
        expect(page.locator('#task-result')).to_contain_text('completed');assert len(case.f.calls)==1
        page.locator('#task-operation').select_option('archive');page.locator('#task-preview').click()
        expect(page.locator('#task-preview-text')).to_contain_text('payload_retained')
        page.locator('#task-confirm-id').fill('a'*32);page.locator('#task-confirm').click()
        expect(page.locator('#task-result')).to_contain_text('archived')
        page.locator('#task-history').click();expect(page.locator('#task-consents li')).to_have_count(5)
        # An offline operation preserves the cancellation barrier, and closing
        # the dialog leaves a durable started consent for explicit recovery.
        page.locator('#task-new').click();page.locator('#task-id').fill('c'*32);page.locator('#task-input').fill('Cancel me')
        page.locator('#task-preview').click();expect(page.locator('#task-preview-text')).to_contain_text('Cancel me')
        page.locator('#task-confirm-id').fill('c'*32);page.locator('#task-confirm').click()
        expect(page.locator('#task-result')).to_contain_text('pending')
        page.locator('#task-operation').select_option('cancel');page.locator('#task-preview').click()
        expect(page.locator('#task-preview-text')).to_contain_text('request_hash')
        page.locator('#task-confirm-id').fill('c'*32)
        with patch.object(case.client.http,'request',side_effect=URLError('SECRET')):
            page.locator('#task-confirm').click();expect(page.locator('#task-status')).to_contain_text('结果未确认')
        assert case.client.show('c'*32)['cancellation_requested'] and 'SECRET' not in page.content()
        page.locator('#task-close').click();page.locator('#task-open').click()
        expect(page.locator('#task-binding option')).to_have_count(1)
        page.locator('#task-history').click();expect(page.locator('#task-consents li')).to_have_count(7)
        page.locator('#task-consents button').last.click();expect(page.locator('#task-preview-text')).to_contain_text('started')
        page.locator('#task-confirm-id').fill('c'*32);page.locator('#task-confirm').click()
        expect(page.locator('#task-result')).to_contain_text('cancelled');assert len(case.f.calls)==1
        # Full retained consent history blocks another preview, while local
        # usage/history and an original completed acknowledgment stay available.
        page.locator('#task-storage-read').click();expect(page.locator('#task-storage')).to_contain_text('charged_bytes')
        assert storage.consent_usage(case.store.db,'caller','owner')['consents']==7
        case.bridge.consent_limits=storage.limits({'capacity':7},consent=True)
        page.locator('#task-new').click();page.locator('#task-id').fill('d'*32);page.locator('#task-input').fill('Blocked preview')
        page.locator('#task-preview').click();expect(page.locator('#task-status')).to_contain_text('consent admission full')
        expect(page.locator('#task-preview-text')).to_be_empty();expect(page.locator('#task-confirm')).to_be_disabled()
        page.locator('#task-history').click();expect(page.locator('#task-consents li')).to_have_count(7)
        page.locator('#task-consents button').last.click();page.locator('#task-confirm-id').fill('c'*32)
        page.locator('#task-confirm').click();expect(page.locator('#task-result')).to_contain_text('cancelled')
        case.bridge.consent_limits=storage.limits({},consent=True)
        # A queue rejected by the caller keeps the same started Human consent.
        # Increasing explicit admission limits lets that original request recover.
        case.client.storage_limits=storage.limits({'byte_capacity':1})
        page.locator('#task-new').click();page.locator('#task-id').fill('d'*32);page.locator('#task-input').fill('Quota original')
        page.locator('#task-preview').click();expect(page.locator('#task-preview-text')).to_contain_text('Quota original')
        page.locator('#task-confirm-id').fill('d'*32);page.locator('#task-confirm').click()
        expect(page.locator('#task-status')).to_contain_text('Caller storage admission full')
        expect(page.locator('#task-retry')).to_be_visible()
        case.client.storage_limits=storage.limits({})
        page.locator('#task-retry').click();expect(page.locator('#task-result')).to_contain_text('pending')
        assert len(case.client.list_tasks()['tasks'])==3 and len(case.f.calls)==1
        # A synthetic interrupted executor produces a verified uncertain receipt.
        # Human observations remain local advice, including when an ACK is lost.
        mid='e'*32
        case.client.queue_once(mid,'Uncertain browser input')
        intent=case.client.submit_preview(mid)
        with patch.object(case.f.executor,'_run',side_effect=TaskUnavailable('pause')):
            try:case.client.submit(mid,intent['request_hash'],mid)
            except HTTPError as error:error.close()
            else:raise AssertionError('expected paused execution')
        with case.f.node._registry.db:case.f.node._registry.db.execute("UPDATE durable_tasks SET status='running' WHERE task_id=?",(mid,))
        case.f.restart();case.client.refresh(mid)
        page.locator('#task-id').fill(mid);page.locator('#task-operation').select_option('review')
        note='<script>window.reviewInjected=true</script> 人工观察'
        page.locator('#task-review-note').fill(note)
        page.locator('#task-preview').click();expect(page.locator('#task-preview-text')).to_contain_text('advisory_local_record_only')
        assert case.client.reviews(mid)['reviews']==[]
        page.locator('#task-confirm-id').fill(mid)
        page.locator('#task-review-decision').select_option('no_effect_observed')
        expect(page.locator('#task-confirm')).to_be_disabled();expect(page.locator('#task-preview-text')).to_be_empty()
        page.locator('#task-preview').click();expect(page.locator('#task-preview-text')).to_contain_text('no_effect_observed')
        page.locator('#task-confirm-id').fill(mid)
        page.route('**/api/task-confirm',lose)
        page.locator('#task-confirm').click();expect(page.locator('#task-retry')).to_be_visible()
        expect(page.locator('#task-status')).to_contain_text('结果未确认')
        original=case.client.db.execute('SELECT token FROM task_reviews').fetchone()[0]
        page.unroute('**/api/task-confirm',lose);page.locator('#task-retry').click()
        expect(page.locator('#task-result')).to_contain_text('advisory_local_record_only')
        assert case.client.db.execute('SELECT token FROM task_reviews').fetchall()==[(original,)]
        assert case.client.show(mid)['status']=='uncertain' and len(case.f.calls)==1
        page.locator('#task-reviews-read').click();expect(page.locator('#task-reviews')).to_contain_text(note)
        assert page.locator('#task-reviews script').count()==0 and page.evaluate('window.reviewInjected') is None
        for i in range(20):
            p=case.client.review_preview(mid)
            case.client.review(mid,p['receipt_hash'],'unresolved','page-'+str(i),f'{1000+i:032x}',mid)
        page.locator('#task-reviews-read').click();expect(page.locator('#task-reviews-next')).to_be_enabled()
        page.locator('#task-reviews-next').click();expect(page.locator('#task-reviews')).to_contain_text('page-19')
        expect(page.locator('#task-reviews-next')).to_be_disabled()
        # Returning to a saved review restores its exact original draft. Editing
        # that draft requires a new preview; an old consent cannot be changed.
        page.locator('#task-history').click();expect(page.locator('#task-consents li')).to_have_count(10)
        page.locator('#task-consents button').last.click();expect(page.locator('#task-review-note')).to_have_value(note)
        expect(page.locator('#task-review-decision')).to_have_value('no_effect_observed')
        page.locator('#task-confirm-id').fill(mid);expect(page.locator('#task-confirm')).to_be_enabled()
        page.locator('#task-review-note').fill('Edited observation');expect(page.locator('#task-confirm')).to_be_disabled()
        delayed_reads=[]
        def hold_review_read(route):
            delayed_reads.append((route,route.fetch()));page.evaluate("document.body.dataset.reviewHeld='yes'")
        page.route('**/api/task-read',hold_review_read)
        page.locator('#task-reviews-read').click();expect(page.locator('body')).to_have_attribute('data-review-held','yes')
        page.locator('#task-close').click();page.locator('#group-select').select_option(second)
        route,response=delayed_reads.pop();route.fulfill(response=response);page.unroute('**/api/task-read',hold_review_read)
        expect(page.locator('#task-reviews')).to_be_empty();expect(page.locator('#task-review-note')).to_have_value('')
        page.locator('#group-select').select_option(case.group);page.locator('#task-open').click()
        expect(page.locator('#task-binding option')).to_have_count(1);page.locator('#task-id').fill(mid)
        # Late previews cannot revive consent after close or a group switch.
        delayed=[]
        def hold(route):
            delayed.append((route,route.fetch()));page.evaluate("document.body.dataset.taskHeld='yes'")
        page.route('**/api/task-preview',hold)
        page.locator('#task-operation').select_option('refresh');page.locator('#task-preview').click()
        expect(page.locator('body')).to_have_attribute('data-task-held','yes')
        page.locator('#task-close').click();page.locator('#group-select').select_option(second)
        route,response=delayed.pop();route.fulfill(response=response);page.unroute('**/api/task-preview',hold)
        page.locator('#task-open').click();expect(page.locator('#task-status')).to_contain_text('没有显式任务绑定')
        expect(page.locator('#task-confirm')).to_be_disabled();expect(page.locator('#task-preview-text')).to_be_empty()
        page.locator('#task-close').click();page.locator('#group-select').select_option(case.group)
        page.locator('#task-open').click();expect(page.locator('#task-binding option')).to_have_count(1)
        page.set_viewport_size({'width':375,'height':812})
        assert page.evaluate("document.querySelector('#task-dialog').scrollWidth<=document.querySelector('#task-dialog').clientWidth")
        assert page.evaluate('localStorage.length')==0 and page.evaluate('sessionStorage.length')==0
        assert page.evaluate('window.taskInjected') is None
        if args.artifacts:
            args.artifacts.mkdir(parents=True,exist_ok=True)
            page.screenshot(path=str(args.artifacts/'task-ui-narrow.png'))
        page.locator('#task-close').click();page.locator('#logout').click()
        expect(page.locator('#task-preview-text')).to_be_empty();expect(page.locator('#task-result')).to_be_empty()
        assert not errors,errors
        browser.close()
    print('Task UI browser PASS: explicit Human operations and advisory uncertainty notes, original-ID lost-ACK/cancel/archive/review recovery, edited drafts, signature-preserving retries, review paging and stale reads, quotas, late-view guards, narrow layout and no credential storage.')
finally:case.doCleanups()
