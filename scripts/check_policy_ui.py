"""Optional Chromium check: install playwright and run with --browser /path/to/chromium."""
import argparse
import re
import shutil
import sys
import tempfile
import threading
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from http.server import ThreadingHTTPServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from playwright.sync_api import sync_playwright, expect
from tailnet_agents.chat import ChatStore
from tailnet_agents.ui import handler
from tailnet_agents.policy_admin import PolicyAuthority
from tailnet_agents.identity import encode, identity_id, public_bytes, verify_grant
from tailnet_agents.policy_delivery import PolicyTarget
from tailnet_agents.verified_directory import VerifiedDirectory
from tailnet_agents.admission_server import handler as admission_handler

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--browser', default=shutil.which('chromium') or shutil.which('google-chrome'), help='existing Chromium/Chrome binary; otherwise Playwright installation')
parser.add_argument('--artifacts', type=Path, help='optional directory for screenshots after credentials are cleared')
args = parser.parse_args()
if args.artifacts:
    args.artifacts.mkdir(parents=True, exist_ok=True)

with tempfile.TemporaryDirectory() as folder:
    owner = Ed25519PrivateKey.generate()
    agent = Ed25519PrivateKey.generate()
    store = ChatStore(str(Path(folder)/'chat.sqlite3'), policy_authority=PolicyAuthority(owner, 'owner'))
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler(store, {'owner': {'role': 'admin', 'token': 'b'*32}}))
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    recipient_server = recipient_worker = recipient = None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path=args.browser, headless=True)
            page = browser.new_page(viewport={'width': 1360, 'height': 900})
            errors=[]
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(f'http://127.0.0.1:{server.server_port}')
            page.locator('#token').fill('b'*32)
            page.locator('#login-form button').click()
            expect(page.locator('#workspace')).to_be_visible()
            assert store.groups('owner')==[]
            page.locator('#create-group').click()
            expect(page.locator('#signed-choice')).to_be_visible()
            page.locator('#group-name').fill('Browser signed group')
            page.locator('#signed-policy').check()
            page.locator('#group-form button[type=submit]').click()
            expect(page.locator('#group-dialog')).not_to_be_visible()
            group=store.groups('owner')[0]['id']
            recipient=VerifiedDirectory(owner.public_key(),group,'browser-directory',require_policy=True)
            network=[]
            class Recipient(admission_handler(recipient,'d'*32)):
                def do_GET(inner):
                    network.append(('GET',inner.path));super().do_GET()
                def do_POST(inner):
                    network.append(('POST',inner.path));super().do_POST()
            recipient_server=ThreadingHTTPServer(('127.0.0.1',0),Recipient)
            recipient_worker=threading.Thread(target=recipient_server.serve_forever)
            recipient_worker.start()
            target=PolicyTarget('browser-recipient',f'http://127.0.0.1:{recipient_server.server_port}',group,'d'*32)
            store.configure_policy_targets([target])
            page.locator('#manage-group').click()
            expect(page.locator('#policy-status')).to_contain_text('第 1 版')
            page.locator('#delivery-preview').click()
            expect(page.locator('#delivery-consent')).to_contain_text(target.url)
            assert network==[]  # Opening the UI and previewing never contact the recipient.
            assert recipient.export_policy()['policy'] is None
            page.locator('#delivery-confirm').click()
            expect(page.locator('#delivery-error')).to_contain_text('接收第 1 版')
            assert recipient.export_policy()['policy']==store.policy_export('owner',group)['policy']
            page.locator('#credential-public-key').fill(encode(public_bytes(agent.public_key())))
            page.locator('#credential-permissions input[value=discover]').check()
            # A delayed response for an edited draft must never restore old consent.
            held_previews=[]
            def hold_credential_preview(route):
                held_previews.append((route,route.fetch()))
                page.evaluate("document.body.dataset.credentialHeld='yes'")
            page.route('**/api/credential-preview',hold_credential_preview)
            page.locator('#credential-preview').click()
            expect(page.locator('body')).to_have_attribute('data-credential-held','yes')
            page.locator('#credential-lifetime').fill('1800')
            route,response=held_previews.pop();route.fulfill(response=response)
            page.unroute('**/api/credential-preview',hold_credential_preview)
            expect(page.locator('#credential-confirm')).to_be_disabled()
            page.locator('#credential-preview').click()
            expect(page.locator('#credential-consent')).to_contain_text(identity_id(agent.public_key()))
            assert store.credential_history('owner',group)['issuances']==[]
            assert store.policy_export('owner',group)['claims']['members']=={}
            if args.artifacts:
                page.locator('#credential-consent').scroll_into_view_if_needed()
                page.screenshot(path=str(args.artifacts/'credential-preview-desktop.png'))
                page.set_viewport_size({'width':375,'height':812})
                page.locator('#credential-consent').scroll_into_view_if_needed()
                page.screenshot(path=str(args.artifacts/'credential-preview-mobile.png'))
                assert page.evaluate("document.querySelector('#manage-dialog').scrollWidth<=document.querySelector('#manage-dialog').clientWidth")
                page.set_viewport_size({'width':1360,'height':900})
            before_network=list(network)
            dropped_issuance=[False]
            def lose_issuance_ack(route):
                if not dropped_issuance[0]:
                    dropped_issuance[0]=True;route.fetch();route.abort()
                else: route.continue_()
            page.route('**/api/credential-issue',lose_issuance_ack)
            page.locator('#credential-confirm').click()
            expect(page.locator('#credential-retry')).to_be_enabled()
            assert len(store.credential_history('owner',group)['issuances'])==1
            page.locator('#credential-retry').click()
            expect(page.locator('#credential-download')).to_be_enabled()
            assert len(store.credential_history('owner',group)['issuances'])==1
            assert network==before_network
            page.unroute('**/api/credential-issue',lose_issuance_ack)
            # Known issuance + failed history refresh must retry reads, not issue again.
            failed_history=[False]
            def lose_history(route):
                if not failed_history[0]: failed_history[0]=True;route.abort()
                else: route.continue_()
            page.route('**/api/credential-issuances?*',lose_history)
            page.locator('.credential-recover').first.click()
            expect(page.locator('#credential-error')).to_contain_text('签发已确认，但页面读取失败')
            expect(page.locator('#credential-download')).to_be_disabled()
            issuance_posts=[]
            def issued_request(request):
                if request.method=='POST': issuance_posts.append(request.url)
            page.on('request',issued_request)
            page.locator('#credential-retry').click()
            expect(page.locator('#credential-download')).to_be_enabled()
            page.remove_listener('request',issued_request)
            assert issuance_posts==[]
            page.unroute('**/api/credential-issuances?*',lose_history)
            with page.expect_download() as transfer:
                page.locator('#credential-download').click()
            grant=Path(transfer.value.path()).read_text().strip()
            claims=verify_grant(grant,owner.public_key(),group)
            assert claims['sub']==identity_id(agent.public_key())
            assert claims['permissions']==['discover','join']
            assert grant not in page.content()  # No credential in the DOM before explicit approval preview.
            assert page.locator('#policy-grant').input_value()==''
            assert page.evaluate('localStorage.length')==0
            assert page.evaluate('sessionStorage.length')==0
            held_reads=[]
            def hold_policy_read(route):
                response=route.fetch()
                held_reads.append((route,response))
                page.evaluate("document.body.dataset.policyReadHeld='yes'")

            def change_with_delayed_read(action, revision, fail=False):
                held_reads.clear()
                page.evaluate("delete document.body.dataset.policyReadHeld")
                page.route('**/api/group-policy?*', hold_policy_read)
                action()
                expect(page.locator('body')).to_have_attribute('data-policy-read-held', 'yes')
                assert store.policy_export('owner',group)['claims']['revision']==revision
                expect(page.locator('#policy-export')).to_be_disabled()
                expect(page.locator('#policy-error')).not_to_have_class(re.compile(r'\bsuccess\b'))
                # Even a programmatic click must not bypass the disabled control.
                downloads=[]
                def downloaded(download): downloads.append(download)
                page.on('download', downloaded)
                page.evaluate("document.querySelector('#policy-export').onclick()")
                assert not downloads
                page.remove_listener('download', downloaded)
                route,response=held_reads.pop()
                if fail:
                    route.abort()
                    page.unroute('**/api/group-policy?*', hold_policy_read)
                    expect(page.locator('#policy-retry')).to_be_enabled()
                    expect(page.locator('#policy-export')).to_be_disabled()
                    expect(page.locator('#policy-error')).not_to_have_class(re.compile(r'\bsuccess\b'))
                    posts=[]
                    def posted(request):
                        if request.method=='POST': posts.append(request.url)
                    page.on('request', posted)
                    page.locator('#policy-retry').click()
                    expect(page.locator('#policy-error')).to_have_class('success')
                    page.remove_listener('request', posted)
                    assert posts==[], posts  # A known commit needs only a fresh read.
                else:
                    route.fulfill(response=response)
                    page.unroute('**/api/group-policy?*', hold_policy_read)
                expect(page.locator('#policy-export')).to_be_enabled()
                with page.expect_download() as transfer:
                    page.locator('#policy-export').click()
                assert Path(transfer.value.path()).read_text().strip()==store.policy_export('owner',group)['policy']

            page.locator('#credential-use').click()
            expect(page.locator('#policy-preview-result')).to_contain_text('discover')
            assert store.policy_export('owner',group)['claims']['members']=={}
            change_with_delayed_read(lambda: page.locator('#policy-approve').click(), 2)
            expect(page.locator('#policy-status')).to_contain_text('第 2 版')
            expect(page.locator('#policy-grant')).to_have_value('')
            with page.expect_download() as transfer:
                page.locator('#policy-export').click()
            assert Path(transfer.value.path()).read_text().strip()==store.policy_export('owner',group)['policy']
            # Lose the UI acknowledgment after the recipient and receipt have committed.
            delivery_dropped=[False]
            def lose_delivery_ack(route):
                if not delivery_dropped[0]:
                    delivery_dropped[0]=True
                    route.fetch();route.abort()
                else: route.continue_()
            page.route('**/api/policy-deliver',lose_delivery_ack)
            page.locator('#delivery-preview').click()
            expect(page.locator('#delivery-consent')).to_contain_text('第 2 版')
            page.locator('#delivery-confirm').click()
            expect(page.locator('#delivery-retry')).to_be_enabled()
            posts=network.count(('POST','/v1/policies'))
            assert recipient.export_policy()['policy']==store.policy_export('owner',group)['policy']
            page.locator('#delivery-retry').click()
            expect(page.locator('#delivery-error')).to_contain_text('接收第 2 版')
            assert network.count(('POST','/v1/policies'))==posts
            page.unroute('**/api/policy-deliver',lose_delivery_ack)
            # Lose the response AFTER the server commits. Retry must not sign twice.
            async_dropped=[False]
            def lose_response(route):
                if not async_dropped[0]:
                    async_dropped[0]=True
                    route.fetch()
                    route.abort()
                else:
                    route.continue_()
            page.route('**/api/policy-renew', lose_response)
            page.locator('#policy-renew').click()
            expect(page.locator('#policy-retry')).to_be_enabled()
            assert store.policy_export('owner',group)['claims']['revision']==3
            page.locator('#policy-retry').click()
            expect(page.locator('#policy-status')).to_contain_text('第 3 版')
            assert store.policy_export('owner',group)['claims']['revision']==3
            change_with_delayed_read(lambda: page.locator('#policy-renew').click(), 4, fail=True)
            page.on('dialog', lambda dialog: dialog.accept())
            change_with_delayed_read(lambda: page.locator('#policy-members button').click(), 5)
            expect(page.locator('#policy-status')).to_contain_text('第 5 版')
            assert store.policy_export('owner',group)['claims']['members']=={}
            page.locator('#dissolve-name').fill('Browser signed group')
            change_with_delayed_read(lambda: page.locator('#dissolve-group').click(), 6)
            expect(page.locator('#policy-status')).to_contain_text('已签名终止')
            assert store.policy_export('owner',group)['claims']['revision']==6
            expect(page.locator('#policy-renew')).to_be_disabled()
            page.locator('#delivery-preview').click()
            expect(page.locator('#delivery-consent')).to_contain_text('dissolved')
            page.locator('#delivery-confirm').click()
            expect(page.locator('#delivery-error')).to_contain_text('终止策略')
            assert recipient.policy_status()['state']=='dissolved'
            expect(page.locator('#credential-confirm')).to_be_disabled()
            expect(page.locator('#credential-download')).to_be_disabled()
            assert 'd'*32 not in page.content()
            if args.artifacts:
                page.screenshot(path=str(args.artifacts/'policy-desktop.png'))
            page.set_viewport_size({'width':375,'height':812})
            page.locator('#manage-dialog').evaluate('(element)=>element.scrollTop=0')
            bounds=page.locator('#manage-dialog').bounding_box()
            assert bounds['x']>=0 and bounds['x']+bounds['width']<=375
            if args.artifacts:
                page.screenshot(path=str(args.artifacts/'policy-mobile.png'))
            assert not errors, errors
            browser.close()
            print('Browser PASS: explicit credential preview/issuance/download, edited-draft race and lost-ACK recovery; issuance does not approve or contact recipients; separate approval, signing, gated exports, explicit delivery and terminal state; no page errors or stored browser credentials.')
    finally:
        if recipient_server is not None:
            recipient_server.shutdown();recipient_server.server_close();recipient_worker.join();recipient.close()
        server.shutdown(); server.server_close(); worker.join(); store.close()
