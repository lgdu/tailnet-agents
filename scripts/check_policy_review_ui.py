"""Chromium: explicit source review, fixed renewal consent and stale-response guards."""
import argparse
from pathlib import Path
import shutil
import sys
import tempfile
import threading
from urllib.error import URLError
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from http.server import ThreadingHTTPServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from playwright.sync_api import sync_playwright,expect
from tailnet_agents.chat import ChatStore
from tailnet_agents.ui import handler
from tailnet_agents.policy_admin import PolicyAuthority
from tailnet_agents.policy_delivery import PolicyTarget
from tailnet_agents.verified_directory import VerifiedDirectory
from tailnet_agents.admission_server import handler as admission_handler
from tailnet_agents.group_policy import POLICY_TYPE
from tailnet_agents.identity import sign

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--browser',default=shutil.which('chromium') or shutil.which('google-chrome'))
args=parser.parse_args()
with tempfile.TemporaryDirectory() as folder:
    owner=Ed25519PrivateKey.generate();store=ChatStore(str(Path(folder)/'chat.sqlite3'),policy_authority=PolicyAuthority(owner,'owner'))
    group=store.create_group('Source review','owner',['owner'],request_id='explicit-human',signed_policy=True)['id']
    second=store.create_group('Other group','owner',['owner'],request_id='other-human',signed_policy=True)['id']
    nodes=[];servers=[];threads=[];targets=[];network=[]
    def serve(request_handler):
        server=ThreadingHTTPServer(('127.0.0.1',0),request_handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        servers.append(server);threads.append(thread)
        return f'http://127.0.0.1:{server.server_port}'
    for index in range(2):
        node=VerifiedDirectory(owner.public_key(),group,'directory',require_policy=True,database=str(Path(folder)/f'node-{index}.sqlite3'))
        nodes.append(node);node.apply_policy(store.policy_export('owner',group)['policy'])
        class Tracked(admission_handler(node,'d'*32)):
            def do_GET(inner):network.append(('GET',inner.path));super().do_GET()
            def do_POST(inner):network.append(('POST',inner.path));super().do_POST()
        url=serve(Tracked);targets.append(PolicyTarget(f'source-{index}',url,group,'d'*32))
    store.configure_policy_targets(targets)
    url=serve(handler(store,{'owner':{'role':'admin','token':'b'*32}}))
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=args.browser,headless=True)
            page=browser.new_page(viewport={'width':1360,'height':1000});errors=[]
            page.on('pageerror',lambda error:errors.append(str(error)))
            page.goto(url);page.locator('#token').fill('b'*32);page.locator('#login-form button').click()
            expect(page.locator('#workspace')).to_be_visible()
            page.locator('#group-select').select_option(group)
            page.locator('#manage-group').click();expect(page.locator('#manage-dialog')).to_be_visible()
            assert network==[]
            page.locator('#source-check').click()
            expect(page.locator('#source-results li')).to_have_count(2)
            expect(page.locator('#source-status')).to_contain_text('2 个配置来源')
            assert len(network)==6 and all(method=='GET' for method,_ in network)
            assert store.policy_export('owner',group)['claims']['revision']==1
            assert 'd'*32 not in page.content()
            page.locator('#policy-renew').click();expect(page.locator('#renewal-confirm')).to_be_enabled()
            expect(page.locator('#renewal-consent')).to_contain_text('原成员、权限和凭证 ID 不变')
            assert store.policy_export('owner',group)['claims']['revision']==1
            # Expiry stays invalid after browser wall-clock rollback.
            page.evaluate('window.savedDateNow=Date.now;Date.now=()=>window.savedDateNow()+61000')
            expect(page.locator('#renewal-confirm')).to_be_disabled()
            page.evaluate('Date.now=window.savedDateNow')
            expect(page.locator('#renewal-confirm')).to_be_disabled()
            page.locator('#policy-renew').click();expect(page.locator('#renewal-confirm')).to_be_enabled()
            page.locator('#renewal-confirm').click();expect(page.locator('#policy-status')).to_contain_text('第 2 版')
            assert all(node._policy.current()['revision']==1 for node in nodes)
            assert all(method=='GET' for method,_ in network)
            # Known read failures replace the previous positive source row.
            with patch.object(targets[1].client,'request',side_effect=URLError('SECRET')):
                page.locator('#source-check').click()
                expect(page.locator('#source-results li').nth(1)).to_contain_text('error')
            assert 'SECRET' not in page.content()
            # A response from a closed management view cannot revive consent.
            held=[]
            def hold(route):
                held.append((route,route.fetch()));page.evaluate("document.body.dataset.reviewHeld='yes'")
            page.route('**/api/policy-renew-preview',hold)
            page.locator('#policy-renew').click();expect(page.locator('body')).to_have_attribute('data-review-held','yes')
            page.locator('#close-manage').click();route,response=held.pop();route.fulfill(response=response)
            page.unroute('**/api/policy-renew-preview',hold)
            page.locator('#manage-group').click();expect(page.locator('#renewal-confirm')).to_be_disabled()
            expect(page.locator('#source-status')).to_contain_text('尚未核对')
            # Switching group discards a late source report.
            page.evaluate("delete document.body.dataset.reviewHeld")
            page.route('**/api/policy-source-check',hold)
            page.locator('#source-check').click();expect(page.locator('body')).to_have_attribute('data-review-held','yes')
            page.locator('#close-manage').click();page.locator('#group-select').select_option(second)
            route,response=held.pop();route.fulfill(response=response);page.unroute('**/api/policy-source-check',hold)
            page.locator('#manage-group').click();expect(page.locator('#source-results li')).to_have_count(0)
            page.locator('#close-manage').click();page.locator('#group-select').select_option(group)
            page.locator('#manage-group').click()
            # Same-revision owner equivocation blocks signing, including after close/reopen and source removal.
            claims=store.policy_export('owner',group)['claims'] | {'name':'Owner fork'}
            fork=sign(owner,claims,POLICY_TYPE)
            with nodes[1]._registry.db:nodes[1]._registry.db.execute('UPDATE group_policy SET token=?',(fork,))
            page.locator('#source-check').click();expect(page.locator('#source-status')).to_contain_text('equivocation')
            expect(page.locator('#policy-renew')).to_be_disabled();expect(page.locator('#renewal-confirm')).to_be_disabled()
            store.configure_policy_targets([])
            page.locator('#close-manage').click();page.locator('#manage-group').click()
            expect(page.locator('#source-status')).to_contain_text('已保存的签名历史')
            expect(page.locator('#policy-renew')).to_be_disabled()
            assert store.policy_export('owner',group)['claims']['revision']==2
            page.set_viewport_size({'width':375,'height':812})
            assert page.evaluate("document.querySelector('#manage-dialog').scrollWidth<=document.querySelector('#manage-dialog').clientWidth")
            assert page.evaluate('localStorage.length')==0 and page.evaluate('sessionStorage.length')==0
            assert not errors,errors
            browser.close()
        print('Policy review browser PASS: explicit all-source GETs, no signing/delivery before consent, fixed-time renewal, expiry/rollback, failed reads, close/group races, sticky conflict and narrow-screen layout; no page errors or stored browser credentials.')
    finally:
        for server in servers:server.shutdown();server.server_close()
        for thread in threads:thread.join()
        for node in nodes:node.close()
        store.close()
