"""Chromium regression for explicitly read, source-scoped simulation presence."""
import argparse
from http.server import ThreadingHTTPServer
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from playwright.sync_api import sync_playwright, expect
from tailnet_agents.agent_runtime import AgentRuntime
from tailnet_agents.chat import ChatStore
from tailnet_agents.identity import issue_grant, identity_id
from tailnet_agents.policy_admin import PolicyAuthority
from tailnet_agents.policy_delivery import PolicyTarget
from tailnet_agents.verified_directory import VerifiedDirectory
from tailnet_agents.admission_server import handler as admission_handler
from tailnet_agents.ui import handler

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--browser', default=shutil.which('chromium') or shutil.which('google-chrome'))
parser.add_argument('--artifacts', type=Path)
args = parser.parse_args()
if args.artifacts: args.artifacts.mkdir(parents=True, exist_ok=True)

with tempfile.TemporaryDirectory() as folder:
    owner = Ed25519PrivateKey.generate()
    store = ChatStore(str(Path(folder)/'chat.sqlite3'), policy_authority=PolicyAuthority(owner, 'owner'))
    servers, runtimes, nodes = [], [], []
    network = []
    def serve(http_handler):
        server = ThreadingHTTPServer(('127.0.0.1', 0), http_handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True);thread.start()
        servers.append((server, thread))
        return f'http://127.0.0.1:{server.server_port}'
    try:
        group = store.create_group('Runtime monitor', 'owner', ['observer'], signed_policy=True)['id']
        credentials = []
        for index in range(2):
            agent = Ed25519PrivateKey.generate()
            grant = issue_grant(owner, agent.public_key(), group, ['join'], now=int(time.time()))
            store.policy_change('owner', group, 'approve', {'expected_revision': index+1, 'request_id': str(index), 'grant': grant})
            credentials.append((agent, grant))
        targets = []
        for target_id in ('primary', 'secondary'):
            node = VerifiedDirectory(owner.public_key(), group, 'browser-directory', require_policy=True)
            nodes.append(node)
            node.apply_policy(store.policy_export('owner', group)['policy'])
            def recording(directory, source):
                class Recipient(admission_handler(directory, 'd'*32)):
                    def do_GET(inner): network.append((source, 'GET', inner.path));super().do_GET()
                    def do_POST(inner): network.append((source, 'POST', inner.path));super().do_POST()
                return Recipient
            url = serve(recording(node, target_id))
            targets.append(PolicyTarget(target_id, url, group, 'd'*32))
        store.configure_policy_targets(targets)
        for index, (agent, grant) in enumerate(credentials):
            runtime = AgentRuntime(targets[0].url, agent, owner.public_key(), grant, group, 'browser-directory',
                                   Path(folder)/(str(index)+'.sqlite3'), {'name': 'Same host',
                                   'endpoint': 'https://never-contact.example:8901', 'ttl_seconds': 10})
            runtimes.append(runtime)
        def heartbeat():
            for runtime in runtimes: assert runtime.step()['state']=='registered'
        heartbeat()
        original_leases = list(nodes[0]._registry.db.execute('SELECT id,expires FROM agents ORDER BY id'))
        network.clear()
        url = serve(handler(store, {'owner': {'role': 'admin', 'token': 'b'*32}, 'observer': {'role': 'observer', 'token': 'w'*32}}))
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path=args.browser, headless=True)
            page = browser.new_page(viewport={'width': 1360, 'height': 900})
            errors, requests = [], []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.on('request', lambda request: requests.append(request.url))
            page.goto(url)
            page.locator('#token').fill('b'*32)
            page.locator('#login-form button').click()
            expect(page.locator('#workspace')).to_be_visible()
            page.locator('#manage-group').click()
            expect(page.locator('#runtime-refresh')).to_be_enabled()
            assert network==[]  # Startup, management and metadata listing stay local.
            heartbeat()
            original_leases = list(nodes[0]._registry.db.execute('SELECT id,expires FROM agents ORDER BY id'))
            network.clear()
            page.locator('#runtime-refresh').click()
            expect(page.locator('.runtime-state.online')).to_have_count(2)
            expect(page.locator('#runtime-status')).to_contain_text(targets[0].url)
            assert len(set(page.locator('.runtime-subject').all_text_contents()))==2
            assert list(nodes[0]._registry.db.execute('SELECT id,expires FROM agents ORDER BY id'))==original_leases
            assert all(method=='GET' for _, method, _ in network)
            assert not any('never-contact.example' in request for request in requests)
            assert 'd'*32 not in page.content()
            if args.artifacts:
                page.locator('#runtime-panel').scroll_into_view_if_needed()
                page.screenshot(path=str(args.artifacts/'runtime-desktop.png'))
                page.set_viewport_size({'width':375,'height':812})
                page.locator('#runtime-panel').scroll_into_view_if_needed()
                assert page.evaluate("document.querySelector('#manage-dialog').scrollWidth<=document.querySelector('#manage-dialog').clientWidth")
                page.screenshot(path=str(args.artifacts/'runtime-mobile.png'))
                page.set_viewport_size({'width':1360,'height':900})
            before = list(network)
            page.evaluate('window.originalNow=Date.now; window.futureNow=Date.now()+12000; Date.now=()=>window.futureNow')
            expect(page.locator('.runtime-state.expired')).to_have_count(2)
            page.evaluate('Date.now=window.originalNow')
            # A backwards browser clock cannot revive an already expired snapshot.
            expect(page.locator('.runtime-state.online')).to_have_count(0)
            assert network==before
            page.locator('#runtime-target').select_option('secondary')
            expect(page.locator('.runtime-entry')).to_have_count(0)
            assert network==before
            page.locator('#runtime-refresh').click()
            expect(page.locator('#runtime-entries')).to_contain_text('暂无签名 runtime 观测')
            page.locator('#runtime-target').select_option('primary')
            heartbeat()
            page.locator('#runtime-refresh').click()
            expect(page.locator('.runtime-state.online')).to_have_count(2)
            def fail(route): route.abort()
            page.route('**/api/runtime-presence?*', fail)
            page.locator('#runtime-refresh').click()
            expect(page.locator('#runtime-status')).to_contain_text('本次读取未确认')
            expect(page.locator('.runtime-entry')).to_have_count(0)
            page.unroute('**/api/runtime-presence?*', fail)
            held = []
            def hold(route):
                held.append((route, route.fetch()))
                page.evaluate("document.body.dataset.runtimeHeld='yes'")
            def begin_hold():
                page.evaluate('delete document.body.dataset.runtimeHeld')
                page.route('**/api/runtime-presence?*', hold)
                page.locator('#runtime-refresh').click()
                expect(page.locator('body')).to_have_attribute('data-runtime-held', 'yes')
            def release():
                route, response = held.pop();route.fulfill(response=response)
                page.unroute('**/api/runtime-presence?*', hold)
            begin_hold()
            page.locator('#runtime-target').select_option('secondary')
            release()
            expect(page.locator('#runtime-status')).to_contain_text('尚未读取')
            expect(page.locator('.runtime-entry')).to_have_count(0)
            page.locator('#runtime-target').select_option('primary')
            heartbeat();begin_hold()
            page.locator('#close-manage').click()
            release()
            page.locator('#manage-group').click()
            expect(page.locator('#runtime-status')).to_contain_text('尚未读取')
            expect(page.locator('.runtime-entry')).to_have_count(0)
            heartbeat();begin_hold()
            page.locator('#policy-renew').click()
            expect(page.locator('#policy-status')).to_contain_text('第 4 版')
            release()
            expect(page.locator('.runtime-entry')).to_have_count(0)
            # Reading an undelivered local revision never pushes policy to the source.
            heartbeat();network.clear()
            page.locator('#runtime-refresh').click()
            expect(page.locator('.runtime-state.unconfirmed')).to_have_count(2)
            expect(page.locator('#runtime-status')).to_contain_text('策略与本机不同')
            assert all(method=='GET' for _, method, _ in network)
            page.evaluate('window.futureNow=window.originalNow()+12000; Date.now=()=>window.futureNow')
            expect(page.locator('.runtime-state.expired')).to_have_count(2)
            page.evaluate('Date.now=window.originalNow')
            expect(page.locator('.runtime-state.unconfirmed')).to_have_count(0)
            begin_hold()
            page.evaluate("document.querySelector('#logout').onclick()")
            release()
            expect(page.locator('#login')).to_be_visible()
            expect(page.locator('.runtime-entry')).to_have_count(0)
            assert page.locator('#runtime-target option').count()==0
            page.locator('#token').fill('w'*32)
            page.locator('#login-form button').click()
            expect(page.locator('#workspace')).to_be_visible()
            expect(page.locator('#manage-group')).not_to_be_visible()
            assert page.request.get(url+'/api/runtime-presence?group_id='+group+'&target_id=primary', headers={'Authorization': 'Bearer '+'w'*32}).status==403
            assert page.evaluate('localStorage.length+sessionStorage.length')==0
            assert not errors, errors
            browser.close()
        print('Runtime browser PASS: explicit source-only GET, two same-host identities, expiry/clock rollback, failure clears online state, target/close/logout/policy races, policy mismatch, roles and no browser credentials.')
    finally:
        for runtime in runtimes: runtime.close()
        for server, thread in reversed(servers): server.shutdown();server.server_close();thread.join()
        for node in nodes: node.close()
        store.close()
