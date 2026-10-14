"""Optional Chromium check: install playwright and run with --browser /path/to/chromium."""
import argparse
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
from tailnet_agents.identity import issue_grant

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--browser', default=shutil.which('chromium'), help='existing Chromium binary; otherwise Playwright installation')
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
            page.locator('#manage-group').click()
            expect(page.locator('#policy-status')).to_contain_text('第 1 版')
            grant=issue_grant(owner, agent.public_key(), group, ['join','discover'])
            page.locator('#policy-grant').fill(grant)
            page.locator('#policy-preview').click()
            expect(page.locator('#policy-preview-result')).to_contain_text('discover')
            assert store.policy_export('owner',group)['claims']['members']=={}
            page.locator('#policy-approve').click()
            expect(page.locator('#policy-status')).to_contain_text('第 2 版')
            expect(page.locator('#policy-grant')).to_have_value('')
            with page.expect_download() as transfer:
                page.locator('#policy-export').click()
            assert Path(transfer.value.path()).read_text().strip()==store.policy_export('owner',group)['policy']
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
            expect(page.locator('#policy-retry')).to_be_visible()
            assert store.policy_export('owner',group)['claims']['revision']==3
            page.locator('#policy-retry').click()
            expect(page.locator('#policy-status')).to_contain_text('第 3 版')
            assert store.policy_export('owner',group)['claims']['revision']==3
            page.on('dialog', lambda dialog: dialog.accept())
            page.locator('#policy-members button').click()
            expect(page.locator('#policy-status')).to_contain_text('第 4 版')
            assert store.policy_export('owner',group)['claims']['members']=={}
            page.locator('#dissolve-name').fill('Browser signed group')
            page.locator('#dissolve-group').click()
            expect(page.locator('#policy-status')).to_contain_text('已签名终止')
            assert store.policy_export('owner',group)['claims']['revision']==5
            expect(page.locator('#policy-renew')).to_be_disabled()
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
            print('Browser PASS: explicit creation, verified preview, approval, download, uncertain-response retry once, removal, terminal dissolution; no page errors.')
    finally:
        server.shutdown(); server.server_close(); worker.join(); store.close()
