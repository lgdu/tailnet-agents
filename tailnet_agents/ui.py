"""Loopback-only role-aware Web UI for simulated chat."""
import argparse
import hmac
import json
import os
import re
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib.error import HTTPError
from .chat import ChatStore, PolicyDeliveryError, RuntimeMonitorError

WEB = Path(__file__).parent / 'web'


class TaskUIError(ValueError):
    """Preserve original consent/task after an unconfirmed operation."""


def validate_users(users):
    if not isinstance(users, dict) or not users:
        raise ValueError('users must be a nonempty object')
    tokens = set()
    for principal, config in users.items():
        if not isinstance(principal, str) or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,64}', principal):
            raise ValueError('invalid human identity')
        if not isinstance(config, dict) or set(config) != {'token', 'role'}:
            raise ValueError('each human needs token and role')
        token, role = config['token'], config['role']
        if not isinstance(token, str) or len(token) < 32 or not token.isascii() or token in tokens:
            raise ValueError('human tokens must be unique ASCII secrets of at least 32 characters')
        if role not in ('admin', 'participant', 'observer'):
            raise ValueError('invalid human role')
        tokens.add(token)
    return users


def handler(store, users, *, task_bridge=None):
    if isinstance(users, str):
        users = {'demo-owner': {'token': users, 'role': 'admin'}}
    validate_users(users)
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *_):
            pass

        def response(self, status, data, content_type='application/json'):
            body = data if isinstance(data, bytes) else json.dumps(data).encode()
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(body)

        def local_request(self):
            allowed = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
            host = self.headers.get('Host', '')
            origin = self.headers.get('Origin')
            if host not in allowed or (origin and origin != 'http://' + host):
                raise PermissionError('local origin required')

        def authorize(self):
            self.local_request()
            auth = self.headers.get('Authorization', '')
            if auth.startswith('Bearer '):
                for principal, config in users.items():
                    if hmac.compare_digest(auth[7:].encode(), config['token'].encode()):
                        return principal, config['role']
            raise PermissionError('invalid UI credential')

        def task_call(self, principal, role, group, method, *args):
            if role != 'admin' or task_bridge is None:
                raise PermissionError('explicit human task configuration required')
            try:
                store.require_group(principal, group)
                return getattr(task_bridge, method)(principal, group, *args)
            except PermissionError:
                raise PermissionError('configured task human/group access required') from None
            except FileExistsError:
                raise FileExistsError('Task consent/state conflicts; inspect the original task and preview again.') from None
            except (KeyError, ValueError, TypeError):
                raise ValueError('Invalid task request; use the original configured binding and task.') from None
            except (OSError, sqlite3.Error) as error:
                if isinstance(error, HTTPError):error.close()
                raise TaskUIError('Task result unconfirmed; retain the original consent/task and retry explicitly. Check authorization, TLS and connectivity.') from None

        def do_GET(self):
            try:
                self.local_request()
                parsed = urlparse(self.path)
                static = {'/': ('index.html', 'text/html; charset=utf-8'),
                          '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                          '/tasks.js': ('tasks.js', 'text/javascript; charset=utf-8'),
                          '/app.css': ('app.css', 'text/css; charset=utf-8')}
                if parsed.path in static:
                    filename, mime = static[parsed.path]
                    return self.response(200, (WEB / filename).read_bytes(), mime)
                principal, role = self.authorize()
                if parsed.path == '/api/me':
                    return self.response(200, {'id': principal, 'role': role})
                if parsed.path == '/api/task-bindings':
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    if set(query) != {'group_id'} or len(query['group_id']) != 1:
                        raise ValueError('one explicit task group required')
                    if task_bridge is None:
                        store.require_group(principal, query['group_id'][0])
                        return self.response(200, {'bindings': []})
                    return self.response(200, self.task_call(principal, role, query['group_id'][0], 'catalog'))
                if parsed.path == '/api/policy-config':
                    if parsed.query:
                        raise ValueError('policy config takes no query')
                    authority = store.policy_authority
                    return self.response(200, {'enabled': authority is not None,
                        'can_sign': authority is not None and role == 'admin' and principal == authority.principal})
                if parsed.path == '/api/group-policy':
                    if role != 'admin':
                        raise PermissionError('admin role required')
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    if set(query) != {'group_id'} or len(query['group_id']) != 1:
                        raise ValueError('one explicit group ID required')
                    return self.response(200, store.policy_export(principal, query['group_id'][0]))
                if parsed.path == '/api/runtime-presence':
                    if role != 'admin':
                        raise PermissionError('admin role required')
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    if (not {'group_id', 'target_id'} <= set(query) or set(query) - {'group_id', 'target_id', 'after', 'limit'} or
                            any(len(values) != 1 for values in query.values())):
                        raise ValueError('one configured directory and group required')
                    return self.response(200, store.runtime_presence(principal, query['group_id'][0], query['target_id'][0],
                        after=query.get('after', [''])[0], limit=int(query.get('limit', ['20'])[0])))
                if parsed.path in ('/api/policy-targets', '/api/policy-deliveries', '/api/credential-issuances'):
                    if role != 'admin':
                        raise PermissionError('admin role required')
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    if set(query) != {'group_id'} or len(query['group_id']) != 1:
                        raise ValueError('one explicit group ID required')
                    method = {'/api/policy-targets': store.policy_recipients, '/api/policy-deliveries': store.policy_delivery_history,
                              '/api/credential-issuances': store.credential_history}[parsed.path]
                    return self.response(200, method(principal, query['group_id'][0]))
                if parsed.path == '/api/groups':
                    return self.response(200, {'groups':store.groups(principal)})
                if parsed.path == '/api/humans':
                    if role != 'admin':
                        raise PermissionError('admin role required')
                    return self.response(200, {'humans':[{'id':p,'role':c['role']} for p,c in users.items()]})
                if parsed.path == '/api/group-info':
                    group_id=parse_qs(parsed.query).get('group_id',[''])[0]
                    return self.response(200,store.group_info(principal,group_id))
                if parsed.path == '/api/members':
                    group_id = parse_qs(parsed.query).get('group_id',['legacy'])[0]
                    store.require_group(principal,group_id)
                    return self.response(200, {'members': store.members()})
                if parsed.path == '/api/messages':
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    if set(query) - {'conversation','after','before','limit','group_id'} or any(len(v) != 1 for v in query.values()):
                        raise ValueError('invalid history query')
                    conversation = query.get('conversation', ['group'])[0]
                    if role == 'observer' and conversation != 'group':
                        raise PermissionError('observer cannot access private conversations')
                    group_id = query.get('group_id',['legacy'])[0]
                    store.require_group(principal,group_id)
                    options = {key: int(query[key][0]) for key in ('after','before','limit') if key in query}
                    return self.response(200, store.page(conversation, principal, group_id=group_id, enforce_access=True, **options))
                self.response(404, {'error': 'not found'})
            except FileExistsError as exc:
                self.response(409, {'error': str(exc)})
            except PermissionError as exc:
                self.response(403, {'error': str(exc)})
            except RuntimeMonitorError as exc:
                self.response(502, {'error': str(exc)})
            except TaskUIError as exc:
                self.response(502, {'error': str(exc)})
            except ValueError as exc:
                self.response(400, {'error': str(exc)})

        def do_POST(self):
            try:
                principal, role = self.authorize()
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 65536:
                    return self.response(413, {'error': 'invalid body size'})
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError('body must be an object')
                if self.path == '/api/groups':
                    if role != 'admin':
                        raise PermissionError('admin role required')
                    if (not {'name','humans','request_id'} <= set(payload) or set(payload) - {'name','humans','request_id','signed_policy'} or
                        not isinstance(payload.get('request_id'),str) or not 1<=len(payload['request_id'])<=128 or not isinstance(payload['humans'],list) or any(not isinstance(p,str) or p not in users for p in payload['humans'])):
                        raise ValueError('select configured human members')
                    return self.response(201,store.create_group(payload['name'],principal,payload['humans'],request_id=payload['request_id'], signed_policy=payload.get('signed_policy', False)))
                if self.path in ('/api/task-read', '/api/task-preview', '/api/task-confirm') and 'group_id' not in payload:
                    raise ValueError('explicit task group required')
                group_id = payload.pop('group_id','legacy')
                if not isinstance(group_id,str):
                    raise ValueError('invalid group id')
                store.require_group(principal,group_id)
                if self.path in ('/api/task-read', '/api/task-preview', '/api/task-confirm'):
                    method = {'/api/task-read':'read', '/api/task-preview':'preview', '/api/task-confirm':'confirm'}[self.path]
                    return self.response(200, self.task_call(principal, role, group_id, method, payload))
                if self.path in ('/api/policy-preview', '/api/policy-approve', '/api/policy-remove', '/api/policy-renew', '/api/policy-delivery-preview', '/api/policy-deliver', '/api/credential-preview', '/api/credential-issue', '/api/policy-source-check', '/api/policy-renew-preview', '/api/policy-renew-confirm'):
                    authority = store.policy_authority
                    if role != 'admin' or authority is None or principal != authority.principal:
                        raise PermissionError('configured policy administrator required')
                    if self.path in ('/api/policy-source-check', '/api/policy-renew-preview'):
                        return self.response(200, store.policy_review(principal, group_id, payload, renewal=self.path == '/api/policy-renew-preview'))
                    if self.path == '/api/policy-renew-confirm':
                        return self.response(200, store.policy_renew_confirm(principal, group_id, payload))
                    if self.path in ('/api/credential-preview', '/api/credential-issue'):
                        method = store.credential_preview if self.path == '/api/credential-preview' else store.credential_issue
                        return self.response(200, method(principal, group_id, payload))
                    if self.path == '/api/policy-delivery-preview':
                        return self.response(200, store.policy_delivery_preview(principal, group_id, payload))
                    if self.path == '/api/policy-deliver':
                        return self.response(200, store.policy_deliver(principal, group_id, payload))
                    if self.path == '/api/policy-preview':
                        if set(payload) != {'grant'}:
                            raise ValueError('signed grant required')
                        return self.response(200, store.policy_preview(principal, group_id, payload['grant']))
                    operation = self.path.removeprefix('/api/policy-')
                    return self.response(200, store.policy_change(principal, group_id, operation, payload))
                if self.path == '/api/group-members':
                    if role!='admin':
                        raise PermissionError('admin role required')
                    if set(payload)!={'subject','operation'} or not isinstance(payload.get('subject'),str) or payload['subject'] not in users:
                        raise ValueError('select a configured human')
                    return self.response(200,store.update_member(principal,group_id,payload['subject'],payload['operation']))
                if self.path == '/api/group-dissolve':
                    if role!='admin':
                        raise PermissionError('admin role required')
                    if set(payload)!={'confirm_name'}:
                        raise ValueError('group name confirmation required')
                    return self.response(200,store.dissolve_group(principal,group_id,payload['confirm_name']))
                if self.path == '/api/messages':
                    if role == 'observer':
                        raise PermissionError('observer cannot send messages')
                    return self.response(200, store.send(payload, principal, group_id, enforce_access=True))
                if self.path == '/api/presence':
                    if role != 'admin':
                        raise PermissionError('admin role required')
                    store.require_group(principal,group_id,active=True)
                    store.set_online(payload.get('agent'), payload.get('online'))
                    return self.response(200, {'members': store.members()})
                self.response(404, {'error': 'not found'})
            except PermissionError as exc:
                self.response(403, {'error': str(exc)})
            except FileExistsError as exc:
                self.response(409, {'error': str(exc)})
            except PolicyDeliveryError as exc:
                self.response(502, {'error': str(exc)})
            except TaskUIError as exc:
                self.response(502, {'error': str(exc)})
            except (ValueError, UnicodeError, TypeError) as exc:
                self.response(400, {'error': str(exc)})
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8770)
    parser.add_argument('--database', default='state/chat.sqlite3')
    parser.add_argument('--policy-owner-key', help='existing private owner PEM on this trusted local gateway')
    parser.add_argument('--policy-owner-public-key', help='separate pinned owner public key file')
    parser.add_argument('--policy-admin', help='configured admin human allowed to sign group policies')
    parser.add_argument('--policy-targets-file', help='trusted recipient JSON; origins/groups and credential environment names')
    parser.add_argument('--task-bindings-file', help='private explicit human/signed-caller bindings; see docs/task-ui.md')
    args = parser.parse_args()
    store = task_bridge = None
    try:
        configured = os.environ.get('TAILNET_UI_USERS')
        users = json.loads(configured) if configured else {
            'demo-owner': {'token': os.environ.get('TAILNET_UI_TOKEN', ''), 'role': 'admin'}}
        validate_users(users)
        signing = (args.policy_owner_key, args.policy_owner_public_key, args.policy_admin)
        authority = None
        if any(signing):
            if not all(signing) or users.get(args.policy_admin, {}).get('role') != 'admin':
                raise ValueError('complete policy authority configuration and admin role required')
            from .policy_admin import PolicyAuthority
            authority = PolicyAuthority.from_files(*signing)
        targets = ()
        if args.policy_targets_file:
            if authority is None:
                raise ValueError('explicit policy recipients require the configured signer')
            from .policy_delivery import load_policy_targets
            targets = load_policy_targets(args.policy_targets_file)
        store = ChatStore(args.database, policy_authority=authority, policy_targets=targets)
        if args.task_bindings_file:
            from .task_ui import TaskBridge
            task_bridge = TaskBridge.from_file(store, users, args.task_bindings_file)
        elif store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ui_task_bindings'").fetchone() and store.db.execute('SELECT 1 FROM ui_task_bindings').fetchone():
            raise ValueError('restart requires original explicit task bindings')
    except (ImportError, ValueError, TypeError, OSError, sqlite3.Error):
        if task_bridge is not None:task_bridge.close()
        if store is not None:store.close()
        parser.error('Invalid human credentials or policy authority configuration; see docs/ui.md')
    class UIServer(ThreadingHTTPServer):
        daemon_threads = False  # Finish authorized transactions before closing SQLite.
    try:
        server = UIServer(('127.0.0.1', args.port), handler(store, users, task_bridge=task_bridge))
    except Exception:
        if task_bridge is not None:task_bridge.close()
        store.close()
        raise
    print(f'Simulated chat UI: http://127.0.0.1:{server.server_port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if task_bridge is not None:task_bridge.close()
        store.close()


if __name__ == '__main__':
    main()
