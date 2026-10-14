"""Loopback-only role-aware Web UI for simulated chat."""
import argparse
import hmac
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from .chat import ChatStore

WEB = Path(__file__).parent / 'web'


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


def handler(store, users):
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

        def do_GET(self):
            try:
                self.local_request()
                parsed = urlparse(self.path)
                static = {'/': ('index.html', 'text/html; charset=utf-8'),
                          '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                          '/app.css': ('app.css', 'text/css; charset=utf-8')}
                if parsed.path in static:
                    filename, mime = static[parsed.path]
                    return self.response(200, (WEB / filename).read_bytes(), mime)
                principal, role = self.authorize()
                if parsed.path == '/api/me':
                    return self.response(200, {'id': principal, 'role': role})
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
            except PermissionError as exc:
                self.response(403, {'error': str(exc)})
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
                    if set(payload) != {'name','humans','request_id'} or not isinstance(payload.get('request_id'),str) or not 1<=len(payload['request_id'])<=128 or not isinstance(payload['humans'],list) or any(not isinstance(p,str) or p not in users for p in payload['humans']):
                        raise ValueError('select configured human members')
                    return self.response(201,store.create_group(payload['name'],principal,payload['humans'],request_id=payload['request_id']))
                group_id = payload.pop('group_id','legacy')
                if not isinstance(group_id,str):
                    raise ValueError('invalid group id')
                store.require_group(principal,group_id)
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
            except (ValueError, UnicodeError, TypeError) as exc:
                self.response(400, {'error': str(exc)})
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8770)
    parser.add_argument('--database', default='state/chat.sqlite3')
    args = parser.parse_args()
    try:
        configured = os.environ.get('TAILNET_UI_USERS')
        users = json.loads(configured) if configured else {
            'demo-owner': {'token': os.environ.get('TAILNET_UI_TOKEN', ''), 'role': 'admin'}}
        validate_users(users)
    except (ValueError, TypeError):
        parser.error('Invalid human credentials; see docs/ui.md')
    store = ChatStore(args.database)
    server = ThreadingHTTPServer(('127.0.0.1', args.port), handler(store, users))
    print(f'Simulated chat UI: http://127.0.0.1:{server.server_port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        store.close()


if __name__ == '__main__':
    main()
