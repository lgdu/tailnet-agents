"""Loopback-only single-owner Web UI for simulated chat."""
import argparse
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from .chat import ChatStore

WEB = Path(__file__).parent / 'web'


def handler(store, token):
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
            if not auth.startswith('Bearer ') or not hmac.compare_digest(auth[7:].encode(), token.encode()):
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
                self.authorize()
                if parsed.path == '/api/members':
                    return self.response(200, {'members': store.members()})
                if parsed.path == '/api/messages':
                    conversation = parse_qs(parsed.query).get('conversation', ['group'])[0]
                    return self.response(200, {'messages': store.history(conversation)})
                self.response(404, {'error': 'not found'})
            except PermissionError as exc:
                self.response(403, {'error': str(exc)})
            except ValueError as exc:
                self.response(400, {'error': str(exc)})

        def do_POST(self):
            try:
                self.authorize()
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 65536:
                    return self.response(413, {'error': 'invalid body size'})
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError('body must be an object')
                if self.path == '/api/messages':
                    return self.response(200, store.send(payload))
                if self.path == '/api/presence':
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
    token = os.environ.get('TAILNET_UI_TOKEN', '')
    if len(token) < 32 or not token.isascii():
        parser.error('TAILNET_UI_TOKEN must contain at least 32 ASCII characters')
    store = ChatStore(args.database)
    server = ThreadingHTTPServer(('127.0.0.1', args.port), handler(store, token))
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
