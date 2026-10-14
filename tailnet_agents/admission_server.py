"""Loopback-only HTTP transport for the optional verified directory."""
import argparse
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs,urlparse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .identity import AdmissionError,decode
from .verified_directory import VerifiedDirectory


def handler(directory,read_token):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self,*_):
            pass

        def respond(self,status,payload):
            body=json.dumps(payload).encode()
            self.send_response(status)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(body)))
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.end_headers()
            self.wfile.write(body)

        def local(self):
            host=self.headers.get('Host','')
            allowed={f'127.0.0.1:{self.server.server_port}',f'localhost:{self.server.server_port}'}
            origin=self.headers.get('Origin')
            if host not in allowed or (origin and origin!='http://'+host):
                raise PermissionError('loopback origin required')

        def read_auth(self):
            auth=self.headers.get('Authorization','')
            if not auth.startswith('Bearer ') or not hmac.compare_digest(auth[7:].encode(),read_token.encode()):
                raise PermissionError('directory read credential required')

        def do_GET(self):
            try:
                self.local()
                parsed=urlparse(self.path)
                if parsed.path=='/healthz':
                    return self.respond(200,{'status':'ok','mode':'verified-loopback'})
                if parsed.path!='/v1/agents':
                    return self.respond(404,{'error':'not found'})
                self.read_auth()
                query=parse_qs(parsed.query,keep_blank_values=True)
                if set(query)-{'skill'} or any(len(v)!=1 for v in query.values()):
                    raise ValueError('invalid discovery query')
                self.respond(200,{'agents':directory.discover(query.get('skill',[None])[0])})
            except PermissionError:
                self.respond(403,{'error':'request not authorized'})
            except ValueError:
                self.respond(400,{'error':'invalid request'})

        def do_POST(self):
            try:
                self.local()
                if self.path not in ('/v1/challenges','/v1/registrations','/v1/revocations'):
                    return self.respond(404,{'error':'not found'})
                if self.path=='/v1/revocations':
                    self.read_auth()
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=65536:
                    return self.respond(413,{'error':'body must be 1..65536 bytes'})
                payload=json.loads(self.rfile.read(size))
                if not isinstance(payload,dict):
                    raise ValueError('object required')
                if self.path=='/v1/challenges':
                    if set(payload)!={'record'}:
                        raise ValueError('invalid challenge fields')
                    try:
                        return self.respond(200,directory.challenge(payload['record']))
                    except AdmissionError as exc:
                        if str(exc)=='challenge capacity reached':
                            return self.respond(429,{'error':'challenge capacity reached; retry later'})
                        raise
                if self.path=='/v1/registrations':
                    if set(payload)!={'record','grant','public_key','proof','nonce'}:
                        raise ValueError('invalid registration fields')
                    if not all(isinstance(payload[k],str) for k in ('grant','public_key','proof','nonce')):
                        raise ValueError('invalid registration values')
                    key=Ed25519PublicKey.from_public_bytes(decode(payload['public_key']))
                    result=directory.register(payload['grant'],key,payload['proof'],payload['nonce'],payload['record'])
                    return self.respond(200,result)
                if set(payload)!={'revocation'}:
                    raise ValueError('invalid revocation fields')
                directory.revoke(payload['revocation'])
                self.respond(200,{'revoked':True})
            except (PermissionError,AdmissionError):
                # Do not expose grant, proof, keys, prompts or detailed verifier errors.
                self.respond(403,{'error':'request not authorized'})
            except (ValueError,UnicodeError,TypeError):
                self.respond(400,{'error':'invalid request'})
    return Handler


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authority-public-key',required=True,help='file containing raw Ed25519 public key in base64url')
    parser.add_argument('--group-id',required=True,help='existing human-created group ID')
    parser.add_argument('--audience',required=True,help='trusted verifier identity agreed out of band')
    parser.add_argument('--port',type=int,default=8771)
    parser.add_argument('--database',default='state/verified-directory.sqlite3')
    args=parser.parse_args()
    token=os.environ.get('TAILNET_VERIFIED_READ_TOKEN','')
    if len(token)<32 or not token.isascii():
        parser.error('TAILNET_VERIFIED_READ_TOKEN needs at least 32 ASCII characters')
    try:
        authority=Ed25519PublicKey.from_public_bytes(decode(Path(args.authority_public_key).read_text().strip()))
        directory=VerifiedDirectory(authority,args.group_id,args.audience,database=args.database)
    except (ValueError,OSError):
        parser.error('authority/group/database setup failed; see docs/admission-http.md')
    server=ThreadingHTTPServer(('127.0.0.1',args.port),handler(directory,token))
    print(f'Verified directory HTTP: http://127.0.0.1:{server.server_port}',flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        directory.close()


if __name__=='__main__':
    main()
