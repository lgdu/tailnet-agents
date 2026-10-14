"""TLS-capable HTTP transport for the optional verified directory."""
import argparse
import hmac
import json
import os
import ipaddress
import re
import ssl
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs,urlparse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .identity import AdmissionError,decode,load_identity
from .verified_directory import VerifiedDirectory
from .client import Client
from .policy_sync import PolicySynchronizer,load_policy_sources
from .discovery import DISCOVERY_PORT,LanBroadcaster,lan_config,origin


def handler(directory,read_token,allowed_hosts=None,scheme="http",synchronizer=None,discovery=None):
    allowed_hosts=allowed_hosts or ("127.0.0.1","localhost")
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
            host=self.headers.get('Host','').lower()
            allowed={f'{name.lower()}:{self.server.server_port}' for name in allowed_hosts}
            origin=self.headers.get('Origin')
            if host not in allowed or (origin and origin!=scheme+'://'+host):
                raise PermissionError('allowed host/origin required')

        def read_auth(self):
            auth=self.headers.get('Authorization','')
            if not auth.startswith('Bearer ') or not hmac.compare_digest(auth[7:].encode(),read_token.encode()):
                raise PermissionError('directory read credential required')

        def do_GET(self):
            try:
                self.local()
                parsed=urlparse(self.path)
                if parsed.path=='/healthz':
                    return self.respond(200,{'status':'ok','mode':'verified-'+scheme})
                if parsed.path=='/v1/discovery':
                    if discovery is None:
                        return self.respond(404,{'error':'not found'})
                    if parsed.query:
                        raise ValueError('discovery route does not accept query parameters')
                    try:
                        return self.respond(200,{'announcement':discovery()})
                    except AdmissionError:
                        return self.respond(503,{'error':'discovery announcement unavailable'})
                if parsed.path=='/v1/revocations':
                    self.read_auth()
                    query=parse_qs(parsed.query,keep_blank_values=True)
                    if set(query)-{'after','limit'} or any(len(v)!=1 for v in query.values()):
                        raise ValueError('invalid revocation query')
                    return self.respond(200,directory.export_revocations(int(query.get('after',['0'])[0]),int(query.get('limit',['100'])[0])))
                if parsed.path in ('/v1/policies','/v1/policy-sync'):
                    self.read_auth()
                    if parsed.query:
                        raise ValueError('policy routes do not accept query parameters')
                    if parsed.path=='/v1/policies':
                        return self.respond(200,directory.export_policy())
                    status={'state':'disabled'} if synchronizer is None else synchronizer.status()
                    return self.respond(200,status|{'policy':directory.policy_status()})
                if parsed.path!='/v1/agents':
                    return self.respond(404,{'error':'not found'})
                self.read_auth()
                query=parse_qs(parsed.query,keep_blank_values=True)
                if set(query)-{'skill'} or any(len(v)!=1 for v in query.values()):
                    raise ValueError('invalid discovery query')
                self.respond(200,{'agents':directory.discover(query.get('skill',[None])[0])})
            except (PermissionError,AdmissionError):
                self.respond(403,{'error':'request not authorized'})
            except ValueError:
                self.respond(400,{'error':'invalid request'})

        def do_POST(self):
            try:
                self.local()
                if self.path not in ('/v1/challenges','/v1/registrations','/v1/revocations','/v1/policies'):
                    return self.respond(404,{'error':'not found'})
                if self.path in ('/v1/revocations','/v1/policies'):
                    self.read_auth()
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=65536:
                    return self.respond(413,{'error':'body must be 1..65536 bytes'})
                payload=json.loads(self.rfile.read(size))
                if not isinstance(payload,dict):
                    raise ValueError('object required')
                if self.path=='/v1/policies':
                    if set(payload)!={'policy'}:
                        raise ValueError('invalid policy fields')
                    return self.respond(200,directory.apply_policy(payload['policy']))
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


class AdmissionHTTPServer(ThreadingHTTPServer):
    def __init__(self,address,request_handler,tls_context=None):
        self.tls_context=tls_context
        super().__init__(address,request_handler)

    def get_request(self):
        connection,address=super().get_request()
        if self.tls_context is not None:
            connection.settimeout(5)
            try:
                connection=self.tls_context.wrap_socket(connection,server_side=True)
            except Exception:
                connection.close()
                raise
        return connection,address


def transport_config(host,cert_file=None,key_file=None,allowed_hosts=None):
    try:
        address=ipaddress.ip_address(host)
        if address.version!=4:
            raise ValueError('this prototype binds IPv4 only')
        loopback=address.is_loopback
    except ValueError:
        if host!='localhost':
            # Hostnames are not resolved here; arbitrary hostname binds are unsupported.
            raise ValueError('bind host must be an IPv4 address or localhost')
        loopback=True
    if bool(cert_file)!=bool(key_file):
        raise ValueError('both TLS certificate and key are required')
    if not loopback and (not cert_file or not allowed_hosts):
        raise ValueError('non-loopback requires TLS and explicit allowed hosts')
    names=tuple(allowed_hosts or ('127.0.0.1','localhost'))
    if any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}',name) or name in ('0.0.0.0',) for name in names):
        raise ValueError('allowed hosts must be explicit DNS names or IPv4 addresses, without ports')
    context=None
    if cert_file:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert_file,key_file)
    return names,context


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--authority-public-key',required=True,help='file containing raw Ed25519 public key in base64url')
    parser.add_argument('--group-id',required=True,help='existing human-created group ID')
    parser.add_argument('--audience',required=True,help='trusted verifier identity agreed out of band')
    parser.add_argument('--port',type=int,default=8771)
    parser.add_argument('--host',default='127.0.0.1')
    parser.add_argument('--tls-cert')
    parser.add_argument('--tls-key')
    parser.add_argument('--allow-host',action='append',help='explicit DNS hostname or IPv4 address without port')
    parser.add_argument('--database',default='state/verified-directory.sqlite3')
    parser.add_argument('--require-policy',action='store_true',help='fail closed without an active signed member policy; persisted across restart')
    parser.add_argument('--policy-file',help='initial signed policy; implies --require-policy')
    sources=parser.add_mutually_exclusive_group()
    sources.add_argument('--policy-peer',help='explicit source directory URL; requires policy mode and TAILNET_POLICY_PEER_TOKEN')
    sources.add_argument('--policy-sources-file',help='ordered JSON array of 1..8 sources: url, token_env and optional ca_cert')
    parser.add_argument('--policy-peer-ca',help='trusted CA certificate PEM for the configured source')
    parser.add_argument('--policy-sync-interval',type=float,default=10,help='policy pull interval, 1..3600 seconds')
    parser.add_argument('--policy-max-age',type=int,help='maximum signed policy age, 1..86400 seconds; default 300 or persisted limit')
    parser.add_argument('--discovery-agent-key',help='existing approved synthetic identity PEM; never an owner key')
    parser.add_argument('--discovery-endpoint',help='explicit advertised directory origin; enables credential-free /v1/discovery')
    parser.add_argument('--discovery-lan-interface',help='opt-in multicast on one explicit local IPv4 interface address')
    parser.add_argument('--discovery-lan-port',type=int,default=DISCOVERY_PORT)
    args=parser.parse_args()
    token=os.environ.get('TAILNET_VERIFIED_READ_TOKEN','')
    if len(token)<32 or not token.isascii():
        parser.error('TAILNET_VERIFIED_READ_TOKEN needs at least 32 ASCII characters')
    peer_token=os.environ.get('TAILNET_POLICY_PEER_TOKEN','')
    if args.policy_peer and (not (args.require_policy or args.policy_file) or len(peer_token)<32 or not peer_token.isascii()):
        parser.error('policy peer requires policy mode and a 32+ character ASCII peer read token')
    if args.policy_peer_ca and not args.policy_peer:
        parser.error('--policy-peer-ca requires --policy-peer')
    if (args.policy_sources_file or args.policy_max_age is not None) and not (args.require_policy or args.policy_file):
        parser.error('policy sources and maximum age require policy mode')
    if bool(args.discovery_agent_key)!=bool(args.discovery_endpoint):
        parser.error('discovery requires both an existing identity key and explicit endpoint')
    if args.discovery_agent_key and not (args.require_policy or args.policy_file):
        parser.error('discovery requires signed policy mode')
    if args.discovery_lan_interface and not args.discovery_agent_key:
        parser.error('LAN announcements require explicit discovery identity/endpoint')
    directory=None
    synchronizer=None
    broadcaster=None
    server=None
    try:
        discovery_key=load_identity(args.discovery_agent_key) if args.discovery_agent_key else None
        if args.discovery_endpoint:
            args.discovery_endpoint=origin(args.discovery_endpoint)
        if args.discovery_lan_interface:
            lan_config(args.discovery_lan_interface,args.discovery_lan_port)
        allowed,context=transport_config(args.host,args.tls_cert,args.tls_key,args.allow_host)
        authority=Ed25519PublicKey.from_public_bytes(decode(Path(args.authority_public_key).read_text().strip()))
        peers=[]
        if args.policy_sources_file:
            peers=load_policy_sources(args.policy_sources_file)
        elif args.policy_peer:
            peers=[Client(args.policy_peer,peer_token,ca_file=args.policy_peer_ca)]
        directory=VerifiedDirectory(authority,args.group_id,args.audience,database=args.database,require_policy=args.require_policy or bool(args.policy_file),policy_max_age=args.policy_max_age)
        if args.policy_file:
            directory.apply_policy(Path(args.policy_file).read_text().strip())
        if peers:
            synchronizer=PolicySynchronizer(directory,peers[0],args.policy_sync_interval,fallback_clients=peers[1:])
        discovery=None if discovery_key is None else lambda: directory.discovery_announcement(discovery_key,args.discovery_endpoint,args.audience)
        if args.discovery_lan_interface:
            broadcaster=LanBroadcaster(discovery,args.discovery_lan_interface,args.discovery_lan_port)
        scheme='https' if context else 'http'
        server=AdmissionHTTPServer((args.host,args.port),handler(directory,token,allowed,scheme,synchronizer,discovery),context)
    except (ValueError,OSError):
        if broadcaster is not None:
            broadcaster.stop()
        if server is not None:
            server.server_close()
        if directory is not None:
            directory.close()
        parser.error('authority/group/database setup failed; see docs/admission-http.md')
    print(f'Verified directory: {scheme}://{allowed[0]}:{server.server_port}',flush=True)
    try:
        if synchronizer is not None:
            synchronizer.start()
        if broadcaster is not None:
            broadcaster.start()
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if broadcaster is not None:
            broadcaster.stop()
        if synchronizer is not None:
            synchronizer.stop()
        directory.close()


if __name__=='__main__':
    main()
