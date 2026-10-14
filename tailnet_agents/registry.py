"""Small in-memory registry. Bind to loopback behind Tailscale Serve."""
import argparse
import hmac
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class Registry:
    def __init__(self, credentials, clock=time.monotonic):
        self.credentials = credentials
        self.clock = clock
        self.records = {}
        self.lock = threading.Lock()

    def authenticate(self, token):
        for owner, secret in self.credentials.items():
            if hmac.compare_digest(token, secret):
                return owner
        raise PermissionError("invalid credential")

    def register(self, owner, record):
        agent_id = record.get("id", "")
        if not isinstance(agent_id, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", agent_id):
            raise ValueError("invalid id")
        endpoint = record.get("endpoint", "")
        if not isinstance(endpoint, str):
            raise ValueError("invalid endpoint")
        parsed = urlparse(endpoint)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("endpoint must be an HTTPS URL without credentials")
        skills = record.get("skills", [])
        if not isinstance(skills, list) or len(skills) > 100 or any(
            not isinstance(s, str) or not 1 <= len(s) <= 128 for s in skills
        ):
            raise ValueError("invalid skills")
        ttl = record.get("ttl_seconds", 60)
        if type(ttl) is not int or not 10 <= ttl <= 300:
            raise ValueError("ttl_seconds must be between 10 and 300")
        name, protocol = record.get("name", agent_id), record.get("protocol", "custom")
        if any(not isinstance(s, str) or not 1 <= len(s) <= 128 for s in (name, protocol)):
            raise ValueError("invalid name or protocol")
        with self.lock:
            existing = self.records.get(agent_id)
            # Ownership survives expiry until restart; another node cannot take the ID.
            if existing and existing[0] != owner:
                raise PermissionError("agent id belongs to another owner")
            self.records[agent_id] = (owner, self.clock() + ttl, {
                "id": agent_id, "name": name, "endpoint": endpoint,
                "protocol": protocol, "skills": skills, "ttl_seconds": ttl,
            })
        return {"id": agent_id, "ttl_seconds": ttl}

    def discover(self, skill=None):
        with self.lock:
            return [dict(record) for _, expiry, record in self.records.values()
                    if expiry > self.clock() and (skill is None or skill in record["skills"])]


def make_handler(registry):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # Avoid logging credentials or request data.

        def respond(self, status, payload):
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def owner(self):
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                raise PermissionError("bearer token required")
            return registry.authenticate(auth[7:])

        def do_GET(self):
            path = urlparse(self.path)
            if path.path == "/healthz":
                return self.respond(200, {"status": "ok"})
            try:
                self.owner()
                if path.path != "/v1/agents":
                    return self.respond(404, {"error": "not found"})
                skill = parse_qs(path.query).get("skill", [None])[0]
                self.respond(200, {"agents": registry.discover(skill)})
            except PermissionError as exc:
                self.respond(403, {"error": str(exc)})

        def do_POST(self):
            try:
                owner = self.owner()
                if self.path != "/v1/agents":
                    return self.respond(404, {"error": "not found"})
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 65536:
                    return self.respond(413, {"error": "body must be 1..65536 bytes"})
                record = json.loads(self.rfile.read(length))
                if not isinstance(record, dict):
                    raise ValueError("body must be an object")
                self.respond(200, registry.register(owner, record))
            except PermissionError as exc:
                self.respond(403, {"error": str(exc)})
            except (ValueError, UnicodeError) as exc:
                self.respond(400, {"error": str(exc)})
    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    credentials = json.loads(os.environ.get("TAILNET_AGENT_TOKENS", "{}"))
    if (not isinstance(credentials, dict) or not credentials
            or any(not isinstance(k, str) or not k or not isinstance(v, str)
                   or len(v) < 32 or not v.isascii() for k, v in credentials.items())
            or len(set(credentials.values())) != len(credentials)):
        parser.error("TAILNET_AGENT_TOKENS must map owners to unique ASCII tokens of at least 32 characters")
    server = ThreadingHTTPServer((args.host, args.port), make_handler(Registry(credentials)))
    print(f"Registry listening on {args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
