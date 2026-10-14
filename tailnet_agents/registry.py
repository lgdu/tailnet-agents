"""SQLite-backed registry. Bind to loopback behind Tailscale Serve."""
import argparse
import hmac
import json
import os
import re
import sqlite3
from pathlib import Path
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class Registry:
    def __init__(self, credentials, clock=time.time, database=":memory:"):
        self.credentials = credentials
        self.clock = clock
        self.lock = threading.Lock()
        if database != ":memory:":
            path = Path(database)
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(database, check_same_thread=False, timeout=10)
        if database != ":memory:":
            os.chmod(database, 0o600)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, owner TEXT NOT NULL, expires REAL NOT NULL, metadata TEXT NOT NULL)")
        # A restarted directory cannot attest that an old endpoint is still live.
        # Keep ownership and metadata, require each bridge to renew its lease.
        self.db.execute("UPDATE agents SET expires = 0")
        self.db.commit()

    def authenticate(self, token):
        for owner, secret in self.credentials.items():
            if hmac.compare_digest(token.encode(), secret.encode()):
                return owner
        raise PermissionError("invalid credential")

    @staticmethod
    def normalize_record(record):
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
        metadata = {"id": agent_id, "name": name, "endpoint": endpoint,
                    "protocol": protocol, "skills": skills, "ttl_seconds": ttl}
        return metadata

    def register(self, owner, record):
        metadata = self.normalize_record(record)
        agent_id, ttl = metadata["id"], metadata["ttl_seconds"]
        with self.lock, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            existing = self.db.execute("SELECT owner FROM agents WHERE id = ?", (agent_id,)).fetchone()
            if existing and existing[0] != owner:
                raise PermissionError("agent id belongs to another owner")
            self.db.execute("INSERT INTO agents(id, owner, expires, metadata) VALUES(?, ?, ?, ?) "
                            "ON CONFLICT(id) DO UPDATE SET expires=excluded.expires, metadata=excluded.metadata",
                            (agent_id, owner, self.clock() + ttl, json.dumps(metadata)))
        return {"id": agent_id, "ttl_seconds": ttl}

    def discover(self, skill=None):
        with self.lock:
            rows = self.db.execute("SELECT metadata FROM agents WHERE expires > ? ORDER BY id",
                                   (self.clock(),)).fetchall()
            records = [json.loads(row[0]) for row in rows]
            return [record for record in records if skill is None or skill in record["skills"]]

    def status(self):
        with self.lock:
            total, online = self.db.execute(
                "SELECT COUNT(*), COALESCE(SUM(expires > ?), 0) FROM agents", (self.clock(),)
            ).fetchone()
            return {"registered": total, "online": online, "stale": total - online}

    def deregister(self, owner, agent_id):
        with self.lock, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            existing = self.db.execute("SELECT owner FROM agents WHERE id = ?", (agent_id,)).fetchone()
            if existing is None or existing[0] != owner:
                raise KeyError(agent_id)
            # Explicit owner-authorized removal releases this ID for future reuse.
            self.db.execute("DELETE FROM agents WHERE id = ?", (agent_id,))
        return {"id": agent_id, "removed": True}

    def close(self):
        with self.lock:
            self.db.close()


def make_handler(registry):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

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
                if path.path == "/v1/status":
                    return self.respond(200, registry.status())
                if path.path != "/v1/agents":
                    return self.respond(404, {"error": "not found"})
                skill = parse_qs(path.query).get("skill", [None])[0]
                self.respond(200, {"agents": registry.discover(skill)})
            except PermissionError as exc:
                self.respond(403, {"error": str(exc)})

        def do_DELETE(self):
            try:
                owner = self.owner()
                prefix = "/v1/agents/"
                agent_id = self.path[len(prefix):] if self.path.startswith(prefix) else ""
                if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", agent_id):
                    return self.respond(404, {"error": "not found"})
                self.respond(200, registry.deregister(owner, agent_id))
            except PermissionError as exc:
                self.respond(403, {"error": str(exc)})
            except KeyError:
                self.respond(404, {"error": "agent not found"})

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
    parser.add_argument("--database", default="state/registry.sqlite3")
    args = parser.parse_args()
    credentials = json.loads(os.environ.get("TAILNET_AGENT_TOKENS", "{}"))
    if (not isinstance(credentials, dict) or not credentials
            or any(not isinstance(k, str) or not k or not isinstance(v, str)
                   or len(v) < 32 or not v.isascii() for k, v in credentials.items())
            or len(set(credentials.values())) != len(credentials)):
        parser.error("TAILNET_AGENT_TOKENS must map owners to unique ASCII tokens of at least 32 characters")
    registry = Registry(credentials, database=args.database)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(registry))
    print(f"Registry listening on {args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        registry.close()


if __name__ == "__main__":
    main()
