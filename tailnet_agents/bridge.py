"""Automatic registry leases and a bounded, authenticated Echo task server.

The task API is custom v0.1, not an A2A implementation.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import logging
import os
import threading
import time
import uuid
from http.server import ThreadingHTTPServer

from .client import Client, validate_url
from .registry import Registry, make_handler

PROTOCOL = 'tailnet-task-v0.1'
LOG = logging.getLogger(__name__)


class TaskConflict(ValueError):
    pass


class TaskStore:
    def __init__(self, adapter, workers=2, capacity=256):
        self.adapter, self.capacity = adapter, capacity
        self.pool = ThreadPoolExecutor(max_workers=workers)
        self.lock = threading.Lock()
        self.tasks, self.keys = {}, {}

    def submit(self, owner, payload):
        key, message = payload.get('idempotency_key'), payload.get('message')
        if not isinstance(key, str) or not 1 <= len(key) <= 128:
            raise ValueError('idempotency_key must be 1..128 characters')
        if not isinstance(message, str) or not 1 <= len(message) <= 32768:
            raise ValueError('message must be 1..32768 characters')
        with self.lock:
            existing = self.keys.get((owner, key))
            if existing:
                if self.tasks[existing]['message'] != message:
                    raise TaskConflict('idempotency_key reused with a different message')
                return self.public(self.tasks[existing])
            # No eviction: preserve deduplication for this process lifetime.
            if len(self.tasks) >= self.capacity:
                raise OverflowError('task capacity reached; restart only after exporting results')
            task_id = uuid.uuid4().hex
            self.tasks[task_id] = {'id': task_id, 'owner': owner, 'message': message,
                                   'status': 'queued', 'result': None, 'error': None}
            self.keys[(owner, key)] = task_id
            result = self.public(self.tasks[task_id])
            self.pool.submit(self.run, task_id)
            return result

    def run(self, task_id):
        with self.lock:
            self.tasks[task_id]['status'] = 'running'
            message = self.tasks[task_id]['message']
        try:
            result = self.adapter(message)
            if not isinstance(result, str) or len(result) > 32768:
                raise ValueError('invalid adapter output')
            status, error = 'completed', None
        except Exception:
            result, status, error = None, 'failed', 'adapter failed'
        with self.lock:
            self.tasks[task_id].update(status=status, result=result, error=error)

    @staticmethod
    def public(task):
        return {key: task[key] for key in ('id', 'status', 'result', 'error')}

    def get(self, owner, task_id):
        with self.lock:
            task = self.tasks.get(task_id)
            if task is None or task['owner'] != owner:
                raise KeyError(task_id)
            return self.public(task)

    def close(self):
        self.pool.shutdown(wait=True)


def task_handler(credentials, store):
    class Handler(make_handler(Registry(credentials))):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def do_GET(self):
            if self.path == '/healthz':
                return self.respond(200, {'status': 'ok'})
            try:
                owner = self.owner()
                if not self.path.startswith('/v1/tasks/'):
                    return self.respond(404, {'error': 'not found'})
                self.respond(200, store.get(owner, self.path[len('/v1/tasks/'):]))
            except PermissionError:
                self.respond(403, {'error': 'invalid credential'})
            except KeyError:
                self.respond(404, {'error': 'task not found'})

        def do_POST(self):
            try:
                owner = self.owner()
                if self.path != '/v1/tasks':
                    return self.respond(404, {'error': 'not found'})
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 65536:
                    return self.respond(413, {'error': 'body must be 1..65536 bytes'})
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError('body must be an object')
                self.respond(202, store.submit(owner, payload))
            except PermissionError:
                self.respond(403, {'error': 'invalid credential'})
            except TaskConflict as exc:
                self.respond(409, {'error': str(exc)})
            except OverflowError as exc:
                self.respond(429, {'error': str(exc)})
            except (ValueError, UnicodeError) as exc:
                self.respond(400, {'error': str(exc)})
    return Handler


class Lease:
    def __init__(self, registry_client, record):
        self.client, self.record = registry_client, record
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def renew(self):
        return self.client.request('/v1/agents', self.record)

    def loop(self):
        delay = 1
        while not self.stop_event.is_set():
            try:
                self.renew()
                delay = self.record['ttl_seconds'] / 3
            except Exception as exc:
                # Do not log URLs, tokens, response bodies or agent prompts.
                LOG.warning('Registry renewal failed (%s); will retry', type(exc).__name__)
                delay = min(delay * 2, self.record['ttl_seconds'] / 3)
            self.stop_event.wait(delay)

    def start(self):
        self.thread.start()

    def close(self):
        self.stop_event.set()
        self.thread.join(timeout=self.client.timeout + 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--id', required=True)
    parser.add_argument('--registry', required=True)
    parser.add_argument('--advertise-url', required=True, help='HTTPS bridge origin via Tailscale Serve')
    parser.add_argument('--port', type=int, default=8766)
    parser.add_argument('--skill', action='append', default=[])
    args = parser.parse_args()
    try:
        parsed = validate_url(args.advertise_url)
        if parsed.scheme != 'https' or parsed.path not in ('', '/'):
            raise ValueError('advertise-url must be an HTTPS origin')
        registry = Client(args.registry, os.environ['TAILNET_REGISTRY_TOKEN'])
        credentials = json.loads(os.environ['TAILNET_PEER_TOKENS'])
        if (not isinstance(credentials, dict) or not credentials or
            any(not isinstance(k, str) or not k or not isinstance(v, str) or
                len(v) < 32 or not v.isascii() for k, v in credentials.items()) or
                len(set(credentials.values())) != len(credentials)):
            raise ValueError('peer tokens must be unique ASCII secrets of at least 32 characters')
    except (ValueError, KeyError) as exc:
        parser.error(str(exc))
    record = {'id': args.id, 'endpoint': args.advertise_url.rstrip('/'),
              'protocol': PROTOCOL, 'skills': args.skill or ['echo'], 'ttl_seconds': 60}
    # Validate before a lease thread starts; no local record is published.
    Registry({}).register('self', record)
    store = TaskStore(lambda message: message)
    server = ThreadingHTTPServer(('127.0.0.1', args.port), task_handler(credentials, store))
    lease = Lease(registry, record)
    lease.start()
    logging.basicConfig(level=logging.INFO)
    LOG.info('Echo bridge listening on loopback port %d', args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        lease.close()
        server.server_close()
        store.close()


if __name__ == '__main__':
    main()
