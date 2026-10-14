"""Discover agents and send tasks to explicitly allowed peer hosts."""
import argparse
import json
import os
import time
from urllib.parse import quote
from urllib.error import URLError
from .bridge import PROTOCOL
from .client import Client, validate_url


def select_peer(registry, agent_id, allowed_hosts):
    agents = registry.request('/v1/agents')['agents']
    matches = [a for a in agents if a['id'] == agent_id]
    if len(matches) != 1:
        raise ValueError('agent is offline or absent')
    agent = matches[0]
    parsed = validate_url(agent['endpoint'])
    if parsed.hostname not in allowed_hosts:
        raise ValueError('peer hostname is not explicitly allowed')
    if parsed.path not in ('', '/'):
        raise ValueError('peer endpoint must be an origin')
    if agent['protocol'] != PROTOCOL:
        raise ValueError('unsupported task protocol')
    return agent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--registry', required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    discover = commands.add_parser('discover')
    discover.add_argument('--skill')
    send = commands.add_parser('send')
    send.add_argument('--agent', required=True)
    send.add_argument('--allow-host', action='append', required=True)
    send.add_argument('--message', required=True)
    send.add_argument('--key', required=True, help='reuse this key for safe retries')
    send.add_argument('--wait', type=float, default=30)
    args = parser.parse_args()
    try:
        registry = Client(args.registry, os.environ['TAILNET_REGISTRY_TOKEN'])
        if args.command == 'discover':
            path = '/v1/agents' + ('?skill=' + quote(args.skill, safe='') if args.skill else '')
            print(json.dumps(registry.request(path), indent=2))
            return
        if not 0 <= args.wait <= 600:
            raise ValueError('wait must be 0..600 seconds')
        agent = select_peer(registry, args.agent, args.allow_host)
        peer = Client(agent['endpoint'], os.environ['TAILNET_REMOTE_TOKEN'])
        task = peer.request('/v1/tasks', {'message': args.message, 'idempotency_key': args.key})
        deadline = time.monotonic() + args.wait
        while task['status'] in ('queued', 'running') and time.monotonic() < deadline:
            time.sleep(min(0.2, max(0, deadline - time.monotonic())))
            task = peer.request('/v1/tasks/' + task['id'])
        print(json.dumps(task, indent=2))
        if task['status'] == 'failed':
            raise SystemExit(1)
    except (ValueError, KeyError, URLError) as exc:
        # HTTP error body and credential-bearing data are never printed.
        parser.exit(1, f'{type(exc).__name__}: request failed; check config and connectivity\n')


if __name__ == '__main__':
    main()
