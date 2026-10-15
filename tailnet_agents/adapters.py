"""Reference Echo contract and explicit capability inspection; no product launchers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re

CONTRACT_ID = 'echo-v1'
MAX_TEXT_BYTES = 2048


def echo_contract():
    return {'version': 1, 'adapter_id': CONTRACT_ID, 'product': 'simulation', 'task_kind': 'echo',
            'permission': 'task.echo', 'input_max_bytes': MAX_TEXT_BYTES, 'output_max_bytes': MAX_TEXT_BYTES,
            'execution': 'synchronous', 'side_effects': 'none', 'restart': 'running-to-uncertain',
            'automatic_retry': False}


def validate_contract(value):
    expected = echo_contract()
    if (not isinstance(value, dict) or set(value) != set(expected) or
            any(type(value[name]) is not type(item) or value[name] != item for name, item in expected.items())):
        raise ValueError('unsupported adapter contract')
    return dict(value)


def contract_hash(value):
    validate_contract(value)
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


class EchoAdapter:
    def __call__(self, text):
        if not isinstance(text, str) or not 1 <= len(text.encode('utf-8')) <= MAX_TEXT_BYTES:
            raise ValueError('invalid Echo input')
        return text


def catalog():
    entries = [{'product': 'simulation', 'kind': 'synthetic_agent', 'implementation': 'echo_reference',
                'interface_validation': 'synthetic_only', 'contract': echo_contract(), 'contract_hash': contract_hash(echo_contract())}]
    for product in ('openclaw', 'codex', 'claude-code', 'qoder', 'grok-agent', 'grok-model-api'):
        entries.append({'product': product, 'kind': 'model_api' if product == 'grok-model-api' else 'product_agent',
                        'implementation': 'not_implemented', 'interface_validation': 'not_run', 'contract': None})
    return {'entries': entries, 'local_installation_scan': 'not_performed', 'product_execution': 'not_attempted'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('catalog', help='offline implementation inventory; does not inspect installed products')
    probe_parser = sub.add_parser('probe', help='explicit signed Echo metadata request; never submits a task')
    for name in ('url', 'authority-public-key', 'group-id', 'audience', 'executor-public-key'):
        probe_parser.add_argument('--' + name, required=True)
    probe_parser.add_argument('--ca-cert')
    probe_parser.add_argument('--token-env', default='TAILNET_VERIFIED_READ_TOKEN')
    args = parser.parse_args()
    if args.command == 'catalog':result = catalog()
    else:
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', args.token_env):parser.error('invalid read credential environment name')
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from .identity import decode
            from .adapter_probe import probe
        except ImportError:
            parser.exit(1, 'Signed adapter probing requires the identity extra; install tailnet-agents[identity].\n')
        from http.client import HTTPException
        try:
            owner = Ed25519PublicKey.from_public_bytes(decode(Path(args.authority_public_key).read_text().strip()))
            executor = Ed25519PublicKey.from_public_bytes(decode(Path(args.executor_public_key).read_text().strip()))
            result = probe(args.url, os.environ.get(args.token_env, ''), owner, args.group_id, args.audience,
                           executor, ca_file=args.ca_cert)
        except (ValueError, TypeError, KeyError, OSError, HTTPException):
            parser.exit(1, 'Adapter metadata probe failed; check explicit source, public pins, contract, clock, authorization and TLS. No task was submitted.\n')
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))


if __name__ == '__main__':main()
