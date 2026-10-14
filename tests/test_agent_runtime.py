import json
import os
from pathlib import Path
import selectors
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from urllib.error import HTTPError
import test_discovery as fixtures

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tailnet_agents.agent_runtime import AgentRuntime, RuntimeState
    from tailnet_agents.identity import (AdmissionError, encode, generate_identity, identity_id,
        issue_grant, prove_possession, public_bytes, sign, verify_grant)
    from tailnet_agents.presence import (MAX_COUNTER, PRESENCE_TYPE, canonical_record, make_presence,
                                        read_presence, verify_presence)
    from tailnet_agents.verified_client import VerifiedClient
    from tailnet_agents.verified_directory import VerifiedDirectory, issue_revocation
    from tailnet_agents.client import Client
    from tailnet_agents.group_policy import revise_policy
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@unittest.skipUnless(HAS_CRYPTO, 'install identity extra')
class AgentRuntimeTests(unittest.TestCase):
    directory = fixtures.DiscoveryFixture.directory
    serve = fixtures.DiscoveryFixture.serve

    def setUp(self):
        fixtures.DiscoveryFixture.setUp(self)
        self.node = self.directory()
        self.url = self.serve(self.node, enabled=False)
        self.record = {'name': 'Same host', 'endpoint': 'https://same-host.example:8901', 'ttl_seconds': 30}

    def runtime(self, name='runtime', **changes):
        options = {'url': self.url, 'key': self.agent, 'owner': self.owner.public_key(), 'grant': self.grant,
                   'group_id': self.group, 'audience': self.audience, 'state_path': self.root/(name+'.sqlite3'),
                   'record': self.record, 'clock': lambda: self.now}
        runtime = AgentRuntime(**(options | changes))
        self.addCleanup(runtime.close)
        return runtime

    def observation(self, node=None):
        return (node or self.node).presence_status()['entries']

    def presence(self, *, sequence=1, generation=1, boot_id='a'*32, **options):
        return make_presence(self.agent, self.owner.public_key(), self.group, self.record,
                             generation, boot_id, sequence, now=self.now, **options)

    def client(self, **options):
        return VerifiedClient(self.url, self.agent, self.grant, self.audience, **options)

    def rejected(self, status, call):
        with self.assertRaises(HTTPError) as caught: call()
        self.assertEqual(caught.exception.code, status)
        caught.exception.close()

    def approve_second(self):
        key = generate_identity(self.root/'second.pem')
        grant = issue_grant(self.owner, key.public_key(), self.group, ['join'], now=int(self.now))
        credential = verify_grant(grant, self.owner.public_key(), self.group, now=self.now)['jti']
        members = self.members | {identity_id(key.public_key()): {'permissions': ['join'], 'grant_ids': [credential]}}
        self.node.apply_policy(revise_policy(self.owner, self.policy, members, now=int(self.now)))
        return key, grant

    def test_constructing_runtime_restores_config_without_network_or_group_mutation(self):
        before = self.node.export_policy()
        runtime = self.runtime()
        with patch.object(runtime.client.client, 'request') as contacted:
            self.assertEqual(runtime.subject, self.subject)
            self.assertEqual(runtime.group_id, self.group)
            self.assertEqual(runtime.state.generation, 1)
            self.assertEqual(runtime.state.sequence, 0)
            contacted.assert_not_called()
        self.assertEqual(self.node.export_policy(), before)
        self.assertEqual(self.observation(), [])

    def test_signed_heartbeat_registers_and_authenticated_reader_verifies_snapshot(self):
        runtime = self.runtime()
        before, original_key = self.node.export_policy(), self.agent_path.read_bytes()
        result = runtime.step()
        self.assertEqual(result['state'], 'registered')
        self.assertEqual(result['sequence'], 1)
        page = read_presence(Client(self.url, 'r'*32), self.owner.public_key(), self.group, now=self.now)
        self.assertEqual(page['entries'][0]['state'], 'online')
        self.assertEqual(page['entries'][0]['subject'], self.subject)
        self.assertEqual(result['expires_at'], 140)
        self.assertEqual(len(self.node.discover()), 1)
        self.assertEqual(self.node.export_policy(), before)
        self.assertEqual(self.agent_path.read_bytes(), original_key)

    def test_signed_claim_schema_owner_group_subject_and_record_are_verified(self):
        token = self.presence()
        claims = verify_presence(token, self.agent.public_key(), self.owner.public_key(), self.group, self.record)
        invalid = [{'group_id': 'foreign'}, {'owner': 'other'}, {'subject': 'ed25519:'+'0'*64},
                   {'record_hash': '0'*64}, {'version': True}, {'generation': True}, {'generation': 0},
                   {'sequence': MAX_COUNTER+1}, {'sequence': 0}, {'boot_id': 'bad'}, {'state': 'approved'},
                   {'issued_at': True}, {'issued_at': 116, 'expires_at': 140}, {'expires_at': 110},
                   {'expires_at': 141}, {'extra': 'field'}]
        for change in invalid:
            changed = sign(self.agent, claims | change, PRESENCE_TYPE)
            self.rejected(403, lambda: self.client().register(self.record, presence=changed))
        foreign = Ed25519PrivateKey.generate()
        self.rejected(403, lambda: self.client().register(self.record, presence=sign(foreign, claims, PRESENCE_TYPE)))
        self.assertEqual(self.observation(), [])
        self.rejected(400, lambda: Client(self.url, '').request('/v1/challenges', {'record': self.record, 'presence': None}))

    def test_receiver_transaction_failure_preserves_previous_lease_and_signed_observation(self):
        runtime = self.runtime()
        runtime.step()
        before = self.observation()
        lease = self.node.discover()
        self.now += 1
        record = runtime.record | {'name': 'Changed metadata'}
        token = make_presence(self.agent, self.owner.public_key(), self.group, record, runtime.state.generation,
                              runtime.state.boot_id, 2, now=self.now)
        challenge = self.node.challenge(record, token)
        proof = prove_possession(self.agent, self.grant, challenge['nonce'], self.audience, context=challenge['context'])
        with self.node._registry.db:
            self.node._registry.db.execute("CREATE TRIGGER fail_presence BEFORE INSERT ON agent_presence BEGIN SELECT RAISE(ABORT,'test failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.node.register(self.grant, self.agent.public_key(), proof, challenge['nonce'], record, token)
        self.assertEqual(self.observation(), before)
        self.assertEqual(self.node.discover(), lease)

    def test_presence_and_metadata_are_bound_into_fresh_possession_challenge(self):
        token, changed = self.presence(), self.presence(sequence=2)
        challenge = self.node.challenge(self.record, token)
        proof = prove_possession(self.agent, self.grant, challenge['nonce'], self.audience, context=challenge['context'])
        with self.assertRaises(AdmissionError):
            self.node.register(self.grant, self.agent.public_key(), proof, challenge['nonce'], self.record, changed)
        with self.assertRaises(AdmissionError):
            self.node.register(self.grant, self.agent.public_key(), proof, challenge['nonce'], self.record | {'endpoint': 'https://other.example'}, token)
        self.node.register(self.grant, self.agent.public_key(), proof, challenge['nonce'], self.record, token)
        with self.assertRaises(AdmissionError):
            self.node.register(self.grant, self.agent.public_key(), proof, challenge['nonce'], self.record, token)

    def test_replaying_signed_sequence_with_new_proof_does_not_extend_lease(self):
        token = self.presence()
        self.client().register(self.record, presence=token)
        before = self.observation()
        self.now += 1
        self.rejected(409, lambda: self.client().register(self.record, presence=token))
        self.assertEqual(self.observation(), before)

    def test_restart_retains_identity_group_and_fences_old_boot_even_with_higher_sequence(self):
        first = self.runtime()
        first.step()
        old_boot = first.state.boot_id
        first.close()
        second = self.runtime()
        self.assertEqual(second.state.generation, 2)
        self.assertNotEqual(second.state.boot_id, old_boot)
        self.assertEqual(second.step()['state'], 'registered')
        old = self.presence(generation=1, boot_id=old_boot, sequence=999)
        self.rejected(409, lambda: self.client().register(self.record, presence=old))
        claims = verify_presence(self.observation()[0]['presence'], self.agent.public_key(), self.owner.public_key(), self.group, canonical_record(second.record))
        self.assertEqual(claims['generation'], 2)
        self.assertEqual(second.subject, self.subject)
        self.assertEqual(second.group_id, self.group)

    def test_same_generation_conflicting_boot_does_not_replace_incumbent_or_other_agent(self):
        key, grant = self.approve_second()
        first = self.runtime()
        other = self.runtime('other', key=key, grant=grant, record=self.record | {'endpoint': 'https://same-host.example:8902'})
        self.assertEqual(first.step()['state'], 'registered')
        self.assertEqual(other.step()['state'], 'registered')
        conflict = make_presence(self.agent, self.owner.public_key(), self.group, first.record, 1, 'f'*32, 999, now=self.now)
        self.rejected(409, lambda: self.client().register(first.record, presence=conflict))
        self.assertEqual(len(self.node.discover()), 2)
        self.assertEqual(first.step()['state'], 'registered')
        self.assertEqual(other.step()['state'], 'registered')

    def test_signed_presence_identity_cannot_downgrade_to_legacy_registration(self):
        self.client().register(self.record)
        runtime = self.runtime()
        self.assertEqual(runtime.step()['state'], 'registered')
        self.rejected(403, lambda: self.client().register(self.record))
        self.assertEqual(runtime.step()['state'], 'registered')

    def test_directory_restart_preserves_versions_but_requires_fresh_live_registration(self):
        path = str(self.root/'directory.sqlite3')
        node = VerifiedDirectory(self.owner.public_key(), self.group, self.audience, database=path, require_policy=True, clock=lambda: self.now)
        try:
            node.apply_policy(self.policy)
            url = self.serve(node, enabled=False)
            first = self.runtime(url=url)
            first.step(); first.close()
            original = node.presence_status()['entries'][0]['presence']
        finally:
            node.close()
        restored = VerifiedDirectory(self.owner.public_key(), self.group, self.audience, database=path, require_policy=True, clock=lambda: self.now)
        try:
            self.assertEqual(restored.presence_status()['entries'][0]['state'], 'expired')
            self.assertEqual(restored.discover(), [])
            new_url = self.serve(restored, enabled=False)
            old_client = VerifiedClient(new_url, self.agent, self.grant, self.audience)
            self.rejected(409, lambda: old_client.register(first.record, presence=original))
            self.rejected(403, lambda: old_client.register(first.record))
            second = self.runtime(url=new_url)
            self.assertEqual(second.step()['state'], 'registered')
            self.assertEqual(restored.export_policy()['policy'], self.policy)
        finally:
            restored.close()

    def test_removal_dissolution_and_revocation_hide_presence_and_deny_renewal(self):
        for action in ('remove', 'dissolve', 'revoke'):
            with self.subTest(action=action):
                node = self.directory()
                runtime = self.runtime(action, url=self.serve(node, enabled=False))
                self.assertEqual(runtime.step()['state'], 'registered')
                if action == 'revoke': node.revoke(issue_revocation(self.owner, self.group, self.jti))
                else: node.apply_policy(revise_policy(self.owner, self.policy, {}, dissolve=action=='dissolve', now=110))
                self.assertEqual(self.observation(node)[0]['state'], 'unauthorized')
                self.assertEqual(node.discover(), [])
                self.assertEqual(runtime.step()['state'], 'waiting_authorization')
                self.assertEqual(runtime.group_id, self.group)

    def test_policy_age_caps_presence_and_expiry_never_renews_authority(self):
        runtime = self.runtime()
        self.now = 390
        result = runtime.step()
        self.assertEqual(result['state'], 'registered')
        self.assertEqual(result['expires_at'], 401)
        self.assertEqual(result['lease_seconds'], 11)
        self.now = 401
        self.assertEqual(runtime.step()['state'], 'waiting_authorization')
        self.assertEqual(self.observation()[0]['state'], 'unauthorized')
        self.assertEqual(self.node.export_policy()['policy'], self.policy)

    def test_local_grant_expiry_stops_network_heartbeats_without_replacing_identity(self):
        grant = issue_grant(self.owner, self.agent.public_key(), self.group, ['join'], now=100, lifetime=20)
        credential = verify_grant(grant, self.owner.public_key(), self.group, now=self.now)['jti']
        self.node.apply_policy(revise_policy(self.owner, self.policy, {self.subject: {'permissions': ['join'], 'grant_ids': [credential]}}, now=110))
        runtime = self.runtime(grant=grant)
        self.assertEqual(runtime.step()['expires_at'], 120)
        self.now = 120
        with patch.object(runtime.client.client, 'request') as contacted:
            self.assertEqual(runtime.step()['state'], 'waiting_authorization')
            contacted.assert_not_called()
        self.assertEqual(runtime.subject, self.subject)

    def test_explicit_offline_preserves_membership_and_later_heartbeat_can_resume(self):
        runtime = self.runtime()
        runtime.step()
        self.assertEqual(runtime.step(offline=True)['state'], 'offline')
        self.assertEqual(self.observation()[0]['state'], 'offline')
        self.assertEqual(self.node.discover(), [])
        self.assertEqual(self.node.export_policy()['policy'], self.policy)
        self.assertEqual(runtime.step()['state'], 'registered')

    def test_crashed_runtime_becomes_expired_without_destroying_identity_or_group(self):
        runtime = self.runtime()
        runtime.step()
        self.now += 30
        self.assertEqual(self.observation()[0]['state'], 'expired')
        self.assertEqual(self.node.discover(), [])
        self.assertEqual(runtime.step()['state'], 'registered')
        self.assertEqual(runtime.state.generation, 1)

    def test_malformed_ack_never_claims_registered_or_changes_saved_identity(self):
        runtime = self.runtime()
        for response in ({'id': 'legacy', 'ttl_seconds': 30}, None,
                         {'id': 'agent-'+self.subject.split(':')[1], 'ttl_seconds': 30, 'presence': {}}):
            with patch.object(runtime.client, 'register', return_value=response):
                self.assertEqual(runtime.step()['state'], 'waiting')
        self.assertEqual(runtime.subject, self.subject)
        self.assertEqual(self.observation(), [])
        for change in ({'generation': True}, {'sequence': 1.0}, {'expires_at': float('nan')}, {'expires_at': 999999}, {'state': 'offline'}):
            def malformed(record, *, presence, guard):
                claims = verify_presence(presence, self.agent.public_key(), self.owner.public_key(), self.group, record)
                observed = {field: claims[field] for field in ('generation', 'boot_id', 'sequence', 'state', 'expires_at')}
                if 'sequence' in change: change['sequence'] = float(claims['sequence'])
                return {'id': 'agent-'+self.subject.split(':')[1], 'ttl_seconds': 30, 'presence': observed | change}
            with patch.object(runtime.client, 'register', side_effect=malformed):
                self.assertEqual(runtime.step()['state'], 'waiting')

    def test_clock_rollback_does_not_show_future_signed_presence_as_online(self):
        runtime = self.runtime()
        self.now = 130
        self.assertEqual(runtime.step()['state'], 'registered')
        self.now = 120
        self.assertEqual(self.observation()[0]['state'], 'expired')
        self.assertEqual(self.node.discover(), [])

    def test_lost_ack_recovers_with_new_counter_and_fresh_proof_not_new_grant(self):
        runtime = self.runtime()
        original = runtime.client.register
        def lose(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError('private transport detail')
        with patch.object(runtime.client, 'register', side_effect=lose):
            self.assertEqual(runtime.step()['state'], 'waiting')
        self.assertEqual(self.observation()[0]['state'], 'online')
        self.assertEqual(runtime.step()['sequence'], 2)
        self.assertEqual(self.node.export_policy()['policy'], self.policy)

    def test_counter_commits_before_network_failure_and_restart_advances_generation(self):
        runtime = self.runtime()
        with patch.object(runtime.state, 'next_sequence', side_effect=sqlite3.OperationalError('disk failure')):
            with patch.object(runtime.client.client, 'request') as contacted:
                self.assertEqual(runtime.step()['state'], 'waiting')
                contacted.assert_not_called()
        self.assertEqual(runtime.state.sequence, 0)
        with patch.object(runtime.client.client, 'request', side_effect=OSError('offline')):
            self.assertEqual(runtime.step()['state'], 'waiting')
        self.assertEqual(runtime.state.db.execute('SELECT sequence FROM runtime_context').fetchone(), (1,))
        runtime.close()
        restored = self.runtime()
        self.assertEqual(restored.state.generation, 2)
        self.assertEqual(restored.step()['state'], 'registered')

    def test_stop_during_challenge_prevents_late_online_post(self):
        runtime = self.runtime()
        original, calls = runtime.client.client.request, []
        def stop(path, *args, **kwargs):
            calls.append(path)
            response = original(path, *args, **kwargs)
            runtime.stop.set()
            return response
        with patch.object(runtime.client.client, 'request', side_effect=stop):
            self.assertEqual(runtime.step()['state'], 'stopped')
        self.assertEqual(calls, ['/v1/challenges'])
        self.assertEqual(self.observation(), [])

    def test_run_stops_idle_wait_and_sends_best_effort_signed_offline(self):
        runtime = self.runtime()
        emitted = []
        def emit(result):
            emitted.append(result)
            runtime.stop.set()
        runtime.run(emit)
        self.assertEqual([result['state'] for result in emitted], ['registered', 'offline'])
        self.assertEqual(self.observation()[0]['state'], 'offline')

    def test_wrong_saved_key_owner_or_group_fails_before_state_creation(self):
        changes = [{'key': Ed25519PrivateKey.generate()}, {'owner': Ed25519PrivateKey.generate().public_key()}, {'group_id': 'foreign'}]
        for index, change in enumerate(changes):
            with self.assertRaises(ValueError): self.runtime(str(index), **change)
            self.assertFalse((self.root/(str(index)+'.sqlite3')).exists())

    def test_expired_saved_grant_restores_original_context_and_waits_without_network(self):
        grant = issue_grant(self.owner, self.agent.public_key(), self.group, ['join'], now=0, lifetime=60)
        runtime = self.runtime(grant=grant)
        with patch.object(runtime.client.client, 'request') as contacted:
            self.assertEqual(runtime.step()['state'], 'waiting_authorization')
            contacted.assert_not_called()
        self.assertEqual(runtime.subject, self.subject)
        self.assertEqual(runtime.group_id, self.group)

    def test_runtime_config_rejects_unsafe_origins_intervals_and_presence_record_extras(self):
        for changes in ({'url': 'http://192.168.1.2'}, {'url': self.url+'/path'}, {'interval': 0}, {'interval': float('nan')},
                        {'interval': 30}, {'record': self.record | {'id': 'caller-selected'}},
                        {'record': self.record | {'endpoint': 'https://host.example?token=secret'}},
                        {'record': self.record | {'skills': ['x'*100]*100}}):
            with self.assertRaises(ValueError): self.runtime(**changes)

    def test_state_file_exclusive_lock_prevents_two_process_instances_sharing_state(self):
        runtime = self.runtime()
        with self.assertRaises(BlockingIOError): self.runtime()
        self.assertEqual(runtime.state.generation, 1)
        self.assertEqual(runtime.step()['state'], 'registered')
        runtime.close()
        self.assertEqual(runtime.step()['state'], 'stopped')
        self.assertEqual(self.runtime().state.generation, 2)

    def test_persisted_context_cannot_change_subject_owner_or_group(self):
        runtime = self.runtime()
        runtime.close()
        path = self.root/'runtime.sqlite3'
        expected = (identity_id(self.owner.public_key()), self.subject, self.group)
        for changes in [('other', self.subject, self.group), (expected[0], 'other', self.group), (expected[0], self.subject, 'other')]:
            with self.assertRaises(AdmissionError): RuntimeState(path, *changes)
        restored = self.runtime()
        self.assertEqual(restored.state.generation, 2)
        self.assertEqual(restored.state.db.execute('SELECT owner,subject,group_id FROM runtime_context').fetchone(), expected)

    def test_state_symlink_and_public_permissions_fail_closed(self):
        path, link = self.root/'state.sqlite3', self.root/'link.sqlite3'
        path.write_bytes(b''); path.chmod(0o644)
        with self.assertRaises(ValueError): RuntimeState(path, 'owner', self.subject, self.group)
        link.symlink_to(path)
        with self.assertRaises(OSError): RuntimeState(link, 'owner', self.subject, self.group)
        self.assertEqual(path.read_bytes(), b'')
        fifo = self.root/'fifo'
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(ValueError): RuntimeState(fifo, 'owner', self.subject, self.group)

    def test_generation_and_sequence_overflow_never_reset_counters(self):
        runtime = self.runtime()
        runtime.state.sequence = MAX_COUNTER
        with self.assertRaises(ValueError): runtime.state.next_sequence()
        with runtime.state.db: runtime.state.db.execute('UPDATE runtime_context SET generation=?', (MAX_COUNTER,))
        runtime.close()
        with self.assertRaises(ValueError): self.runtime()

    def test_presence_read_requires_token_and_pages_without_merging_same_host_agents(self):
        key, grant = self.approve_second()
        self.runtime().step()
        self.runtime('second', key=key, grant=grant, record=self.record | {'endpoint': 'https://same-host.example:8902'}).step()
        reader = Client(self.url, 'r'*32)
        first = reader.request('/v1/presence?limit=1')
        second = reader.request('/v1/presence?limit=1&after='+first['next_after'])
        self.assertTrue(first['has_more']); self.assertFalse(second['has_more'])
        self.assertNotEqual(first['entries'][0]['subject'], second['entries'][0]['subject'])
        self.rejected(403, lambda: Client(self.url, 'wrong').request('/v1/presence'))
        for query in ('limit=21', 'limit=0', 'limit=true', 'after=bad', 'extra=1', 'limit=1&limit=2'):
            self.rejected(400, lambda: reader.request('/v1/presence?'+query))

    def test_reader_rejects_substitution_and_conservatively_expires_old_observation(self):
        self.runtime().step()
        reader = Client(self.url, 'r'*32)
        response = reader.request('/v1/presence')
        with patch.object(reader, 'request', return_value=response):
            self.assertEqual(read_presence(reader, self.owner.public_key(), self.group, now=140)['entries'][0]['state'], 'expired')
        for bad in (response | {'group_id': 'foreign'}, response | {'owner': 'foreign'}):
            with patch.object(reader, 'request', return_value=bad), self.assertRaises(ValueError):
                read_presence(reader, self.owner.public_key(), self.group, now=self.now)
        response = reader.request('/v1/presence')
        response['entries'][0]['record']['endpoint'] = 'https://other.example'
        with patch.object(reader, 'request', return_value=response), self.assertRaises(ValueError):
            read_presence(reader, self.owner.public_key(), self.group, now=self.now)

    def test_runtime_checks_tls_ca_and_hostname_before_reporting_success(self):
        paths = fixtures.certificates(str(self.root))
        url = self.serve(self.node, enabled=False, tls=paths)
        self.assertEqual(self.runtime('bad-ca', url=url).step()['state'], 'waiting')
        self.assertEqual(self.runtime('bad-host', url=url.replace('localhost', '127.0.0.1'), ca_file=paths['ca']).step()['state'], 'waiting')
        self.assertEqual(self.runtime('good', url=url, ca_file=paths['ca']).step()['state'], 'registered')

    def test_challenge_substitution_is_rejected_before_signing_or_posting(self):
        runtime = self.runtime()
        with patch.object(runtime.client.client, 'request', return_value={'nonce': 'n', 'context': 'wrong'}) as request:
            self.assertEqual(runtime.step()['state'], 'waiting')
            self.assertEqual([call.args[0] for call in request.call_args_list], ['/v1/challenges'])

    def test_concurrent_steps_serialize_signed_counters_and_network_updates(self):
        runtime = self.runtime()
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda _: runtime.step(), range(3)))
        self.assertEqual(sorted(result['sequence'] for result in results), [1, 2, 3])
        self.assertTrue(all(result['state']=='registered' for result in results))
        claims = verify_presence(self.observation()[0]['presence'], self.agent.public_key(), self.owner.public_key(), self.group, runtime.record)
        self.assertEqual(claims['sequence'], 3)

    def cli(self, key_path, grant, state, *, url=None, record=None, once=True):
        pin, grant_path, record_path = self.root/'owner.pub', self.root/(state+'.grant'), self.root/(state+'.json')
        pin.write_text(encode(public_bytes(self.owner.public_key())))
        grant_path.write_text(grant); grant_path.chmod(0o600)
        record_path.write_text(json.dumps(self.record if record is None else record))
        return [sys.executable, '-m', 'tailnet_agents.agent_runtime', '--url', url or self.url,
                '--agent-key', str(key_path), '--authority-public-key', str(pin), '--grant-file', str(grant_path),
                '--group-id', self.group, '--audience', self.audience, '--state', str(self.root/(state+'.sqlite3')),
                '--record-file', str(record_path), '--interval', '1'] + (['--once'] if once else [])

    def real_time_policy(self):
        self.now = int(time.time())
        self.grant = issue_grant(self.owner, self.agent.public_key(), self.group, ['join'], now=self.now)
        credential = verify_grant(self.grant, self.owner.public_key(), self.group, now=self.now)['jti']
        self.members = {self.subject: {'permissions': ['join'], 'grant_ids': [credential]}}
        self.policy = revise_policy(self.owner, self.policy, self.members, now=self.now)
        self.node.apply_policy(self.policy)

    def test_real_cli_two_agents_same_host_and_restart_keep_original_keys_group(self):
        self.real_time_policy()
        key, grant = self.approve_second()
        commands = [self.cli(self.agent_path, self.grant, 'first'),
                    self.cli(self.root/'second.pem', grant, 'second', record=self.record | {'endpoint': 'https://same-host.example:8902'})]
        original_keys = [self.agent_path.read_bytes(), (self.root/'second.pem').read_bytes()]
        first_outputs = []
        for command in commands:
            result = subprocess.run(command, text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr+result.stdout)
            first_outputs.append([json.loads(line) for line in result.stdout.splitlines()])
            self.assertNotIn(self.grant, result.stdout+result.stderr)
            self.assertNotIn(grant, result.stdout+result.stderr)
        self.assertEqual(len(self.observation()), 2)
        restarted = subprocess.run(commands[0], text=True, capture_output=True, timeout=15)
        self.assertEqual(restarted.returncode, 0, restarted.stderr+restarted.stdout)
        output = [json.loads(line) for line in restarted.stdout.splitlines()]
        self.assertEqual(output[-1]['subject'], first_outputs[0][-1]['subject'])
        self.assertEqual(output[-1]['group_id'], self.group)
        self.assertEqual(output[-1]['generation'], 2)
        self.assertNotEqual(output[-1]['boot_id'], first_outputs[0][-1]['boot_id'])
        self.assertEqual([self.agent_path.read_bytes(), (self.root/'second.pem').read_bytes()], original_keys)
        viewer = subprocess.run([sys.executable, '-m', 'tailnet_agents.presence', '--url', self.url,
                                 '--authority-public-key', str(self.root/'owner.pub'), '--group-id', self.group],
                                env=os.environ | {'TAILNET_VERIFIED_READ_TOKEN': 'r'*32}, text=True, capture_output=True, timeout=10)
        self.assertEqual(viewer.returncode, 0, viewer.stderr)
        self.assertEqual(len(json.loads(viewer.stdout)['entries']), 2)

    def test_real_cli_sigterm_sends_signed_offline_and_releases_state_lock(self):
        self.real_time_policy()
        command = self.cli(self.agent_path, self.grant, 'continuous', once=False)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            for _ in range(2):
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(timeout=8), 'runtime did not start')
                output = json.loads(process.stdout.readline())
            self.assertEqual(output['state'], 'registered')
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertIn('offline', stdout)
            self.assertEqual(self.observation()[0]['state'], 'offline')
            restored = self.runtime('continuous')
            self.assertEqual(restored.state.generation, 2)
        finally:
            if process.poll() is None: process.kill(); process.communicate(timeout=5)

    def test_two_real_processes_renew_independently_and_stopping_one_keeps_other_online(self):
        self.real_time_policy()
        _, grant = self.approve_second()
        commands = [self.cli(self.agent_path, self.grant, 'parallel-a', once=False),
                    self.cli(self.root/'second.pem', grant, 'parallel-b', once=False,
                             record=self.record | {'endpoint': 'https://same-host.example:8902'})]
        processes = [subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for command in commands]
        try:
            deadline = time.monotonic()+8
            while time.monotonic()<deadline:
                self.now = int(time.time())
                entries = self.observation()
                if len(entries)==2:
                    counters = [verify_presence(entry['presence'],
                        self.agent.public_key() if entry['subject']==self.subject else fixtures.load_identity(self.root/'second.pem').public_key(),
                        self.owner.public_key(), self.group, entry['record'])['sequence'] for entry in entries]
                    if min(counters)>=2 and all(entry['state']=='online' for entry in entries):break
                time.sleep(0.05)
            else:self.fail('both runtime processes did not renew independently')
            processes[0].send_signal(signal.SIGTERM)
            _, error = processes[0].communicate(timeout=10)
            self.assertEqual(processes[0].returncode, 0, error)
            states = {entry['subject']: entry['state'] for entry in self.observation()}
            self.assertEqual(states[self.subject], 'offline')
            self.assertEqual(list(states.values()).count('online'), 1)
            processes[1].send_signal(signal.SIGTERM)
            _, error = processes[1].communicate(timeout=10)
            self.assertEqual(processes[1].returncode, 0, error)
            self.assertTrue(all(entry['state']=='offline' for entry in self.observation()))
        finally:
            for process in processes:
                if process.poll() is None:process.kill();process.communicate(timeout=5)
