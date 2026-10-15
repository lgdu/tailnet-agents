"""Real synthetic-key HTTP/TLS conversations and crash/retry authorization."""
import copy
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tailnet_agents.admission_server import AdmissionHTTPServer, handler, transport_config
    from tailnet_agents.client import Client
    from tailnet_agents.group_policy import POLICY_TYPE, create_policy, revise_policy
    from tailnet_agents.identity import (AdmissionError, decode, encode, generate_identity, identity_id,
        issue_grant, prove_possession, public_bytes, sign, verify, verify_grant)
    from tailnet_agents.message_client import MessageClient
    from tailnet_agents.network_messages import (MESSAGE_TYPE, MessageStore, conversation_id, digest,
        make_message, validate_request, verify_message)
    from tailnet_agents.verified_directory import VerifiedDirectory, issue_revocation
    from tests.test_discovery import DiscoveryFixture
    from tests.test_admission_tls import certificates
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    DiscoveryFixture = unittest.TestCase


@unittest.skipUnless(HAS_CRYPTO, 'install identity extra')
class NetworkMessageTests(DiscoveryFixture):
    def setUp(self):
        super().setUp()
        self.keys = [self.agent] + [generate_identity(self.root / f'agent-{i}.pem') for i in range(1, 4)]
        self.scopes = ['join', 'chat.group', 'chat.direct']
        self.grants = [issue_grant(self.owner, key.public_key(), self.group, self.scopes if i < 3 else ['join'], now=100) for i, key in enumerate(self.keys)]
        self.subjects = [identity_id(key.public_key()) for key in self.keys]
        self.members = {subject: {'permissions': self.scopes if i < 3 else ['join'],
            'grant_ids': [verify_grant(self.grants[i], self.owner.public_key(), self.group, now=110)['jti']]}
            for i, subject in enumerate(self.subjects)}
        self.policy = revise_policy(self.owner, self.policy, self.members, now=102)
        self.node = self.directory(database=str(self.root / 'directory.sqlite3'))
        self.url, self.server = self.serve_messages(self.node)

    def serve_messages(self, node, *, enabled=True, tls=None):
        allowed, context = (None, None) if tls is None else transport_config('127.0.0.1', tls['cert'], tls['key'], ['localhost', '127.0.0.1'])
        scheme = 'http' if tls is None else 'https'
        server = AdmissionHTTPServer(('127.0.0.1', 0), handler(node, 'r'*32, allowed, scheme, messages=enabled), context)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def cleanup():
            server.shutdown(); server.server_close(); thread.join()
        self.addCleanup(cleanup)
        return f'{scheme}://{"localhost" if tls else "127.0.0.1"}:{server.server_port}', server

    def client(self, index=0, *, state=None, url=None, **options):
        client = MessageClient(url or self.url, self.keys[index], self.owner.public_key(), self.grants[index],
                               self.group, self.audience, state or self.root / f'messages-{index}.sqlite3', clock=lambda: self.now, **options)
        self.addCleanup(client.close)
        return client

    def request(self, index=0, **options):
        return {'operation': 'send', 'message': make_message(self.keys[index], self.owner.public_key(), self.group,
            self.audience, 'Hello', 'a'*32, now=self.now, **options)}

    def authenticated(self, request, index=0, **changes):
        challenge = Client(self.url, '').request('/v1/messages/challenges', {'request': request})
        return {'request': request, 'grant': self.grants[index], 'public_key': encode(public_bytes(self.keys[index].public_key())),
                'nonce': challenge['nonce'], 'proof': prove_possession(self.keys[index], self.grants[index], challenge['nonce'], self.audience, context=challenge['context'])} | changes

    def post(self, payload):
        return Client(self.url, '').request('/v1/messages', payload)

    def read(self, scope='group', peer=None, after=0, limit=20):
        return {'operation': 'read', 'scope': scope, 'peer': peer, 'after': after, 'limit': limit}

    def denied(self, operation, status=403):
        with self.assertRaises(HTTPError) as caught:operation()
        self.assertEqual(caught.exception.code, status)
        return caught.exception

    def revise(self, members=None, *, dissolve=False):
        self.policy = revise_policy(self.owner, self.policy, self.members if members is None else members, now=int(self.now), dissolve=dissolve)
        self.node.apply_policy(self.policy)

    def count(self):
        return self.node._registry.db.execute('SELECT COUNT(*) FROM network_messages').fetchone()[0]

    def test_default_disabled_and_requires_policy_without_creating_group(self):
        url, _ = self.serve_messages(self.node, enabled=False)
        self.denied(lambda: Client(url, 'r'*32).request('/v1/messages/challenges', {'request': self.read()}), 404)
        empty = VerifiedDirectory(self.owner.public_key(), self.group, self.audience)
        self.addCleanup(empty.close)
        with self.assertRaises(ValueError):handler(empty, 'r'*32, messages=True)
        missing = VerifiedDirectory(self.owner.public_key(), self.group, self.audience, require_policy=True, clock=lambda: self.now)
        self.addCleanup(missing.close)
        store = MessageStore(missing)
        req = self.read();ch = store.challenge(req)
        proof = prove_possession(self.agent, self.grants[0], ch['nonce'], self.audience, context=ch['context'])
        with self.assertRaises(AdmissionError):store.execute(req, self.grants[0], self.agent.public_key(), proof, ch['nonce'])
        self.assertIsNone(missing._policy.current())

    def test_group_and_direct_chat_across_same_host_identities_without_automatic_replies(self):
        a, b, c = self.client(0), self.client(1), self.client(2)
        a.queue('group hello');a.queue('private hello', recipient=self.subjects[1]);a.flush()
        self.assertEqual([row['text'] for row in b.sync()['messages']], ['group hello'])
        self.assertEqual([row['text'] for row in c.sync()['messages']], ['group hello'])
        private = b.sync('direct', peer=self.subjects[0])['messages']
        self.assertEqual([row['text'] for row in private], ['private hello'])
        self.assertEqual(c.sync('direct', peer=self.subjects[0])['messages'], [])
        b.queue('private reply', recipient=self.subjects[0], reply_to=private[0]['message_id']);b.flush()
        self.assertEqual([row['text'] for row in a.sync('direct', peer=self.subjects[1])['messages']], ['private hello', 'private reply'])
        self.assertEqual(self.count(), 3)
        self.assertEqual(self.node.discover(), [])
        self.assertEqual(self.node._registry.db.execute('SELECT COUNT(*) FROM admission_grants').fetchone()[0], 0)
        self.assertEqual(self.node._policy.current()['members'], self.members)

    def test_directory_read_token_and_owner_have_no_implicit_message_access(self):
        client = self.client();client.queue('private', recipient=self.subjects[1]);client.flush()
        self.denied(lambda: Client(self.url, 'r'*32).request('/v1/messages', {'request': self.read('direct', self.subjects[0])}), 400)
        self.denied(lambda: Client(self.url, 'r'*32).request('/v1/messages'), 404)
        self.denied(lambda: self.post(self.authenticated(self.read(), public_key=encode(public_bytes(self.owner.public_key())))))

    def test_join_only_grant_cannot_send_or_read_chat(self):
        for req in [self.request(3), self.read(), self.read('direct', self.subjects[0])]:
            self.denied(lambda: self.post(self.authenticated(req, 3)))
        self.assertEqual(self.count(), 0)

    def test_unapproved_and_foreign_grants_and_subject_substitution_are_denied(self):
        good = self.authenticated(self.request())
        grants = [issue_grant(self.owner, self.agent.public_key(), self.group, self.scopes, now=100),
                  issue_grant(Ed25519PrivateKey.generate(), self.agent.public_key(), self.group, self.scopes, now=100),
                  issue_grant(self.owner, self.agent.public_key(), 'another-group', self.scopes, now=100), self.grants[1]]
        for grant in grants:self.denied(lambda: self.post(good | {'grant': grant}))
        self.denied(lambda: self.post(good | {'public_key': encode(public_bytes(self.keys[1].public_key()))}))
        self.assertEqual(self.post(good)['state'], 'stored')

    def test_current_grant_expiry_and_revocation_apply_even_to_dedup_retry(self):
        req = self.request();self.post(self.authenticated(req))
        self.node.revoke(issue_revocation(self.owner, self.group, self.members[self.subjects[0]]['grant_ids'][0]))
        self.denied(lambda: self.post(self.authenticated(req)))
        self.denied(lambda: self.post(self.authenticated(self.read())))
        self.assertEqual(self.count(), 1)
        self.now = 4000
        self.denied(lambda: self.post(self.authenticated(self.read(), 1)))

    def test_membership_removal_and_stale_policy_block_reads_without_deleting_history(self):
        c = self.client();c.queue('retained');c.flush()
        self.now = 403
        self.denied(lambda: c.sync())
        self.now = 111
        self.revise({k: v for k, v in self.members.items() if k != self.subjects[0]})
        self.denied(lambda: c.sync())
        self.assertEqual(self.count(), 1)

    def test_terminal_dissolution_blocks_send_and_read_and_survives_restart(self):
        client = self.client();client.queue('retained');client.flush();self.revise(dissolve=True)
        self.denied(lambda: client.sync())
        self.denied(lambda: self.post(self.authenticated(self.request())))
        self.node.close()
        self.node = VerifiedDirectory(self.owner.public_key(), self.group, self.audience, require_policy=True, database=str(self.root/'directory.sqlite3'), clock=lambda: self.now)
        self.addCleanup(self.node.close)
        self.assertEqual(self.node.policy_status()['state'], 'dissolved')
        self.assertEqual(self.count(), 1)

    def test_recipient_must_have_current_direct_permission_and_unrevoked_approval(self):
        a = self.client()
        a.queue('not granted', recipient=self.subjects[3]);self.denied(lambda: a.flush())
        a.close()
        a = self.client(state=self.root/'other-state.sqlite3')
        a.queue('revoked recipient', recipient=self.subjects[1])
        self.node.revoke(issue_revocation(self.owner, self.group, self.members[self.subjects[1]]['grant_ids'][0]))
        self.denied(lambda: a.flush())
        self.assertEqual(self.count(), 0)

    def test_message_signature_owner_group_audience_and_type_are_bound(self):
        original = self.request();claim = verify(original['message'], self.agent.public_key(), MESSAGE_TYPE)
        for changes in [{'owner': self.subjects[1]}, {'group_id': 'foreign'}, {'audience': 'foreign'}, {'sender': self.subjects[1]}, {'conversation_id': '0'*64}, {'version': True}]:
            req = original | {'message': sign(self.agent, claim | changes, MESSAGE_TYPE)}
            self.denied(lambda: self.post(self.authenticated(req)))
        req = original | {'message': sign(self.keys[1], claim, MESSAGE_TYPE)}
        self.denied(lambda: self.post(self.authenticated(req)))
        req = original | {'message': self.grants[0]}
        self.denied(lambda: self.post(self.authenticated(req)))
        self.assertEqual(self.count(), 0)

    def test_single_use_proof_binds_operation_body_scope_and_cursor(self):
        payload = self.authenticated(self.request())
        self.assertEqual(self.post(payload)['state'], 'stored')
        self.denied(lambda: self.post(payload))
        read = self.authenticated(self.read())
        for req in [self.read('direct', self.subjects[1]), self.read(after=1), self.read(limit=1), self.request()]:
            self.denied(lambda: self.post(read | {'request': req}))
        self.assertEqual(len(self.post(read)['messages']), 1)
        self.denied(lambda: self.post(read))

    def test_expired_challenge_fails_without_committing_message(self):
        payload = self.authenticated(self.request());self.now += 31
        self.denied(lambda: self.post(payload))
        self.assertEqual(self.count(), 0)

    def test_duplicate_id_is_idempotent_but_conflicting_content_or_sender_is_409(self):
        req = self.request()
        first = self.post(self.authenticated(req));second = self.post(self.authenticated(req))
        self.assertEqual(first, second)
        claim = verify(req['message'], self.agent.public_key(), MESSAGE_TYPE)
        changed = req | {'message': sign(self.agent, claim | {'text': 'changed'}, MESSAGE_TYPE)}
        self.denied(lambda: self.post(self.authenticated(changed)), 409)
        self.denied(lambda: self.post(self.authenticated(self.request(1), 1)), 409)
        self.assertEqual(self.count(), 1)

    def test_reply_reference_cannot_cross_conversations_or_reference_missing_message(self):
        a = self.client();mid = a.queue('private', recipient=self.subjects[1])['message_id'];a.flush()
        a.queue('group reference to private', reply_to=mid)
        self.denied(lambda: a.flush())
        bad = self.request(recipient=self.subjects[1], reply_to='b'*32)
        self.denied(lambda: self.post(self.authenticated(bad)))
        self.assertEqual(self.count(), 1)

    def test_offline_queue_reconnect_paging_and_restart_keep_original_messages_and_cursor(self):
        a, b = self.client(), self.client(1)
        with patch.object(a.http, 'request', side_effect=URLError('offline')):
            mids = [a.queue(f'message {i}')['message_id'] for i in range(5)]
            with self.assertRaises(URLError):a.flush()
        self.assertEqual(a.status(), {'pending': 5});a.close()
        a = self.client();self.assertEqual([row['message_id'] for row in a.flush()], mids)
        page = b.sync(limit=2);self.assertTrue(page['has_more']);self.assertEqual(len(page['messages']), 2)
        b.close();b = self.client(1)
        self.assertEqual([r['text'] for r in b.sync(limit=2)['messages']], ['message 2', 'message 3'])
        self.assertFalse(b.sync(limit=2)['has_more']);self.assertEqual(b.sync()['messages'], [])
        self.assertEqual([r['message_id'] for r in b.history()], mids)
        self.assertEqual(a.flush(), [])

    def test_lost_ack_receiver_and_sender_restart_retry_exact_envelope_once(self):
        a = self.client();mid = a.queue('one committed message')['message_id']
        original = a.http.request
        def lost_ack(path, body=None):
            result = original(path, body)
            if path == '/v1/messages':raise URLError('response lost after commit')
            return result
        with patch.object(a.http, 'request', side_effect=lost_ack):
            with self.assertRaises(URLError):a.flush()
        self.assertEqual(self.count(), 1);self.assertEqual(a.status(), {'pending': 1});a.close()
        # Preserve the same service origin while replacing its handler/directory.
        self.node.close()
        self.node = VerifiedDirectory(self.owner.public_key(), self.group, self.audience, require_policy=True, database=str(self.root/'directory.sqlite3'), clock=lambda: self.now)
        self.addCleanup(self.node.close)
        self.server.RequestHandlerClass = handler(self.node, 'r'*32, messages=True)
        a = self.client();receipt = a.flush()[0]
        self.assertEqual(receipt['message_id'], mid);self.assertEqual(receipt['sequence'], 1)
        self.assertEqual(self.count(), 1);self.assertEqual(a.status(), {'stored': 1})

    def test_failed_storage_transaction_never_acknowledges_or_drops_outbox(self):
        a = self.client();a.queue('pending')
        self.node._registry.db.execute("CREATE TRIGGER reject_message BEFORE INSERT ON network_messages BEGIN SELECT RAISE(ABORT,'test storage unavailable'); END")
        self.denied(lambda: a.flush(), 503)
        self.assertEqual(self.count(), 0);self.assertEqual(a.status(), {'pending': 1})
        self.node._registry.db.execute('DROP TRIGGER reject_message')
        self.assertEqual(a.flush()[0]['state'], 'stored')

    def test_forged_ack_keeps_original_outbox_pending(self):
        a = self.client();mid = a.queue('pending')['message_id']
        for ack in [{'state': 'delivered'}, {'state': 'stored', 'message_id': mid, 'sequence': True, 'message_hash': 'fake'},
                    {'state': 'stored', 'message_id': mid, 'sequence': 1, 'message_hash': 'fake'}]:
            with patch.object(a, '_request', return_value=ack), self.assertRaises(ValueError):a.flush()
            self.assertEqual(a.status(), {'pending': 1})

    def test_wrong_challenge_never_sends_private_payload_or_proof(self):
        a = self.client();a.queue('pending')
        for response in [{'nonce': 'n', 'context': 'another operation'}, {'nonce': [], 'context': 'bad'}]:
            with patch.object(a.http, 'request', return_value=response) as network, self.assertRaises(ValueError):a.flush()
            self.assertEqual(network.call_count, 1)
            self.assertEqual(network.call_args.args[0], '/v1/messages/challenges')

    def test_reader_verifies_entire_page_before_saving_any_message_or_cursor(self):
        a, b = self.client(), self.client(1)
        a.queue('first');a.queue('second');a.flush()
        valid = self.post(self.authenticated(self.read(), 1))
        bad_pages = []
        for field, value in [('owner', self.subjects[0]), ('group_id', 'other'), ('audience', 'other'), ('next_after', 9), ('has_more', 1)]:
            bad_pages.append(valid | {field: value})
        bad = copy.deepcopy(valid);bad['messages'][1]['message'] = self.grants[0];bad_pages.append(bad)
        bad = copy.deepcopy(valid);bad['messages'][1]['sequence'] = 1;bad_pages.append(bad)
        bad = copy.deepcopy(valid);bad['messages'][1]['stored_at'] = float('nan');bad_pages.append(bad)
        for page in bad_pages:
            with patch.object(b, '_request', return_value=page), self.assertRaises(ValueError):b.sync()
            self.assertEqual(b.history(), [])
            self.assertEqual(b.db.execute('SELECT COUNT(*) FROM message_cursors').fetchone()[0], 0)
        self.assertEqual(len(b.sync()['messages']), 2)

    def test_direct_recipient_never_accepts_another_conversations_page(self):
        a, c = self.client(), self.client(2)
        a.queue('private', recipient=self.subjects[1]);a.flush()
        page = self.post(self.authenticated(self.read('direct', self.subjects[0]), 1))
        with patch.object(c, '_request', return_value=page), self.assertRaises(ValueError):c.sync('direct', peer=self.subjects[0])
        self.assertEqual(c.history('direct', peer=self.subjects[0]), [])

    def test_message_client_state_pins_original_key_group_service_audience_and_ca(self):
        a = self.client();state = self.root/'messages-0.sqlite3';a.close()
        cases = [(self.url, self.keys[1], self.grants[1], self.group, self.audience),
                 ('https://other.example', self.agent, self.grants[0], self.group, self.audience),
                 (self.url, self.agent, self.grants[0], self.group, 'other')]
        for url, key, grant, group, audience in cases:
            with self.assertRaises(AdmissionError):MessageClient(url, key, self.owner.public_key(), grant, group, audience, state)
        foreign = issue_grant(self.owner, self.agent.public_key(), 'foreign', self.scopes, now=100)
        with self.assertRaises(AdmissionError):MessageClient(self.url, self.agent, self.owner.public_key(), foreign, 'foreign', self.audience, state)
        self.assertEqual(self.client().subject, self.subjects[0])

    def test_private_state_rejects_shared_permissions_symlinks_and_concurrent_process(self):
        a = self.client();state = self.root/'messages-0.sqlite3'
        self.assertEqual(state.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(OSError):self.client()
        link = self.root/'link.sqlite3';link.symlink_to(state)
        with self.assertRaises(OSError):self.client(state=link)
        a.close();state.chmod(0o644)
        with self.assertRaises(ValueError):self.client()
        state.chmod(0o600)

    def test_manual_grant_renewal_can_resume_original_pending_outbox(self):
        a = self.client();mid = a.queue('queued before renewal')['message_id'];a.close()
        self.now = 4000
        fresh = issue_grant(self.owner, self.agent.public_key(), self.group, self.scopes, now=self.now)
        self.grants[0] = fresh
        self.members[self.subjects[0]]['grant_ids'] = [verify_grant(fresh, self.owner.public_key(), self.group, now=self.now)['jti']]
        self.revise()
        a = self.client();self.assertEqual(a.flush()[0]['message_id'], mid)
        self.assertEqual(self.count(), 1)

    def test_strict_request_and_signed_message_schema_and_bounds(self):
        malformed = [self.read(after=True), self.read(limit=True), self.read(limit=21), self.read(after=-1),
                     self.read(peer=self.subjects[1]), self.read('direct'), self.read() | {'extra': 1}, {'operation': 'execute'}]
        for request in malformed:
            self.denied(lambda: Client(self.url, '').request('/v1/messages/challenges', {'request': request}), 400)
        a = self.client()
        for text in ['', '   ', 'x'*4097, '中'*1366]:
            with self.assertRaises(ValueError):a.queue(text)
        a.queue('中'*1365);self.assertEqual(a.flush()[0]['state'], 'stored')
        req = self.request();claim = verify(req['message'], self.agent.public_key(), MESSAGE_TYPE)
        for change in [{'created_at': True}, {'created_at': self.now + 31}, {'reply_to': 9}, {'recipient': {}}, {'kind': 'task'}, {'extra': 1}]:
            bad = req | {'message': sign(self.agent, claim | change, MESSAGE_TYPE)}
            self.denied(lambda: self.post(self.authenticated(bad)))

    def test_tls_ca_hostname_and_external_plain_http_are_rejected(self):
        tls = certificates(self.root);url, _ = self.serve_messages(self.node, tls=tls)
        a = self.client(url=url, state=self.root/'tls-a.sqlite3', ca_file=tls['ca'])
        a.queue('TLS group');self.assertEqual(a.flush()[0]['state'], 'stored')
        b = self.client(1, url=url, state=self.root/'tls-b.sqlite3', ca_file=tls['ca'])
        self.assertEqual(b.sync()['messages'][0]['text'], 'TLS group')
        c = self.client(2, url=url, state=self.root/'tls-c.sqlite3')
        with self.assertRaises(URLError):c.sync()
        d = self.client(2, url=url.replace('localhost','127.0.0.1'), state=self.root/'tls-d.sqlite3', ca_file=tls['ca'])
        with self.assertRaises(URLError):d.sync()
        with self.assertRaises(ValueError):self.client(state=self.root/'bad.sqlite3', url='http://100.64.0.1:8771')
        with self.assertRaises(ValueError):transport_config('0.0.0.0')

    def test_client_does_not_follow_redirect_or_ambient_proxy(self):
        # Exercise the shared transport's redirect guard with an actual server.
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        hits = []
        class Redirect(BaseHTTPRequestHandler):
            def do_POST(self):
                hits.append(self.path);self.send_response(307);self.send_header('Location', self.server.destination);self.send_header('Content-Length','0');self.end_headers()
            def log_message(self, *_):pass
        server = ThreadingHTTPServer(('127.0.0.1',0), Redirect);server.destination = self.url + '/v1/messages'
        thread = threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(lambda: (server.shutdown(),server.server_close(),thread.join()))
        client = self.client(state=self.root/'redirect.sqlite3', url=f'http://127.0.0.1:{server.server_port}')
        with patch.dict(os.environ, {'HTTP_PROXY':'http://127.0.0.1:1'}):
            self.denied(lambda: client.sync(), 307)
        self.assertEqual(hits, ['/v1/messages/challenges']);self.assertEqual(self.count(),0)

    def test_simultaneous_senders_keep_independent_order_and_scoped_history(self):
        a, b = self.client(), self.client(1)
        a.queue('from a');b.queue('from b')
        errors = []
        def flush(client):
            try:client.flush()
            except Exception as error:errors.append(error)
        threads = [threading.Thread(target=flush,args=(client,)) for client in (a,b)]
        for thread in threads:thread.start()
        for thread in threads:thread.join()
        self.assertEqual(errors, [])
        entries = self.client(2).sync()['messages']
        self.assertEqual({entry['sender'] for entry in entries}, set(self.subjects[:2]))
        self.assertEqual([entry['sequence'] for entry in entries], [1,2])

    def test_inbox_transaction_failure_preserves_cursor_and_recovers_same_page(self):
        a, b = self.client(), self.client(1);a.queue('one');a.queue('two');a.flush()
        b.db.execute("CREATE TRIGGER reject_inbox BEFORE INSERT ON message_inbox WHEN NEW.sequence=2 BEGIN SELECT RAISE(ABORT,'test'); END")
        with self.assertRaises(sqlite3.Error):b.sync()
        self.assertEqual(b.history(), [])
        self.assertEqual(b.db.execute('SELECT COUNT(*) FROM message_cursors').fetchone()[0], 0)
        b.db.execute('DROP TRIGGER reject_inbox')
        self.assertEqual(len(b.sync()['messages']), 2)

    def test_message_service_rejects_replacing_persisted_audience(self):
        self.node.close()
        node = VerifiedDirectory(self.owner.public_key(), self.group, 'replacement', require_policy=True,
            database=str(self.root/'directory.sqlite3'), clock=lambda: self.now)
        self.addCleanup(node.close)
        with self.assertRaises(AdmissionError):MessageStore(node)

    def test_failed_later_send_preserves_earlier_ack_and_bounded_pending_order(self):
        a = self.client();a.queue('first');a.queue('second');a.queue('denied', recipient=self.subjects[3])
        self.assertEqual(len(a.flush(limit=1)), 1)
        self.assertEqual(a.status(), {'pending':2, 'stored':1})
        self.denied(lambda: a.flush())
        self.assertEqual(a.status(), {'pending':1, 'stored':2})
        self.assertEqual(self.count(), 2)

    def test_authorized_recipient_keeps_history_after_sender_removal(self):
        a, b = self.client(), self.client(1)
        a.queue('retained private', recipient=self.subjects[1]);a.flush()
        self.revise({k:v for k,v in self.members.items() if k!=self.subjects[0]})
        self.denied(lambda: a.sync('direct', peer=self.subjects[1]))
        self.assertEqual(b.sync('direct', peer=self.subjects[0])['messages'][0]['text'], 'retained private')

    def test_real_service_and_message_clis_restore_state_and_do_not_print_credentials(self):
        now = int(time.time())
        grants = [issue_grant(self.owner,key.public_key(),self.group,self.scopes,now=now) for key in self.keys[:2]]
        members = {self.subjects[i]:{'permissions':self.scopes,'grant_ids':[verify_grant(grants[i],self.owner.public_key(),self.group,now=now)['jti']]} for i in range(2)}
        policy = revise_policy(self.owner,self.policy,members,now=now)
        authority = self.root/'owner.pub';authority.write_text(encode(public_bytes(self.owner.public_key())))
        policy_file = self.root/'policy.jwt';policy_file.write_text(policy)
        text = self.root/'text.txt';text.write_text('real CLI private text')
        for i,grant in enumerate(grants):(self.root/f'grant-{i}').write_text(grant)
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        env = os.environ | {'TAILNET_VERIFIED_READ_TOKEN':'r'*32}
        service = subprocess.Popen([sys.executable,'-m','tailnet_agents.admission_server','--authority-public-key',str(authority),
            '--group-id',self.group,'--audience',self.audience,'--database',str(self.root/'cli-dir.sqlite3'),
            '--policy-file',str(policy_file),'--messages','--port',str(port)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.addCleanup(lambda: (service.poll() is None and service.terminate(), service.communicate(timeout=10)))
        url = f'http://127.0.0.1:{port}'
        deadline = time.monotonic()+10
        while True:
            try:Client(url,'').request('/healthz');break
            except URLError:
                if time.monotonic()>deadline:self.fail('CLI service failed to start')
                time.sleep(.02)
        def run(i,*operation,success=True):
            key = self.agent_path if i==0 else self.root/'agent-1.pem'
            result = subprocess.run([sys.executable,'-m','tailnet_agents.message_client','--url',url,'--agent-key',str(key),
                '--authority-public-key',str(authority),'--grant-file',str(self.root/f'grant-{i}'),'--group-id',self.group,
                '--audience',self.audience,'--state',str(self.root/f'cli-messages-{i}.sqlite3'),*operation],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0 if success else 1,result.stderr)
            for grant in grants:self.assertNotIn(grant,result.stdout+result.stderr)
            self.assertNotIn('PRIVATE KEY',result.stdout+result.stderr)
            return json.loads(result.stdout) if success else result
        mid = run(0,'queue','--text-file',str(text),'--recipient',self.subjects[1])['message_id']
        self.assertEqual(run(0,'status'),{'pending':1})
        self.assertEqual(run(0,'flush')[0]['message_id'],mid)
        self.assertEqual(run(1,'sync','--scope','direct','--peer',self.subjects[0])['messages'][0]['text'],'real CLI private text')
        self.assertEqual(run(1,'sync','--scope','direct','--peer',self.subjects[0])['messages'],[])
        self.assertEqual(len(run(1,'history','--scope','direct','--peer',self.subjects[0])),1)
        self.assertEqual(run(0,'flush'),[])
        run(1,'sync','--scope','direct',success=False)
