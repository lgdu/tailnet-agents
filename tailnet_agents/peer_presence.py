"""Configured, one-hop signed presence observations; never admission leases."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
from urllib.parse import urlencode
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .client import Client
from .identity import AdmissionError, GRANT_TYPE, decode, identity_id, verify, verify_grant
from .presence import MAX_COUNTER, verify_presence
from .discovery import origin
from .runtime_monitor import validate_page

STATES = {'online', 'offline', 'expired', 'unauthorized'}
MERGED_STATES = STATES | {'superseded', 'conflict'}


def finite(value):
    return type(value) in (int, float) and 0 <= value < math.inf


def unpack_entry(entry, owner, group):
    fields = {'subject', 'public_key', 'record', 'presence', 'grant', 'expires_at', 'observed_at', 'state'}
    if not isinstance(entry, dict) or set(entry) != fields:
        raise AdmissionError('invalid presence replication entry')
    key = Ed25519PublicKey.from_public_bytes(decode(entry['public_key']))
    claims = verify_presence(entry['presence'], key, owner, group, entry['record'])
    raw_grant = verify(entry['grant'], owner, GRANT_TYPE)
    issued = raw_grant.get('iat')
    if type(issued) is not int: raise AdmissionError('invalid replication grant')
    grant = verify_grant(entry['grant'], owner, group, now=issued)
    if (entry['subject'] != claims['subject'] or grant['sub'] != claims['subject'] or
            not finite(entry['expires_at']) or entry['expires_at'] > min(claims['expires_at'], grant['exp']) or
            not finite(entry['observed_at']) or entry['state'] not in STATES or
            (entry['state'] in ('online', 'offline') and claims['state'] != entry['state'])):
        raise AdmissionError('invalid signed replication scope or deadline')
    return claims, grant


def validate_export(page, owner, group, after, now):
    if (not isinstance(page, dict) or set(page) != {'owner','group_id','observed_at','entries','has_more','next_after'} or
            page['owner'] != identity_id(owner) or page['group_id'] != group or
            not finite(page['observed_at']) or page['observed_at'] > now+5 or
            not isinstance(page['entries'], list) or len(page['entries']) > 20 or
            type(page['has_more']) is not bool):
        raise AdmissionError('invalid presence replication page')
    cursor, result = after, []
    for entry in page['entries']:
        claims, grant = unpack_entry(entry, owner, group)
        if entry['subject'] <= cursor or entry['observed_at'] > page['observed_at'] or claims['issued_at'] > now+5:
            raise AdmissionError('invalid presence replication order or time')
        cursor = entry['subject']
        result.append((entry, claims, grant))
    if page['next_after'] != cursor or (page['has_more'] and not result):
        raise AdmissionError('presence replication cursor did not advance')
    return result


class PeerPresenceStore:
    """SQLite cache and durable observation high-water marks, under directory lock."""
    def __init__(self, db):
        self.db, self.sources = db, {}
        db.execute('CREATE TABLE IF NOT EXISTS peer_presence (source TEXT NOT NULL,fingerprint TEXT NOT NULL,subject TEXT NOT NULL,payload TEXT NOT NULL,received REAL NOT NULL,PRIMARY KEY(source,fingerprint,subject))')
        db.execute('CREATE TABLE IF NOT EXISTS presence_heads (subject TEXT PRIMARY KEY,generation INTEGER NOT NULL,boot_id TEXT NOT NULL,sequence INTEGER NOT NULL,token_hash TEXT NOT NULL,conflict INTEGER NOT NULL)')

    def configure(self, sources, group):
        sources = tuple(sources)
        if len(sources) > 8: raise ValueError('configure at most eight presence sources')
        configured, urls = {}, set()
        for source in sources:
            if source.group_id != group or source.id == 'local' or source.id in configured or source.url in urls:
                raise ValueError('invalid presence source identity, group or origin')
            configured[source.id] = source
            urls.add(source.url)
        self.sources = configured

    def note(self, claims, token):
        subject = claims['subject']
        generation, boot, sequence = (claims[field] for field in ('generation', 'boot_id', 'sequence'))
        digest = hashlib.sha256(token.encode()).hexdigest()
        previous = self.db.execute('SELECT generation,boot_id,sequence,token_hash,conflict FROM presence_heads WHERE subject=?', (subject,)).fetchone()
        if previous is None or generation > previous[0]:
            self.db.execute('INSERT INTO presence_heads VALUES(?,?,?,?,?,0) ON CONFLICT(subject) DO UPDATE SET generation=excluded.generation,boot_id=excluded.boot_id,sequence=excluded.sequence,token_hash=excluded.token_hash,conflict=0', (subject,generation,boot,sequence,digest))
        elif generation == previous[0]:
            if boot != previous[1] or (sequence == previous[2] and digest != previous[3]):
                self.db.execute('UPDATE presence_heads SET conflict=1 WHERE subject=?', (subject,))
            elif sequence > previous[2]:
                self.db.execute('UPDATE presence_heads SET sequence=?,token_hash=? WHERE subject=?', (sequence,digest,subject))

    def apply(self, source, rows, owner, group, now):
        if self.sources.get(source.id) is not source: raise AdmissionError('presence source configuration changed')
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            for entry, claims, _ in rows:
                self.note(claims, entry['presence'])
                saved = self.db.execute('SELECT payload FROM peer_presence WHERE source=? AND fingerprint=? AND subject=?', (source.id,source.fingerprint,entry['subject'])).fetchone()
                payload = dict(entry)
                if saved:
                    old = json.loads(saved[0])
                    previous, _ = unpack_entry(old, owner, group)
                    if claims['generation'] < previous['generation']: continue
                    if claims['generation'] == previous['generation']:
                        if claims['boot_id'] != previous['boot_id'] or claims['sequence'] < previous['sequence']: continue
                        if claims['sequence'] == previous['sequence']:
                            if entry['presence'] != old['presence']: continue  # note() made the conflict durable.
                            if entry['grant'] != old['grant']: raise AdmissionError('credential changed without a new heartbeat')
                            payload['expires_at'] = min(old['expires_at'], entry['expires_at'])
                            payload['observed_at'] = min(old['observed_at'], entry['observed_at'])
                            if old['state'] != 'online': payload['state'] = old['state']
                self.db.execute('INSERT INTO peer_presence VALUES(?,?,?,?,?) ON CONFLICT(source,fingerprint,subject) DO UPDATE SET payload=excluded.payload,received=excluded.received',
                    (source.id,source.fingerprint,entry['subject'],json.dumps(payload),now))

    def subjects(self, after, limit):
        sql = 'SELECT subject FROM agent_presence WHERE subject>?'
        args = [after]
        if self.sources:
            conditions = ' OR '.join('(source=? AND fingerprint=?)' for _ in self.sources)
            sql += ' UNION SELECT subject FROM peer_presence WHERE subject>? AND ('+conditions+')'
            args.append(after)
            for source in self.sources.values(): args.extend((source.id,source.fingerprint))
        return [row[0] for row in self.db.execute(sql+' ORDER BY subject LIMIT ?', args+[limit+1])]

    def remote(self, subject):
        for source in self.sources.values():
            row = self.db.execute('SELECT payload,received FROM peer_presence WHERE source=? AND fingerprint=? AND subject=?', (source.id,source.fingerprint,subject)).fetchone()
            if row: yield source.public(), json.loads(row[0]), row[1]

    def merge(self, subject, observations):
        head = self.db.execute('SELECT generation,boot_id,sequence,token_hash,conflict FROM presence_heads WHERE subject=?', (subject,)).fetchone()
        if head is None: raise AdmissionError('missing observation ordering history')
        matching = []
        for observation, claims in observations:
            if claims['generation'] == head[0] and head[4]: observation['state'] = 'conflict'
            elif (claims['generation'],claims['boot_id'],claims['sequence'],hashlib.sha256(observation['presence'].encode()).hexdigest()) != head[:4]:
                observation['state'] = 'superseded'
            else: matching.append(observation['state'])
        state = ('conflict' if head[4] else next((state for state in ('online','offline','unauthorized','expired') if state in matching), 'superseded'))
        return {'subject':subject, 'state':state,
                'head':dict(zip(('generation','boot_id','sequence','token_hash','conflict'), head)) | {'conflict':bool(head[4])},
                'observations':[observation for observation, _ in observations]}


class PresenceSynchronizer:
    """Poll every configured source; never promote discovery or stop at a primary."""
    def __init__(self, directory, sources, interval=5, *, max_pages=10):
        if not directory.require_policy: raise AdmissionError('presence synchronization requires policy mode')
        if type(interval) not in (int,float) or not 1 <= interval <= 3600 or type(max_pages) is not int or not 1 <= max_pages <= 100:
            raise ValueError('invalid presence synchronization bounds')
        self.directory, self.sources, self.interval, self.max_pages = directory, tuple(sources), interval, max_pages
        if not self.sources: raise ValueError('presence sources required')
        directory.configure_presence_sources(self.sources)
        self.stopped, self.apply_lock, self.attempt_lock = threading.Event(), threading.Lock(), threading.Lock()
        self.thread = None
        self.states = [{'id':source.id,'state':'idle','after':'','last_success':None} for source in self.sources]

    def status(self):
        with self.apply_lock:
            return {'state':'stopped' if self.stopped.is_set() else 'configured', 'sources':[dict(state) for state in self.states]}

    def sync_once(self):
        with self.attempt_lock:
            for source, status in zip(self.sources, self.states):
                try:
                    for _ in range(self.max_pages):
                        with self.apply_lock:
                            if self.stopped.is_set(): return self.status_unlocked()
                            after = status['after']
                        page = source.client.request('/v1/presence-export?'+urlencode({'after':after,'limit':20}))
                        with self.apply_lock:
                            if self.stopped.is_set(): return self.status_unlocked()
                            self.directory.apply_peer_presence(source, page, after)
                            status.update(after=page['next_after'], state='catching_up')
                            if not page['has_more']:
                                status.update(after='', state='synced', last_success=self.directory.clock())
                                break
                except (ValueError, OSError, KeyError, TypeError, sqlite3.Error):
                    with self.apply_lock:
                        if not self.stopped.is_set(): status['state'] = 'error'
            return self.status()

    def status_unlocked(self):
        return {'state':'stopped','sources':[dict(state) for state in self.states]}

    def run(self):
        while not self.stopped.is_set():
            self.sync_once()
            self.stopped.wait(self.interval)

    def start(self):
        with self.apply_lock:
            if self.stopped.is_set() or self.thread is not None: raise RuntimeError('presence synchronizer already started/stopped')
            self.thread = threading.Thread(target=self.run, daemon=True, name='presence-sync')
            self.thread.start()

    def stop(self):
        self.stopped.set()
        with self.apply_lock: pass  # No apply can continue past this point.
        if self.thread is not None: self.thread.join(timeout=5)


def read_peer_presence(client, owner, group, *, after='', limit=20):
    validate_page(after, limit)
    page = client.request('/v1/peer-presence?'+urlencode({'after':after,'limit':limit}))
    if (not isinstance(page,dict) or set(page) != {'owner','group_id','observed_at','policy','entries','has_more','next_after'} or
            page['owner'] != identity_id(owner) or page['group_id'] != group or not finite(page['observed_at']) or
            not isinstance(page['entries'],list) or len(page['entries']) > limit or type(page['has_more']) is not bool or
            not isinstance(page['policy'],dict) or page['policy'].get('state') not in ('missing','fresh','stale','future','dissolved')):
        raise AdmissionError('invalid merged presence response')
    cursor, now = after, time.time()
    for entry in page['entries']:
        if (not isinstance(entry,dict) or set(entry) != {'subject','state','head','observations'} or
                not isinstance(entry['subject'],str) or entry['subject'] <= cursor or entry['state'] not in MERGED_STATES or
                not isinstance(entry['observations'],list) or not 1 <= len(entry['observations']) <= 9):
            raise AdmissionError('invalid merged observation')
        cursor = entry['subject']
        head=entry['head']
        if (not isinstance(head,dict) or set(head) != {'generation','boot_id','sequence','token_hash','conflict'} or
                any(type(head[field]) is not int or not 1 <= head[field] <= MAX_COUNTER for field in ('generation','sequence')) or
                not isinstance(head['boot_id'],str) or not re.fullmatch(r'[a-f0-9]{32}',head['boot_id']) or
                not isinstance(head['token_hash'],str) or not re.fullmatch(r'[a-f0-9]{64}',head['token_hash']) or
                type(head['conflict']) is not bool or (entry['state']=='conflict') != head['conflict']):
            raise AdmissionError('invalid merged observation head')
        seen=set()
        for observation in entry['observations']:
            if (not isinstance(observation,dict) or set(observation) != {'source','subject','public_key','record','presence','state','expires_at','observed_at','received_at'} or
                    not isinstance(observation['source'],dict)):
                raise AdmissionError('invalid observation schema')
            source=observation['source']
            if (not isinstance(source.get('id'),str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',source['id']) or source['id'] in seen):
                raise AdmissionError('invalid observation source identity')
            seen.add(source['id'])
            if source['id']=='local':
                if source != {'id':'local','url':None,'fingerprint':None}:raise AdmissionError('invalid local source')
            elif (set(source) != {'id','url','group_id','fingerprint'} or source['group_id'] != group or
                    not isinstance(source['url'],str) or origin(source['url']) != source['url'] or
                    not isinstance(source['fingerprint'],str) or not re.fullmatch(r'[a-f0-9]{64}',source['fingerprint'])):
                raise AdmissionError('invalid configured source attribution')
            key = Ed25519PublicKey.from_public_bytes(decode(observation['public_key']))
            claims = verify_presence(observation['presence'],key,owner,group,observation['record'])
            if (claims['subject'] != cursor or observation['subject'] != cursor or observation['state'] not in MERGED_STATES or
                    not finite(observation['expires_at']) or observation['expires_at'] > claims['expires_at'] or
                    not finite(observation['observed_at']) or observation['observed_at'] > page['observed_at'] or
                    not finite(observation['received_at']) or observation['received_at'] > page['observed_at']):
                raise AdmissionError('invalid attributed presence')
            if observation['state'] in ('online','offline'):
                if (claims['state'] != observation['state'] or head['conflict'] or
                        any(claims[field] != head[field] for field in ('generation','boot_id','sequence')) or
                        hashlib.sha256(observation['presence'].encode()).hexdigest() != head['token_hash']):
                    raise AdmissionError('observation does not match merged head')
            if observation['state']=='online' and page['policy']['state']!='fresh':raise AdmissionError('online observation requires fresh local policy')
            if observation['state'] == 'online' and (now >= observation['expires_at'] or claims['issued_at'] > now+5): observation['state'] = 'expired'
        if entry['state'] in ('online','offline') and not any(observation['state']==entry['state'] for observation in entry['observations']):
            if entry['state']=='online':entry['state']='expired'
            else:raise AdmissionError('offline subject lacks an offline observation')
    if page['next_after'] != cursor or (page['has_more'] and not page['entries']): raise AdmissionError('invalid merged presence cursor')
    return page


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url',required=True)
    parser.add_argument('--authority-public-key',required=True)
    parser.add_argument('--group-id',required=True)
    parser.add_argument('--ca-cert')
    parser.add_argument('--after',default='')
    parser.add_argument('--limit',type=int,default=20)
    args = parser.parse_args()
    try:
        owner = Ed25519PublicKey.from_public_bytes(decode(Path(args.authority_public_key).read_text().strip()))
        client = Client(args.url,os.environ.get('TAILNET_VERIFIED_READ_TOKEN',''),timeout=2,ca_file=args.ca_cert)
        result = read_peer_presence(client,owner,args.group_id,after=args.after,limit=args.limit)
    except (ValueError,OSError,KeyError,TypeError):
        parser.exit(1,'Peer presence read failed; check configured origin, authority, group, credential and TLS.\n')
    print(json.dumps(result))


if __name__ == '__main__': main()
