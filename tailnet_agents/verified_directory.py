"""Credential-enforced directory used by the separate admission HTTP service."""
import json
import hashlib
import math
import re
import threading
import time
import secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .identity import Admission, AdmissionError, REVOCATION_TYPE, decode, encode, identity_id, public_bytes, sign, verify, verify_grant
from .registry import Registry
from .group_policy import PolicyStore
from .discovery import make_announcement
from .presence import canonical_record, presence_context, verify_presence
from .peer_presence import PeerPresenceStore, unpack_entry, validate_export
from .runtime_monitor import validate_page


def issue_revocation(owner_key,group_id,credential_id):
    if not isinstance(credential_id,str) or not re.fullmatch(r'[a-f0-9]{32}',credential_id):
        raise AdmissionError('invalid credential id')
    return sign(owner_key,{'group_id':group_id,'jti':credential_id},REVOCATION_TYPE)


class VerifiedDirectory:
    def __init__(self,owner_key,group_id,audience,*,database=':memory:',clock=time.time,require_policy=False,policy_max_age=None):
        if policy_max_age is not None and (type(policy_max_age) is not int or not 1<=policy_max_age<=86400):
            raise ValueError('policy maximum age must be 1..86400 seconds')
        if policy_max_age is not None and not require_policy:
            raise AdmissionError('policy maximum age requires policy mode')
        self.owner_key,self.group_id,self.clock=owner_key,group_id,clock
        self.lock=threading.Lock()
        self._registry=Registry({},clock=clock,database=database)
        try:
            db=self._registry.db
            with db:
                db.execute('CREATE TABLE IF NOT EXISTS admission_context (id INTEGER PRIMARY KEY CHECK(id=1),owner_id TEXT NOT NULL,group_id TEXT NOT NULL)')
                existing=db.execute('SELECT owner_id,group_id FROM admission_context WHERE id=1').fetchone()
                expected=(identity_id(owner_key),group_id)
                if existing and existing!=expected:
                    raise AdmissionError('database authority/group mismatch')
                db.execute('INSERT OR IGNORE INTO admission_context VALUES(1,?,?)',expected)
                db.execute('CREATE TABLE IF NOT EXISTS admission_grants (agent_id TEXT PRIMARY KEY,token TEXT NOT NULL)')
                db.execute('CREATE TABLE IF NOT EXISTS agent_presence (subject TEXT PRIMARY KEY,generation INTEGER NOT NULL,boot_id TEXT NOT NULL,sequence INTEGER NOT NULL,token TEXT NOT NULL,public_key TEXT NOT NULL,record TEXT NOT NULL,expires REAL NOT NULL,observed REAL NOT NULL)')
                db.execute('CREATE TABLE IF NOT EXISTS admission_revocations (jti TEXT PRIMARY KEY,proof TEXT NOT NULL)')
                db.execute('CREATE TABLE IF NOT EXISTS revocation_generation (id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL)')
                db.execute('INSERT OR IGNORE INTO revocation_generation VALUES(1,?)',(secrets.token_hex(16),))
                db.execute('CREATE TABLE IF NOT EXISTS admission_policy_mode (id INTEGER PRIMARY KEY CHECK(id=1),required INTEGER NOT NULL)')
                mode=db.execute('SELECT required FROM admission_policy_mode WHERE id=1').fetchone()
                if mode and mode[0] and not require_policy:
                    raise AdmissionError('cannot disable persisted policy enforcement')
                db.execute('INSERT INTO admission_policy_mode VALUES(1,?) ON CONFLICT(id) DO UPDATE SET required=MAX(required,excluded.required)',(int(require_policy),))
                self.require_policy=bool(require_policy)
                db.execute('CREATE TABLE IF NOT EXISTS admission_policy_freshness (id INTEGER PRIMARY KEY CHECK(id=1),max_age INTEGER NOT NULL)')
                saved=db.execute('SELECT max_age FROM admission_policy_freshness WHERE id=1').fetchone()
                self.policy_max_age=policy_max_age if policy_max_age is not None else (saved[0] if saved else 300)
                if saved and self.policy_max_age>saved[0]:
                    raise AdmissionError('cannot weaken persisted policy freshness')
                if self.require_policy:
                    db.execute('INSERT INTO admission_policy_freshness VALUES(1,?) ON CONFLICT(id) DO UPDATE SET max_age=excluded.max_age',(self.policy_max_age,))
                self._policy=PolicyStore(db,owner_key,group_id,clock=clock,max_age=self.policy_max_age)
            revoked=[row[0] for row in db.execute('SELECT jti FROM admission_revocations')]
            self._admission=Admission(owner_key,group_id,audience,clock=clock,revoked=revoked)
            with db:
                self._peers=PeerPresenceStore(db)
                for token,public_key,record in db.execute('SELECT token,public_key,record FROM agent_presence'):
                    key=Ed25519PublicKey.from_public_bytes(decode(public_key))
                    self._peers.note(verify_presence(token,key,self.owner_key,self.group_id,json.loads(record)),token)
        except Exception:
            self._registry.close()
            raise

    def apply_policy(self,signed_policy):
        with self.lock:
            if not self.require_policy:
                raise AdmissionError('policy enforcement must be explicitly enabled')
            claims=self._policy.apply(signed_policy)
            return {'group_id':claims['group_id'],'revision':claims['revision'],'state':claims['state']}

    def export_policy(self):
        with self.lock:
            if not self.require_policy:
                raise AdmissionError('policy enforcement must be explicitly enabled')
            # Validate persisted data before sending it to another pinned verifier.
            self._policy.current()
            row=self._registry.db.execute('SELECT token FROM group_policy WHERE id=1').fetchone()
            return {'policy':None if row is None else row[0]}

    def policy_status(self):
        with self.lock:
            return self._policy.status() if self.require_policy else {'state':'disabled'}

    def discovery_announcement(self,key,endpoint,audience):
        with self.lock:
            if not self.require_policy:
                raise AdmissionError('policy mode required for candidate announcements')
            row=self._registry.db.execute('SELECT token FROM group_policy WHERE id=1').fetchone()
            if row is None:
                raise AdmissionError('existing signed group policy required')
            return make_announcement(key,row[0],self.owner_key,self.group_id,endpoint,audience,
                now=int(self.clock()),max_age=self.policy_max_age,revoked=self._admission.revoked)

    @staticmethod
    def record_context(record,presence=None):
        if not isinstance(record,dict) or 'id' in record:
            raise AdmissionError('identity is derived from the verified subject, not caller input')
        normalized=Registry.normalize_record(record|{'id':'pending'})
        del normalized['id']
        if presence is not None:
            return presence_context(record,presence)
        return hashlib.sha256(json.dumps(normalized,sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def challenge(self,record,presence=None):
        context=self.record_context(record,presence)
        with self.lock:
            return {'nonce':self._admission.challenge(context),'context':context}

    def register(self,grant_token,subject_key,proof,nonce,record,presence=None):
        with self.lock:
            # Metadata validation precedes consuming a valid single-use challenge.
            if not isinstance(record,dict) or 'id' in record:
                raise AdmissionError('identity is derived from the verified subject, not caller input')
            # Identity belongs to an Agent key, never its shared machine/IP/endpoint.
            agent_id='agent-'+identity_id(subject_key).split(':')[1]
            metadata=Registry.normalize_record(record|{'id':agent_id})
            context=self.record_context(record,presence)
            observed=None
            if presence is not None:
                if not self.require_policy:
                    raise AdmissionError('signed presence requires policy enforcement')
                observed=verify_presence(presence,subject_key,self.owner_key,self.group_id,record,now=self.clock())
            policy=None
            if self.require_policy:
                grant=verify_grant(grant_token,self.owner_key,self.group_id,now=self.clock(),revoked=self._admission.revoked)
                policy=self._policy.authorize(grant)
            grant=self._admission.admit(grant_token,subject_key,proof,nonce,context=context)
            old=self._registry.db.execute('SELECT generation,boot_id,sequence FROM agent_presence WHERE subject=?',(grant['sub'],)).fetchone()
            if old:
                if observed is None:
                    raise AdmissionError('cannot downgrade persisted signed presence to legacy registration')
                if observed['generation']<old[0] or (observed['generation']==old[0] and (observed['boot_id']!=old[1] or observed['sequence']<=old[2])):
                    raise FileExistsError('stale or conflicting runtime incarnation')
            lease_now=self.clock()
            remaining=math.floor(grant['exp']-lease_now)
            if policy is not None:
                remaining=min(remaining,math.floor(policy['issued_at']+self.policy_max_age-lease_now))
            offline=observed is not None and observed['state']=='offline'
            if remaining<10 and not offline:
                raise AdmissionError('authorization too close to expiry for a directory lease')
            if observed is not None and not offline:
                # The requested TTL is at least ten seconds, but transport consumes
                # its signed budget. Never round up or extend a signed deadline.
                remaining=min(remaining,math.floor(observed['expires_at']-lease_now))
                if remaining<1:
                    raise AdmissionError('presence too close to expiry for a directory lease')
            metadata['ttl_seconds']=0 if offline else min(metadata['ttl_seconds'],remaining)
            lease_expires=lease_now+metadata['ttl_seconds']
            if observed is not None:
                lease_expires=min(lease_expires,observed['expires_at'])
            registry=self._registry
            with registry.lock,registry.db:
                registry.db.execute('BEGIN IMMEDIATE')
                previous=registry.db.execute('SELECT owner FROM agents WHERE id=?',(agent_id,)).fetchone()
                if previous and previous[0]!=grant['sub']:
                    raise AdmissionError('identity ownership conflict')
                registry.db.execute('INSERT INTO agents(id,owner,expires,metadata) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET expires=excluded.expires,metadata=excluded.metadata',
                                    (agent_id,grant['sub'],lease_expires,json.dumps(metadata)))
                registry.db.execute('INSERT INTO admission_grants VALUES(?,?) ON CONFLICT(agent_id) DO UPDATE SET token=excluded.token',(agent_id,grant_token))
                if observed is not None:
                    expires=lease_expires
                    registry.db.execute('INSERT INTO agent_presence VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(subject) DO UPDATE SET generation=excluded.generation,boot_id=excluded.boot_id,sequence=excluded.sequence,token=excluded.token,public_key=excluded.public_key,record=excluded.record,expires=excluded.expires,observed=excluded.observed',
                        (grant['sub'],observed['generation'],observed['boot_id'],observed['sequence'],presence,encode(public_bytes(subject_key)),json.dumps(canonical_record(record)),expires,lease_now))
                    self._peers.note(observed,presence)
            result={'id':agent_id,'ttl_seconds':metadata['ttl_seconds']}
            if observed is not None:
                result['presence']={name:observed[name] for name in ('generation','boot_id','sequence','state')}|{'expires_at':expires}
            return result

    def presence_status(self,after='',limit=20,*,_include_grants=False):
        if (type(limit) is not int or not 1<=limit<=20 or not isinstance(after,str) or
                (after and not re.fullmatch(r'ed25519:[a-f0-9]{64}',after))):
            raise ValueError('invalid presence page')
        with self.lock:
            if not self.require_policy:
                raise AdmissionError('signed presence requires policy enforcement')
            db=self._registry.db
            rows=db.execute('SELECT subject,token,public_key,record,expires,observed FROM agent_presence WHERE subject>? ORDER BY subject LIMIT ?',(after,limit+1)).fetchall()
            entries=[]
            for subject,token,public_key,record,expires,observed_at in rows[:limit]:
                record=json.loads(record)
                key=Ed25519PublicKey.from_public_bytes(decode(public_key))
                claims=verify_presence(token,key,self.owner_key,self.group_id,record)
                if claims['subject']!=subject:raise AdmissionError('presence subject mismatch')
                agent_id='agent-'+subject.split(':')[1]
                lease=db.execute('SELECT expires FROM agents WHERE id=?',(agent_id,)).fetchone()
                expires=min(expires,claims['expires_at'],0 if lease is None else lease[0])
                try:
                    grant_row=db.execute('SELECT token FROM admission_grants WHERE agent_id=?',(agent_id,)).fetchone()
                    if grant_row is None:raise AdmissionError('missing credential')
                    grant=verify_grant(grant_row[0],self.owner_key,self.group_id,now=self.clock(),revoked=self._admission.revoked)
                    self._policy.authorize(grant)
                    state='offline' if claims['state']=='offline' else 'expired' if self.clock()>=expires or claims['issued_at']>self.clock()+5 else 'online'
                except AdmissionError:
                    state='unauthorized'
                entries.append({'id':agent_id,'subject':subject,'public_key':public_key,'record':record,
                                'presence':token,'state':state,'expires_at':expires,'observed_at':observed_at})
                if _include_grants:
                    if grant_row is None:raise AdmissionError('missing replication credential')
                    del entries[-1]['id']
                    entries[-1]['grant']=grant_row[0]
            return {'owner':identity_id(self.owner_key),'group_id':self.group_id,'observed_at':self.clock(),
                    'policy':self._policy.status(),'entries':entries,'has_more':len(rows)>limit,
                    'next_after':after if not entries else entries[-1]['subject']}

    def export_presence(self,after='',limit=20):
        # Only local direct observations are exported; copied data never loops.
        result=self.presence_status(after,limit,_include_grants=True)
        del result['policy']
        return result

    def configure_presence_sources(self,sources):
        with self.lock:
            if not self.require_policy:raise AdmissionError('presence sources require policy mode')
            self._peers.configure(sources,self.group_id)

    def apply_peer_presence(self,source,page,after=''):
        validate_page(after,20)
        with self.lock:
            if not self.require_policy:raise AdmissionError('presence replication requires policy mode')
            now=self.clock()
            rows=validate_export(page,self.owner_key,self.group_id,after,now)
            policy=self._policy.current()
            bounded=[]
            for entry,claims,grant in rows:
                entry=dict(entry)
                entry['expires_at']=min(entry['expires_at'],grant['exp'],0 if policy is None else policy['issued_at']+self.policy_max_age)
                try:
                    current=verify_grant(entry['grant'],self.owner_key,self.group_id,now=now,revoked=self._admission.revoked)
                    self._policy.authorize(current)
                    if entry['state']=='online' and now>=entry['expires_at']:entry['state']='expired'
                except AdmissionError:
                    entry['state']='unauthorized'
                bounded.append((entry,claims,grant))
            self._peers.apply(source,bounded,self.owner_key,self.group_id,now)

    def _peer_observation(self,source,entry,received):
        claims,_=unpack_entry(entry,self.owner_key,self.group_id)
        state=entry['state']
        expires=entry['expires_at']
        try:
            grant=verify_grant(entry['grant'],self.owner_key,self.group_id,now=self.clock(),revoked=self._admission.revoked)
            policy=self._policy.authorize(grant)
            expires=min(expires,grant['exp'],policy['issued_at']+self.policy_max_age)
            if state=='online' and (self.clock()>=expires or claims['issued_at']>self.clock()+5):state='expired'
        except AdmissionError:
            state='unauthorized'
        return ({'source':source,'subject':entry['subject'],'public_key':entry['public_key'],
                 'record':entry['record'],'presence':entry['presence'],'state':state,'expires_at':expires,
                 'observed_at':entry['observed_at'],'received_at':received},claims)

    def peer_presence_status(self,after='',limit=20):
        validate_page(after,limit)
        with self.lock:
            if not self.require_policy:raise AdmissionError('peer presence requires policy mode')
            db=self._registry.db
            subjects=self._peers.subjects(after,limit)
            entries=[]
            for subject in subjects[:limit]:
                observations=[]
                local=db.execute('SELECT token,public_key,record,expires,observed FROM agent_presence WHERE subject=?',(subject,)).fetchone()
                if local:
                    agent_id='agent-'+subject.split(':')[1]
                    grant=db.execute('SELECT token FROM admission_grants WHERE agent_id=?',(agent_id,)).fetchone()
                    lease=db.execute('SELECT expires FROM agents WHERE id=?',(agent_id,)).fetchone()
                    if grant is None or lease is None:raise AdmissionError('incomplete local observation')
                    key=Ed25519PublicKey.from_public_bytes(decode(local[1]))
                    claims=verify_presence(local[0],key,self.owner_key,self.group_id,json.loads(local[2]))
                    entry={'subject':subject,'presence':local[0],'public_key':local[1],'record':json.loads(local[2]),
                           'grant':grant[0],'expires_at':min(local[3],lease[0]),'observed_at':local[4],'state':claims['state']}
                    observations.append(self._peer_observation({'id':'local','url':None,'fingerprint':None},entry,local[4]))
                for source,entry,received in self._peers.remote(subject):
                    observations.append(self._peer_observation(source,entry,received))
                merged=self._peers.merge(subject,observations)
                # Whole subjects stay together; bound large multi-source responses.
                if entries and len(json.dumps(entries+[merged]).encode())>512*1024:break
                entries.append(merged)
            return {'owner':identity_id(self.owner_key),'group_id':self.group_id,'observed_at':self.clock(),
                    'policy':self._policy.status(),'entries':entries,'has_more':len(subjects)>len(entries),
                    'next_after':after if not entries else entries[-1]['subject']}

    def revoke(self,signed_revocation):
        with self.lock:
            claims=verify(signed_revocation,self.owner_key,REVOCATION_TYPE)
            if (set(claims)!={'group_id','jti'} or claims['group_id']!=self.group_id or
                not isinstance(claims['jti'],str) or not re.fullmatch(r'[a-f0-9]{32}',claims['jti'])):
                raise AdmissionError('invalid revocation scope')
            with self._registry.db:
                self._registry.db.execute('INSERT OR IGNORE INTO admission_revocations VALUES(?,?)',(claims['jti'],signed_revocation))
            self._admission.revoked.add(claims['jti'])

    def export_revocations(self,after=0,limit=100):
        if type(after) is not int or not 0<=after<=2**53-1 or type(limit) is not int or not 1<=limit<=100:
            raise ValueError('invalid revocation page')
        with self.lock:
            rows=self._registry.db.execute('SELECT rowid,proof FROM admission_revocations WHERE rowid>? ORDER BY rowid LIMIT ?',(after,limit+1)).fetchall()
            page=rows[:limit]
            generation=self._registry.db.execute('SELECT value FROM revocation_generation WHERE id=1').fetchone()[0]
            return {'generation':generation,'entries':[{'sequence':seq,'revocation':proof} for seq,proof in page],
                    'next_cursor':page[-1][0] if page else after,'has_more':len(rows)>limit}

    def discover(self,skill=None):
        with self.lock:
            records=self._registry.discover(skill)
            result=[]
            for record in records:
                row=self._registry.db.execute('SELECT token FROM admission_grants WHERE agent_id=?',(record['id'],)).fetchone()
                if row is None:
                    continue  # Raw registry entries do not become verified entries.
                try:
                    grant=verify_grant(row[0],self.owner_key,self.group_id,now=self.clock(),revoked=self._admission.revoked)
                    if self.require_policy:
                        self._policy.authorize(grant)
                    presence=self._registry.db.execute('SELECT token,public_key,record,expires FROM agent_presence WHERE subject=?',(grant['sub'],)).fetchone()
                    if presence is not None:
                        claims=verify_presence(presence[0],Ed25519PublicKey.from_public_bytes(decode(presence[1])),self.owner_key,self.group_id,json.loads(presence[2]),now=self.clock())
                        if claims['subject']!=grant['sub'] or claims['state']!='online' or self.clock()>=presence[3]:
                            continue
                except (ValueError,TypeError):
                    continue
                result.append(record)
            return result

    def close(self):
        with self.lock:
            self._registry.close()
