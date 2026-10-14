"""Credential-enforced directory used by the separate admission HTTP service."""
import json
import hashlib
import math
import re
import threading
import time
import secrets
from .identity import Admission, AdmissionError, REVOCATION_TYPE, identity_id, sign, verify, verify_grant
from .registry import Registry
from .group_policy import PolicyStore
from .discovery import make_announcement


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
    def record_context(record):
        if not isinstance(record,dict) or 'id' in record:
            raise AdmissionError('identity is derived from the verified subject, not caller input')
        normalized=Registry.normalize_record(record|{'id':'pending'})
        del normalized['id']
        return hashlib.sha256(json.dumps(normalized,sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def challenge(self,record):
        context=self.record_context(record)
        with self.lock:
            return {'nonce':self._admission.challenge(context),'context':context}

    def register(self,grant_token,subject_key,proof,nonce,record):
        with self.lock:
            # Metadata validation precedes consuming a valid single-use challenge.
            if not isinstance(record,dict) or 'id' in record:
                raise AdmissionError('identity is derived from the verified subject, not caller input')
            # Identity belongs to an Agent key, never its shared machine/IP/endpoint.
            agent_id='agent-'+identity_id(subject_key).split(':')[1]
            metadata=Registry.normalize_record(record|{'id':agent_id})
            policy=None
            if self.require_policy:
                grant=verify_grant(grant_token,self.owner_key,self.group_id,now=self.clock(),revoked=self._admission.revoked)
                policy=self._policy.authorize(grant)
            grant=self._admission.admit(grant_token,subject_key,proof,nonce,context=self.record_context(record))
            remaining=math.floor(grant['exp']-self.clock())
            if policy is not None:
                remaining=min(remaining,math.floor(policy['issued_at']+self.policy_max_age-self.clock()))
            if remaining<10:
                raise AdmissionError('authorization too close to expiry for a directory lease')
            metadata['ttl_seconds']=min(metadata['ttl_seconds'],remaining)
            registry=self._registry
            with registry.lock,registry.db:
                registry.db.execute('BEGIN IMMEDIATE')
                previous=registry.db.execute('SELECT owner FROM agents WHERE id=?',(agent_id,)).fetchone()
                if previous and previous[0]!=grant['sub']:
                    raise AdmissionError('identity ownership conflict')
                registry.db.execute('INSERT INTO agents(id,owner,expires,metadata) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET expires=excluded.expires,metadata=excluded.metadata',
                                    (agent_id,grant['sub'],self.clock()+metadata['ttl_seconds'],json.dumps(metadata)))
                registry.db.execute('INSERT INTO admission_grants VALUES(?,?) ON CONFLICT(agent_id) DO UPDATE SET token=excluded.token',(agent_id,grant_token))
            return {'id':agent_id,'ttl_seconds':metadata['ttl_seconds']}

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
                except AdmissionError:
                    continue
                result.append(record)
            return result

    def close(self):
        with self.lock:
            self._registry.close()
