"""In-process credential-enforced directory, no HTTP endpoint or mesh transport."""
import json
import hashlib
import math
import re
import threading
import time
from .identity import Admission, AdmissionError, identity_id, sign, verify, verify_grant
from .registry import Registry

REVOCATION_TYPE='tailnet-agent-revocation+jwt'


def issue_revocation(owner_key,group_id,credential_id):
    if not isinstance(credential_id,str) or not re.fullmatch(r'[a-f0-9]{32}',credential_id):
        raise AdmissionError('invalid credential id')
    return sign(owner_key,{'group_id':group_id,'jti':credential_id},REVOCATION_TYPE)


class VerifiedDirectory:
    def __init__(self,owner_key,group_id,audience,*,database=':memory:',clock=time.time):
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
            revoked=[row[0] for row in db.execute('SELECT jti FROM admission_revocations')]
            self._admission=Admission(owner_key,group_id,audience,clock=clock,revoked=revoked)
        except Exception:
            self._registry.close()
            raise

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
            agent_id='agent-'+identity_id(subject_key).split(':')[1]
            metadata=Registry.normalize_record(record|{'id':agent_id})
            grant=self._admission.admit(grant_token,subject_key,proof,nonce,context=self.record_context(record))
            remaining=math.floor(grant['exp']-self.clock())
            if remaining<10:
                raise AdmissionError('credential too close to expiry for a directory lease')
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

    def discover(self,skill=None):
        with self.lock:
            records=self._registry.discover(skill)
            result=[]
            for record in records:
                row=self._registry.db.execute('SELECT token FROM admission_grants WHERE agent_id=?',(record['id'],)).fetchone()
                if row is None:
                    continue  # Raw registry entries do not become verified entries.
                try:
                    verify_grant(row[0],self.owner_key,self.group_id,now=self.clock(),revoked=self._admission.revoked)
                except AdmissionError:
                    continue
                result.append(record)
            return result

    def close(self):
        with self.lock:
            self._registry.close()
