"""Optional Ed25519 identity and scoped admission primitives.

This module is not wired into the UI, registry or network mesh yet.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

GRANT_TYPE = 'tailnet-agent-grant+jwt'
PROOF_TYPE = 'tailnet-agent-proof+jwt'
PERMISSIONS = frozenset({'join','discover','chat.group','chat.direct','task.echo'})


class AdmissionError(ValueError):
    pass


def encode(data):
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def decode(text):
    if not isinstance(text,str) or not re.fullmatch(r'[A-Za-z0-9_-]+',text):
        raise AdmissionError('invalid base64url')
    try:
        data=base64.b64decode(text+'='*((-len(text))%4),altchars=b'-_',validate=True)
    except ValueError as exc:
        raise AdmissionError('invalid base64url') from exc
    if encode(data)!=text:
        raise AdmissionError('noncanonical base64url')
    return data


def public_bytes(key):
    return key.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)


def identity_id(key):
    return 'ed25519:'+hashlib.sha256(public_bytes(key)).hexdigest()


def generate_identity(path):
    """Create without overwrite; private key is local plaintext PEM, mode 0600."""
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    key=Ed25519PrivateKey.generate()
    data=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,'wb') as output:
        output.write(data)
    return key


def load_identity(path):
    key=serialization.load_pem_private_key(Path(path).read_bytes(),password=None)
    if not isinstance(key,Ed25519PrivateKey):
        raise AdmissionError('Ed25519 identity required')
    return key


def sign(key, payload, kind):
    header={'alg':'EdDSA','typ':kind,'kid':identity_id(key.public_key())}
    parts=[encode(json.dumps(item,sort_keys=True,separators=(',',':'),allow_nan=False).encode()) for item in (header,payload)]
    data='.'.join(parts)
    return data+'.'+encode(key.sign(data.encode()))


def unique_object(pairs):
    value={}
    for name,item in pairs:
        if name in value:
            raise AdmissionError('duplicate JSON field')
        value[name]=item
    return value


def verify(token,key,kind):
    if not isinstance(token,str) or len(token)>16384:
        raise AdmissionError('invalid signed message size')
    parts=token.split('.')
    if len(parts)!=3:
        raise AdmissionError('invalid JWS')
    try:
        header=json.loads(decode(parts[0]),object_pairs_hook=unique_object)
        if header!={'alg':'EdDSA','typ':kind,'kid':identity_id(key)}:
            raise AdmissionError('wrong algorithm, type or trusted issuer')
        key.verify(decode(parts[2]),'.'.join(parts[:2]).encode())
        payload=json.loads(decode(parts[1]),object_pairs_hook=unique_object)
        if not isinstance(payload,dict):
            raise AdmissionError('payload must be an object')
        return payload
    except (InvalidSignature,UnicodeError,ValueError) as exc:
        raise AdmissionError('signed message verification failed') from exc


def issue_grant(owner_key,subject_key,group_id,permissions,*,now=None,lifetime=3600):
    now=int(time.time()) if now is None else now
    if type(now) is not int or type(lifetime) is not int or not 1<=lifetime<=86400:
        raise AdmissionError('invalid grant lifetime')
    if not isinstance(group_id,str) or not 1<=len(group_id)<=128:
        raise AdmissionError('invalid group id')
    if not isinstance(permissions,list) or any(not isinstance(p,str) or p not in PERMISSIONS for p in permissions) or 'join' not in permissions:
        raise AdmissionError('invalid grant permissions')
    payload={'iss':identity_id(owner_key.public_key()),'sub':identity_id(subject_key),
             'group_id':group_id,'permissions':sorted(set(permissions)),
             'iat':now,'nbf':now,'exp':now+lifetime,'jti':secrets.token_hex(16)}
    return sign(owner_key,payload,GRANT_TYPE)


def verify_grant(token,owner_key,group_id,permission='join',*,now=None,revoked=()):
    now=time.time() if now is None else now
    grant=verify(token,owner_key,GRANT_TYPE)
    expected={'iss','sub','group_id','permissions','iat','nbf','exp','jti'}
    if set(grant)!=expected or any(type(grant[k]) is not int for k in ('iat','nbf','exp')):
        raise AdmissionError('invalid grant claims')
    if grant['iss']!=identity_id(owner_key) or grant['group_id']!=group_id:
        raise AdmissionError('wrong issuer or group')
    if not isinstance(grant['sub'],str) or not re.fullmatch(r'ed25519:[a-f0-9]{64}',grant['sub']):
        raise AdmissionError('invalid subject')
    if not isinstance(grant['jti'],str) or not re.fullmatch(r'[a-f0-9]{32}',grant['jti']):
        raise AdmissionError('invalid grant id')
    permissions=grant['permissions']
    if not isinstance(permissions,list) or len(permissions)>len(PERMISSIONS) or any(not isinstance(p,str) or p not in PERMISSIONS for p in permissions) or len(set(permissions))!=len(permissions):
        raise AdmissionError('invalid permissions')
    if not grant['iat']==grant['nbf'] or not 0<grant['exp']-grant['iat']<=86400 or not grant['nbf']<=now<grant['exp']:
        raise AdmissionError('grant expired or not yet valid')
    if grant['jti'] in revoked or 'join' not in permissions or permission not in permissions:
        raise AdmissionError('grant revoked or permission denied')
    return grant


def prove_possession(agent_key,grant_token,nonce,audience,context=None):
    payload={'sub':identity_id(agent_key.public_key()),'nonce':nonce,'aud':audience,
             'grant_hash':hashlib.sha256(grant_token.encode()).hexdigest()}
    if context is not None:
        payload['context']=context
    return sign(agent_key,payload,PROOF_TYPE)


class Admission:
    """Single-threaded admission engine. Challenges expire and are single-use.

    Caller supplies trusted owner key and revocation set; no distributed
    revocation delivery or cryptographic channel binding is implemented.
    """
    def __init__(self,owner_key,group_id,audience,clock=time.time,revoked=()):
        self.owner_key,self.group_id,self.audience=owner_key,group_id,audience
        self.clock,self.revoked=clock,set(revoked)
        self.challenges={}

    def challenge(self,context=None):
        now=self.clock()
        self.challenges={n:item for n,item in self.challenges.items() if item[0]>now}
        if len(self.challenges)>=256:
            raise AdmissionError('challenge capacity reached')
        nonce=secrets.token_urlsafe(32)
        self.challenges[nonce]=(now+30,context)
        return nonce

    def admit(self,grant_token,subject_key,proof,nonce,permission='join',context=None):
        challenge=self.challenges.get(nonce)
        if challenge is None or challenge[0]<=self.clock():
            raise AdmissionError('unknown, expired or consumed challenge')
        if challenge[1]!=context:
            raise AdmissionError('challenge context mismatch')
        grant=verify_grant(grant_token,self.owner_key,self.group_id,permission,now=self.clock(),revoked=self.revoked)
        if grant['sub']!=identity_id(subject_key):
            raise AdmissionError('wrong subject key')
        claim=verify(proof,subject_key,PROOF_TYPE)
        expected={'sub':grant['sub'],'nonce':nonce,'aud':self.audience,
                  'grant_hash':hashlib.sha256(grant_token.encode()).hexdigest()}
        if context is not None:
            expected['context']=context
        if claim!=expected:
            raise AdmissionError('proof scope mismatch')
        del self.challenges[nonce]
        return grant
