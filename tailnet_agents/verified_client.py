"""Optional client for the verified admission HTTP service."""
import argparse
import json
import os
from pathlib import Path
from urllib.error import URLError
from .client import Client
from .identity import encode,load_identity,prove_possession,public_bytes


class VerifiedClient:
    def __init__(self,url,agent_key,grant,audience,read_token='',ca_file=None):
        self.client=Client(url,read_token,ca_file=ca_file)
        self.agent_key,self.grant,self.audience=agent_key,grant,audience

    def register(self,record):
        challenge=self.client.request('/v1/challenges',{'record':record})
        proof=prove_possession(self.agent_key,self.grant,challenge['nonce'],self.audience,context=challenge['context'])
        return self.client.request('/v1/registrations',{
            'record':record,'grant':self.grant,'public_key':encode(public_bytes(self.agent_key.public_key())),
            'proof':proof,'nonce':challenge['nonce']})

    def discover(self):
        return self.client.request('/v1/agents')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url',required=True)
    parser.add_argument('--agent-key',required=True)
    parser.add_argument('--grant-file',required=True)
    parser.add_argument('--record-file',required=True)
    parser.add_argument('--audience',required=True)
    parser.add_argument('--ca-cert',help='trusted private CA certificate PEM; default system trust')
    args=parser.parse_args()
    try:
        client=VerifiedClient(args.url,load_identity(args.agent_key),Path(args.grant_file).read_text().strip(),args.audience,
                              os.environ.get('TAILNET_VERIFIED_READ_TOKEN',''),ca_file=args.ca_cert)
        result=client.register(json.loads(Path(args.record_file).read_text()))
    except (ValueError,OSError,URLError):
        parser.exit(1,'Verified registration failed; check credentials, grant lifetime and connectivity.\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
