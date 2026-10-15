"""Reference contracts and offline product inventory work without identity extras."""
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch
from tailnet_agents.adapters import EchoAdapter, catalog, contract_hash, echo_contract, validate_contract


class AdapterContractTests(unittest.TestCase):
    def test_echo_preserves_multibyte_text_and_enforces_wire_byte_limit(self):
        echo=EchoAdapter();text='界'*682+'ab'
        self.assertEqual(len(text.encode()),2048);self.assertEqual(echo(text),text)
        for invalid in ('',text+'a',None,42,{'text':'hello'}):
            with self.subTest(invalid=type(invalid).__name__),self.assertRaises(ValueError):echo(invalid)

    def test_contract_rejects_unsupported_execution_scope_and_non_strict_types(self):
        for mutation in ({'version':True},{'automatic_retry':0},{'permission':'task.run'},
                         {'product':'codex'},{'side_effects':'filesystem'},{'input_max_bytes':2048.0},
                         {'adapter_id':'other'},{'extra':'field'}):
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):validate_contract(echo_contract()|mutation)

    def test_returned_contracts_and_catalog_cannot_mutate_reference_semantics(self):
        before=contract_hash(echo_contract());value=echo_contract();value['automatic_retry']=True
        listing=catalog();listing['entries'][0]['contract']['permission']='task.run'
        self.assertEqual(contract_hash(echo_contract()),before)
        self.assertEqual(validate_contract(echo_contract())['permission'],'task.echo')

    def test_catalog_neither_scans_installations_nor_launches_products_or_network(self):
        with patch.object(socket,'create_connection',side_effect=AssertionError('network')),\
             patch.object(subprocess,'Popen',side_effect=AssertionError('product launch')),\
             patch('os.scandir',side_effect=AssertionError('installation scan')):
            listing=catalog()
        real=listing['entries'][1:]
        self.assertTrue(all(row['implementation']=='not_implemented' and row['interface_validation']=='not_run' for row in real))
        grok={row['product']:row['kind'] for row in real}
        self.assertEqual(grok['grok-agent'],'product_agent');self.assertEqual(grok['grok-model-api'],'model_api')

    def test_catalog_subprocess_needs_no_site_packages_and_emits_only_json(self):
        result=subprocess.run([sys.executable,'-S','-m','tailnet_agents.adapters','catalog'],
            cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stderr,'')
        self.assertEqual(json.loads(result.stdout),catalog())
