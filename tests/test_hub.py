import importlib.util
import json
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch
import subprocess

spec = importlib.util.spec_from_file_location('hub', Path(__file__).parents[1] / 'hub.py')
hub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hub)

class HubTests(unittest.TestCase):
    def test_two_nodes_share_identity_but_block_to_their_own_ip(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / 'first'
            first.mkdir()
            with patch.object(hub, 'ROOT', first), patch.object(hub.socket, 'socket'), patch.object(hub, 'ask', side_effect=['', '8.8.8.8', '9.9.9.9', 'dns.example.com', 'admin@example.com', '8.8.8.8']):
                hub.setup()
                (first / 'tls').mkdir()
                subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                                '-subj', '/CN=dns.example.com', '-addext', 'subjectAltName=DNS:dns.example.com',
                                '-keyout', str(first / 'tls/key.pem'), '-out', str(first / 'tls/fullchain.pem')],
                               check=True, capture_output=True)
                hub.pairing_bundle()
                hub.render()
            second = Path(tmp) / 'second'
            second.mkdir()
            with patch.object(hub, 'ROOT', second), patch.object(hub.socket, 'socket'), patch.object(hub, 'ask', side_effect=[str(first / 'exports/dns-pairing.tar.gz'), '9.9.9.9']):
                hub.setup()
                hub.render()
            for name in ('ca.der', 'ca.p12', 'settings.json'):
                self.assertEqual((first / 'shared' / name).read_bytes(), (second / 'shared' / name).read_bytes())
            for name in ('key.pem', 'fullchain.pem'):
                self.assertEqual((first / 'tls' / name).read_bytes(), (second / 'tls' / name).read_bytes())
            profile_bytes = hub.profile(json.loads((first / 'shared/settings.json').read_text()), (first / 'shared/ca.der').read_bytes())
            profile = plistlib.loads(profile_bytes)
            dns = profile['PayloadContent'][1]['DNSSettings']
            self.assertEqual(dns['ServerAddresses'], ['8.8.8.8', '9.9.9.9'])
            self.assertEqual(dns['DNSProtocol'], 'HTTPS')
            self.assertNotIn(b'PRIVATE KEY', profile_bytes)
            subprocess.run(['openssl', 'verify', '-CAfile', str(first / 'shared/ca.crt'), str(first / 'shared/ca.crt')], check=True, capture_output=True)
            nodes = []
            for root in (first, second):
                nodes.append(json.loads((root / 'node.json').read_text()))
                self.assertIn('127.0.0.1:5380:5380', (root / 'compose.yaml').read_text())
                self.assertNotIn('"53:53', (root / 'compose.yaml').read_text())
            self.assertNotEqual(nodes[0]['public_ip'], nodes[1]['public_ip'])
            self.assertNotEqual(nodes[0]['admin_password'], nodes[1]['admin_password'])

    def test_apply_preserves_other_zones_and_sets_each_nodes_block_ip(self):
        class FakeAPI:
            zones = {'unrelated.example'}
            calls = []
            def call(self, path, **params):
                self.calls.append((path, params))
                if path == 'apps/list':
                    return {'response': {'apps': [{'name': 'Block Page'}]}}
                if path == 'zones/list':
                    return {'response': {'zones': [{'name': n} for n in self.zones]}}
                if path == 'zones/create':
                    self.zones.add(params['zone'])
                return {'status': 'ok'}
            def close(self):
                pass
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            hub.write(root / 'node.json', json.dumps({'public_ip': '8.8.8.8'}))
            hub.write(root / 'shared/settings.json', json.dumps({'proxy_ip': '1.1.1.1'}))
            with patch.object(hub, 'ROOT', root), patch.object(hub, 'API', FakeAPI):
                hub.apply()
                hub.apply()
            self.assertFalse(any(p == 'zones/delete' and a['zone'] == 'unrelated.example' for p, a in FakeAPI.calls))
            settings = [a for p, a in FakeAPI.calls if p == 'settings/set']
            self.assertEqual(settings[-1]['customBlockingAddresses'], '8.8.8.8')
            records = [a for p, a in FakeAPI.calls if p == 'zones/records/add']
            self.assertTrue(all(a['ipAddress'] == '45.88.89.23' and a['type'] == 'A' for a in records))
            self.assertTrue(any(a['domain'] == '*.googlevideo.com' for a in records))

    def test_single_node_setup_and_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(hub, 'ROOT', root), patch.object(hub.socket, 'socket'), patch.object(hub, 'ask', side_effect=['', '8.8.8.8', '', 'dns.example.com', 'admin@example.com', '8.8.8.8']):
                hub.setup()
                settings = hub.load(root/'shared/settings.json')
                self.assertEqual(settings['dns_ips'], ['8.8.8.8'])
                config = plistlib.loads(hub.profile(settings, (root/'shared/ca.der').read_bytes()))
                self.assertEqual(config['PayloadContent'][1]['DNSSettings']['ServerAddresses'], ['8.8.8.8'])

    def test_invalid_addresses_rejected(self):
        for addr in ['127.0.0.1', '192.168.1.5', '::1', 'not-an-ip']:
            with self.assertRaises(ValueError):
                hub.ipv4(addr)

if __name__ == '__main__':
    unittest.main()
