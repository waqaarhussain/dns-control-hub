import json
from pathlib import Path
import secrets
import struct
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import hub
import devices
import profiles
import gateway
from test_gateway import GatewayTests, Upstream


class ProfileRulesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root_patch = patch.object(hub, 'ROOT', self.root)
        self.root_patch.start()
    def tearDown(self):
        self.root_patch.stop()
        self.temp.cleanup()
    def test_defaults_preserve_existing_filtering_and_separate_adults_kids(self):
        data = profiles.ensure()
        self.assertEqual(data['profiles']['default']['categories'], list(profiles.CATEGORIES))
        self.assertEqual(data['profiles']['adults']['categories'], ['ads_malware'])
        self.assertEqual(data['profiles']['kids']['categories'], list(profiles.CATEGORIES))
        self.assertEqual(profiles.ensure(), data)
    def test_url_normalization_and_domain_boundaries(self):
        self.assertEqual(profiles.normalize_site('https://WWW.Example.com:443/path?q=1'), 'www.example.com')
        self.assertEqual(profiles.normalize_site('bücher.de'), 'xn--bcher-kva.de')
        for site in ('https://user:secret@example.com', '127.0.0.1', 'example', 'ftp://example.com', '*.example.com'):
            with self.subTest(site=site), self.assertRaises(ValueError):
                profiles.normalize_site(site)
        policy = dict(categories=[], blocked_sites=['example.com'], allowed_sites=[])
        self.assertTrue(profiles.blocked('a.example.com', policy))
        self.assertFalse(profiles.blocked('notexample.com', policy))
    def test_allow_exception_and_more_specific_block(self):
        policy = dict(categories=[], blocked_sites=['example.com','bad.safe.example.com'], allowed_sites=['safe.example.com'])
        self.assertTrue(profiles.blocked('example.com',policy))
        self.assertFalse(profiles.blocked('safe.example.com',policy))
        self.assertTrue(profiles.blocked('bad.safe.example.com',policy))
    def test_stale_or_new_secondary_defaults_do_not_replace_edited_profiles(self):
        data = profiles.ensure()
        data['revision'] = 50
        data['profiles']['kids']['blocked_sites'] = ['example.com']
        profiles.merge(data)
        self.assertEqual(profiles.merge(profiles.initial())['profiles']['kids']['blocked_sites'], ['example.com'])
    def test_list_failure_keeps_last_good_file(self):
        directory = self.root / 'control/category-lists'
        directory.mkdir(parents=True)
        content = '\n'.join(f'domain{i}.example' for i in range(120)) + '\n'
        for name in profiles.CATEGORIES:
            (directory / (name + '.txt')).write_text(content)
        with patch.object(profiles.urllib.request, 'urlopen', side_effect=urllib.error.URLError('offline')):
            profiles.refresh_lists(force=True)
        for name in profiles.CATEGORIES:
            self.assertEqual((directory / (name + '.txt')).read_text(), content)
        (directory / 'adult.txt').unlink()
        with patch.object(profiles.urllib.request, 'urlopen', side_effect=urllib.error.URLError('offline')):
            with self.assertRaises(RuntimeError): profiles.refresh_lists(force=True)
    def test_new_device_selects_profile_and_exports_existing_token_shape(self):
        name = 'test-' + secrets.token_hex(8)
        with patch.object(hub, 'ask', side_effect=[name, '1', 'kids']), patch.object(devices, 'sync_peer'), patch.object(devices, 'sync_message'), patch.object(devices, 'export_device') as export:
            devices.new()
        item = export.call_args[0][0]
        self.assertTrue(devices.valid_device(item))
        self.assertEqual(item['profile'], 'kids')
        self.assertEqual(devices.snapshot()[item['id']]['token'], item['token'])
    def test_profile_menu_moves_legacy_device_without_replacing_token(self):
        item = dict(id=secrets.token_hex(32), name='Existing phone', slug='existing-phone', type='iOS', token=secrets.token_hex(32), download_token=secrets.token_hex(32), blocked=False, revision=10)
        devices.merge({item['id']: item})
        with patch.object(hub, 'ask', side_effect=['4', 'adults']), patch.object(devices, 'choose_device', return_value=item), patch.object(devices, 'sync_message'):
            profiles.manage()
        moved = devices.snapshot()[item['id']]
        self.assertEqual(moved['profile'], 'adults')
        self.assertEqual(moved['token'], item['token'])
        self.assertGreater(moved['revision'], item['revision'])
    def test_rule_helpers_are_scoped_and_allow_overrides_category(self):
        profiles.ensure()
        with patch.object(hub,'ask',side_effect=['https://example.com/path','kids']), patch.object(devices,'sync_message'):
            profiles.site_rule(True)
        data = profiles.snapshot()['profiles']
        self.assertIn('example.com',data['kids']['blocked_sites'])
        self.assertNotIn('example.com',data['adults']['blocked_sites'])
        with patch.object(hub,'ask',side_effect=['example.com','kids']), patch.object(devices,'sync_message'):
            profiles.site_rule(False)
        data = profiles.snapshot()['profiles']
        self.assertNotIn('example.com',data['kids']['blocked_sites'])
        self.assertIn('example.com',data['kids']['allowed_sites'])


class ProfileGatewayTests(GatewayTests):
    # Reuse the real HTTP gateway/upstream fixture, without rerunning base tests.
    def prepare(self):
        hub.write(self.root/'node.json', json.dumps(dict(public_ip='8.8.8.8')))
        directory = self.root / 'control/category-lists'
        directory.mkdir()
        for category in profiles.CATEGORIES:
            names = [f'{category}{i}.example' for i in range(100)]
            if category == 'gambling': names.append('bets.example')
            (directory / (category + '.txt')).write_text('\n'.join(names))
        policy = profiles.snapshot()
        policy['revision'] = 5
        profiles.merge(policy)
        self.device.update(profile='kids', revision=20)
        self.adult = dict(self.device, id=secrets.token_hex(32), token=secrets.token_hex(32), download_token=secrets.token_hex(32), profile='adults', name='Adult',slug='adult')
        devices.merge({d['id']:d for d in (self.device,self.adult)})
    def test_category_isolation_subdomains_and_allow_next_query(self):
        self.prepare()
        packet = hub.dns_query('www.bets.example')
        child = self.resolve(packet=packet)
        adult = self.resolve(token=self.adult['token'],packet=packet)
        self.assertTrue(child.endswith(bytes([8,8,8,8])))
        self.assertTrue(adult.endswith(bytes([93,184,216,34])))
        policy = profiles.snapshot()
        policy['revision'] += 1
        policy['profiles']['kids']['allowed_sites'] = ['bets.example']
        profiles.merge(policy)
        self.assertTrue(self.resolve(packet=packet).endswith(bytes([93,184,216,34])))
    def test_block_all_rr_types_no_ipv6_or_service_hint_bypass(self):
        self.prepare()
        for kind in (1,28,64,65,15,16,255):
            packet = hub.dns_query('bets.example')[:-4] + struct.pack('!HH',kind,1)
            answer = self.resolve(packet=packet)
            header = struct.unpack('!6H',answer[:12])
            self.assertEqual(header[3], 1 if kind == 1 else 0)
            self.assertEqual(header[1]&15, 0 if kind in (1,28,64,65) else 5)
        self.assertEqual(Upstream.requests,0)
    def test_policy_control_auth_and_stale_policy(self):
        self.prepare()
        current = profiles.snapshot()
        incoming = dict(current,revision=1)
        body = json.dumps(incoming).encode()
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.request('/control/policy',body)
        self.assertEqual(caught.exception.code,403)
        with self.request('/control/policy',body,{'Authorization':'Bearer '+self.settings['management_key']}) as response:
            self.assertEqual(json.load(response)['revision'],current['revision'])
    def test_missing_policy_or_category_fails_closed(self):
        self.prepare()
        (self.root/'control/category-lists/gambling.txt').unlink()
        self.assertEqual(struct.unpack('!6H',self.resolve()[:12])[1]&15,2)
        (self.root/'control/profiles.json').unlink()
        self.assertEqual(struct.unpack('!6H',self.resolve()[:12])[1]&15,2)
        self.assertEqual(Upstream.requests,0)
    def test_move_device_preserves_token_and_changes_next_query(self):
        self.prepare()
        token = self.device['token']
        packet = hub.dns_query('bets.example')
        self.assertTrue(self.resolve(packet=packet).endswith(bytes([8,8,8,8])))
        self.device.update(profile='adults',revision=21)
        devices.merge({self.device['id']:self.device})
        self.assertEqual(self.device['token'],token)
        self.assertTrue(self.resolve(packet=packet).endswith(bytes([93,184,216,34])))


class WireResponseTests(unittest.TestCase):
    def test_ttl_zero_preserves_edns_flags_and_filters_compressed_cname(self):
        request = hub.dns_query('alias.example')
        target = b'\x04bets\xc0\x12'  # suffix points to example in the question
        cname = b'\xc0\x0c' + struct.pack('!HHIH',5,1,3600,len(target)) + target
        opt = b'\0' + struct.pack('!HHIH',41,1232,0x8000,0)
        answer = struct.pack('!6H',4567,0x8180,1,1,0,1) + request[12:] + cname + opt
        policy = dict(categories=[],blocked_sites=['bets.example'],allowed_sites=[])
        output, denied = gateway.filter_answer(answer, request, policy)
        self.assertTrue(denied)
        offset = len(request)+2
        self.assertEqual(struct.unpack('!I',output[offset+4:offset+8])[0],0)
        self.assertEqual(output[-6:-2],struct.pack('!I',0x8000))
    def test_name_compression_loop_rejected(self):
        with self.assertRaises(ValueError): gateway.read_name(b'\xc0\0',0)

# unittest otherwise discovers imported base tests twice and inherited tests again.
for name in list(vars(GatewayTests)):
    if name.startswith('test_'):
        setattr(ProfileGatewayTests,name,None)
del GatewayTests
