import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import admin
import devices
import hub
import profiles
from test_gateway import GatewayTests

class ConsoleSetupTests(unittest.TestCase):
    def test_migration_retains_password_without_technitium_api(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(hub,'ROOT',Path(directory)):
            hub.write(hub.ROOT/'node.json',json.dumps(dict(public_ip='8.8.8.8',admin_password='existing-password',console_ready=True)))
            admin.setup()
            self.assertTrue(admin.matches('existing-password',hub.load(hub.ROOT/'control/admin-auth.json')))
            self.assertNotIn('admin_password',hub.load(hub.ROOT/'node.json'))
            self.assertEqual((hub.ROOT/'control/admin-auth.json').stat().st_mode&0o777,0o600)
            with patch.object(admin.getpass,'getpass') as prompt:
                admin.setup();prompt.assert_not_called()
    def test_new_account_requires_matching_password(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(hub,'ROOT',Path(directory)):
            hub.write(hub.ROOT/'node.json',json.dumps(dict(public_ip='8.8.8.8')))
            with patch.object(admin.getpass,'getpass',side_effect=['short']):
                with self.assertRaises(ValueError): admin.setup()
            self.assertFalse((hub.ROOT/'control/admin-auth.json').exists())

class ConsoleHTTPTests(GatewayTests):
    def setUp(self):
        super().setUp()
        hub.write(self.root/'node.json',json.dumps(dict(public_ip='8.8.8.8',admin_password='existing-password',console_ready=True)))
        admin.setup()
        with admin.lock:
            admin.sessions.clear();admin.failures.clear()
        self.peer_patch=patch.object(devices,'sync_peer',return_value=False);self.peer_patch.start()
    def tearDown(self):
        self.peer_patch.stop();super().tearDown()
    def login(self):
        headers={'Content-Type':'application/json','Origin':'https://dns.example.com'}
        with self.request('/api/console/login',json.dumps(dict(username='admin',password='existing-password')).encode(),headers) as response:
            self.cookie=response.headers['Set-Cookie'].split(';',1)[0];self.csrf=json.load(response)['csrf']
            self.assertIn('HttpOnly',response.headers['Set-Cookie']);self.assertIn('Secure',response.headers['Set-Cookie'])
    def post(self,path,data,csrf=True,origin=True):
        headers={'Content-Type':'application/json','Cookie':self.cookie}
        if csrf: headers['X-CSRF-Token']=self.csrf
        if origin: headers['Origin']='https://dns.example.com'
        return self.request('/api/console/'+path,json.dumps(data).encode(),headers)
    def test_console_state_requires_login_and_excludes_management_secrets(self):
        with self.assertRaises(urllib.error.HTTPError) as error: self.request('/api/console/state')
        self.assertEqual(error.exception.code,401)
        self.login()
        with self.request('/api/console/state',headers={'Cookie':self.cookie}) as response: state=json.load(response)
        self.assertNotIn(self.settings['management_key'],json.dumps(state))
        self.assertNotIn(self.device['token'],json.dumps(state))
        self.assertIn(self.device['download_token'],json.dumps(state))
    def test_csrf_and_origin_required(self):
        self.login()
        for csrf,origin in [(False,True),(True,False)]:
            with self.assertRaises(urllib.error.HTTPError) as error: self.post('device/update',dict(id=self.device['id'],blocked=True),csrf,origin)
            self.assertEqual(error.exception.code,403)
        self.assertFalse(devices.snapshot()[self.device['id']]['blocked'])
    def test_device_site_and_profile_controls_share_helper_state(self):
        self.login()
        with self.post('profile/save',dict(name='Family',categories=[])) as response: self.assertTrue(json.load(response)['ok'])
        with self.post('device/update',dict(id=self.device['id'],profile='family',blocked=True)): pass
        item=devices.snapshot()[self.device['id']]
        self.assertEqual(item['profile'],'family');self.assertTrue(item['blocked']);self.assertEqual(item['token'],self.device['token'])
        with self.post('site',dict(site='https://example.com/path',profiles=['family'],mode='block')): pass
        self.assertIn('example.com',profiles.snapshot()['profiles']['family']['blocked_sites'])
        with self.post('site',dict(site='example.com',profiles=['family'],mode='allow')): pass
        self.assertIn('example.com',profiles.snapshot()['profiles']['family']['allowed_sites'])
        with self.post('device/new',dict(name='Second phone',type='iOS',profile='family')): pass
        self.assertEqual(len(devices.snapshot()),2)
    def test_password_change_invalidates_sessions(self):
        self.login()
        with self.post('password',dict(current='existing-password',password='new-password-1234')): pass
        self.assertTrue(admin.matches('new-password-1234',hub.load(self.root/'control/admin-auth.json')))
        with self.assertRaises(urllib.error.HTTPError) as error: self.request('/api/console/state',headers={'Cookie':self.cookie})
        self.assertEqual(error.exception.code,401)
    def test_login_rate_limit_and_secondary_cannot_mutate(self):
        for _ in range(5):
            with self.assertRaises(urllib.error.HTTPError): self.request('/api/console/login',json.dumps(dict(username='admin',password='wrong')).encode(),{'Origin':'https://dns.example.com'})
        with self.assertRaises(urllib.error.HTTPError) as error: self.request('/api/console/login',json.dumps(dict(username='admin',password='existing-password')).encode(),{'Origin':'https://dns.example.com'})
        self.assertEqual(error.exception.code,429)
        admin.failures.clear();self.login()
        hub.write(self.root/'node.json',json.dumps(dict(public_ip='9.9.9.9')))
        with self.assertRaises(urllib.error.HTTPError): self.post('device/update',dict(id=self.device['id'],blocked=True))
        self.assertFalse(devices.snapshot()[self.device['id']]['blocked'])
    def test_static_dashboard_contains_no_demo_data(self):
        with self.request('/') as response:
            page=response.read();self.assertIn(b'DNS Control Hub',page);self.assertIn(b'login-form',page)
        with self.assertRaises(urllib.error.HTTPError): self.request('/assets/../node.json')

for name in list(vars(GatewayTests)):
    if name.startswith('test_'): setattr(ConsoleHTTPTests,name,None)
del GatewayTests
