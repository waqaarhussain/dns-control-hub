import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import hub

class ConsoleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root_patch = patch.object(hub, 'ROOT', self.root)
        self.root_patch.start()
        hub.write(self.root/'node.json', json.dumps(dict(public_ip='8.8.8.8', admin_password='old-test-password')))
        hub.write(self.root/'shared/settings.json', json.dumps(dict(hostname='dns.example.com', dns_ips=['8.8.8.8'])))
    def tearDown(self):
        self.root_patch.stop(); self.temp.cleanup()
    def test_password_required_before_console_routes_are_exposed(self):
        hub.render()
        self.assertNotIn('set $console dns:5380;', (self.root/'nginx.conf').read_text())
        with patch.object(hub.getpass, 'getpass', side_effect=['short', 'short']), patch.object(hub, 'API') as api:
            with self.assertRaises(ValueError):
                hub.console()
            api.assert_not_called()
        self.assertFalse(hub.load(self.root/'node.json').get('console_ready'))
    def test_password_change_and_automation_token_enable_console(self):
        password = 'chosen-test-password'
        with patch.object(hub.getpass, 'getpass', side_effect=[password, password]), patch.object(hub, 'API') as api:
            api.return_value.call.return_value = {'token':'private-test-api-token'}
            hub.console()
            api.assert_called_once_with(force_login=True)
            api.return_value.call.assert_any_call('user/changePassword', **{'pass':'old-test-password', 'newPass':password})
        self.assertEqual((self.root/'admin-api-token').read_text(), 'private-test-api-token')
        self.assertEqual((self.root/'admin-api-token').stat().st_mode & 0o777, 0o600)
        self.assertNotIn('private-test-api-token', (self.root/'node.json').read_text())
        hub.render()
        nginx = (self.root/'nginx.conf').read_text()
        self.assertIn('set $console dns:5380;', nginx)
        self.assertIn('location = /api/user/login', nginx)
        self.assertIn('set $backend api:8080;', nginx)
        self.assertNotIn(password, nginx)
        compose = (self.root/'compose.yaml').read_text()
        self.assertIn('127.0.0.1:5380:5380', compose)
        self.assertNotIn('admin-api-token:', compose)
        with patch.object(hub.getpass, 'getpass') as prompt:
            hub.console()
            prompt.assert_not_called()
    def test_policy_api_uses_token_without_login_or_logout(self):
        hub.write(self.root/'admin-api-token', 'private-test-api-token')
        with patch.object(hub.API, 'call') as call:
            api = hub.API()
            self.assertEqual(api.token, 'private-test-api-token')
            api.close()
            call.assert_not_called()

    def test_deployment_rejects_anonymously_accessible_settings(self):
        with patch.object(hub.subprocess, 'check_output', side_effect=[b'<html>login</html>', b'{"status":"ok"}']):
            with self.assertRaises(RuntimeError):
                hub.check_console('dns.example.com')
        with patch.object(hub.subprocess, 'check_output', side_effect=[b'<html>login</html>', b'{"status":"invalid-token"}']) as curl:
            hub.check_console('dns.example.com')
            for call in curl.call_args_list:
                self.assertNotIn('--insecure', call.args[0])
                self.assertFalse(any('Authorization' in arg for arg in call.args[0]))
