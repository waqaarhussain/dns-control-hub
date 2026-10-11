import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import hub
import certificate_sync

class CertificateTests(unittest.TestCase):
    def test_identity_validation_rejects_wrong_hostname_and_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('one', 'two'):
                subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                                '-subj', '/CN=dns.example.com', '-addext', 'subjectAltName=DNS:dns.example.com',
                                '-keyout', str(root/(name+'.key')), '-out', str(root/(name+'.crt'))],
                               check=True, capture_output=True)
            bundle = dict(key=(root/'one.key').read_text(), fullchain=(root/'one.crt').read_text())
            certificate_sync.validate(bundle, 'dns.example.com')
            with self.assertRaises(ValueError):
                certificate_sync.validate(bundle, 'other.example.com')
            with self.assertRaises(OSError):
                certificate_sync.validate(dict(bundle, key=(root/'two.key').read_text()), 'dns.example.com')

    def test_failed_reload_retains_certificate_for_retry_and_new_arrivals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hub.write(root/'shared/settings.json', json.dumps(dict(hostname='dns.example.com')))
            original = dict(key='new-key', fullchain='new-chain')
            incoming = dict(key='later-key', fullchain='later-chain')
            pending = root/'control/pending-certificate.json'
            hub.write(pending, json.dumps(original))
            calls = []
            def run(command, **kwargs):
                calls.append(command)
                if command[-1] == '-t':
                    hub.write(pending, json.dumps(incoming))
                    raise subprocess.CalledProcessError(1, command)
            with patch.object(hub, 'ROOT', root), patch.object(certificate_sync, 'validate'), patch.object(certificate_sync.subprocess, 'run', side_effect=run):
                with self.assertRaises(subprocess.CalledProcessError):
                    certificate_sync.apply_pending()
            self.assertEqual(hub.load(root/'control/processing-certificate.json'), original)
            self.assertEqual(hub.load(pending), incoming)
            with patch.object(hub, 'ROOT', root), patch.object(certificate_sync, 'validate'), patch.object(certificate_sync.subprocess, 'run') as run_mock, patch.object(hub, 'pairing_bundle'):
                certificate_sync.apply_pending()
                self.assertTrue(any(call.args[0][-2:] == ['-s', 'reload'] for call in run_mock.call_args_list))
            self.assertFalse((root/'control/processing-certificate.json').exists())
            self.assertEqual(hub.load(pending), incoming)
