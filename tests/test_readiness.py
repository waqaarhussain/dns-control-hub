import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import stack

class ReadinessTests(unittest.TestCase):
    def test_tls_startup_disconnect_is_retried_with_certificate_checks(self):
        responses=[SimpleNamespace(returncode=35,stdout=b'',stderr=b'SSL_ERROR_SYSCALL'),SimpleNamespace(returncode=0,stdout=b'DNS Control Hub',stderr=b'')]
        with patch.object(stack.subprocess,'run',side_effect=responses) as run,patch.object(stack.time,'sleep') as sleep:
            stack.wait_ready('dns.example.com')
        self.assertEqual(run.call_count,2)
        sleep.assert_called_once_with(2)
        for call in run.call_args_list:
            self.assertNotIn('--insecure',call.args[0])
            self.assertNotIn('-k',call.args[0])
            self.assertNotIn('/dns/',str(call))
    def test_certificate_failure_is_not_hidden_as_startup_delay(self):
        with patch.object(stack.subprocess,'run',return_value=SimpleNamespace(returncode=60,stdout=b'',stderr=b'certificate verification failed')),patch.object(stack.time,'sleep') as sleep:
            with self.assertRaisesRegex(RuntimeError,'certificate verification failed'): stack.wait_ready('dns.example.com')
            sleep.assert_not_called()
    def test_persistent_failure_has_a_bounded_wait(self):
        with patch.object(stack.subprocess,'run',return_value=SimpleNamespace(returncode=35,stdout=b'',stderr=b'TLS backend closed')),patch.object(stack.time,'monotonic',side_effect=[0,0,61]),patch.object(stack.time,'sleep'):
            with self.assertRaisesRegex(RuntimeError,'within 60 seconds'): stack.wait_ready('dns.example.com')
