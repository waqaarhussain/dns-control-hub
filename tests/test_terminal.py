import fcntl
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import termios
import time
import unittest

class TerminalTests(unittest.TestCase):
    def test_prompt_uses_controlling_terminal_with_piped_stdin(self):
        master, slave = pty.openpty()
        def attach_terminal():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        process = None
        try:
            process = subprocess.Popen(
                [sys.executable, '-c', "import hub; print('ANSWER=' + hub.ask('DNS hostname'))"],
                cwd=Path(__file__).parents[1], stdin=subprocess.PIPE, stdout=slave, stderr=slave,
                pass_fds=(slave,), preexec_fn=attach_terminal)
            output = b''
            deadline = time.monotonic() + 5
            while b'DNS hostname: ' not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    output += os.read(master, 4096)
            self.assertIn(b'DNS hostname: ', output)
            os.write(master, b'dns.example.com\n')
            self.assertEqual(process.wait(timeout=5), 0)
            while select.select([master], [], [], 0.1)[0]:
                output += os.read(master, 4096)
            self.assertIn(b'ANSWER=dns.example.com', output)
        finally:
            if process is not None:
                if process.poll() is None:
                    process.kill(); process.wait()
                process.stdin.close()
            os.close(master); os.close(slave)
