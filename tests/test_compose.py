import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


class ComposeTests(unittest.TestCase):
    def run_piped_installer(self, wrapper, directory, legacy):
        # Simulate Compose exec attaching stdin and draining curl's script.
        docker = directory / 'docker'
        docker.write_text(
            '#!/bin/bash\n'
            'if [[ "$*" == "compose version" ]]; then\n'
            f'  exit {1 if legacy else 0}\n'
            'fi\n'
            'cat >/dev/null\n'
            'echo NGINX_CHECKED\n')
        docker.chmod(0o755)
        fallback = directory / 'docker-compose'
        fallback.write_text('#!/bin/bash\ncat >/dev/null\necho NGINX_CHECKED\n')
        fallback.chmod(0o755)
        script = f'bash {shlex.quote(str(wrapper))} exec -T doh nginx -t\necho RELOADED\n'
        return subprocess.run(
            ['bash'], input=script, text=True, capture_output=True, timeout=5,
            env={**os.environ, 'PATH': str(directory) + ':' + os.environ['PATH']})

    def test_piped_install_continues_after_compose_exec(self):
        wrapper = Path(__file__).parents[1] / 'compose.sh'
        for legacy in (False, True):
            with self.subTest(legacy=legacy), tempfile.TemporaryDirectory() as name:
                directory = Path(name)
                # Ensure this fixture reproduces the previous premature exit.
                old = directory / 'old-compose.sh'
                old.write_text(wrapper.read_text().replace(' </dev/null', ''))
                before = self.run_piped_installer(old, directory, legacy)
                self.assertEqual(before.returncode, 0, before.stderr)
                self.assertIn('NGINX_CHECKED', before.stdout)
                self.assertNotIn('RELOADED', before.stdout)
                after = self.run_piped_installer(wrapper, directory, legacy)
                self.assertEqual(after.returncode, 0, after.stderr)
                self.assertIn('NGINX_CHECKED', after.stdout)
                self.assertIn('RELOADED', after.stdout)
