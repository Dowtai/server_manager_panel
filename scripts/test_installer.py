#!/usr/bin/env python3
"""Offline installer smoke tests. Docker/apt/network are replaced; no host services are changed."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parent.parent


class InstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="awg-check-test-")
        cls.helper = Path(cls.build.name) / "check"
        subprocess.run(["go", "build", "-o", str(cls.helper), "./cmd/check"], cwd=REPO, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="awg-installer-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "deploy").mkdir()
        shutil.copy(REPO / "compose.yml", self.root / "compose.yml")
        shutil.copy(REPO / "deploy/compose.installer.yml", self.root / "deploy/compose.installer.yml")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "commands.jsonl"
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        INSTALLER_ROOT=str(self.root), INSTALLER_LOG=str(self.log),
                        INSTALLER_CHECK=str(self.helper))
        self.executable("docker", '''#!/usr/bin/env python3
import sys,os,json,pathlib,subprocess
args=sys.argv[1:]
with open(os.environ['INSTALLER_LOG'],'a') as f: f.write(json.dumps(args)+'\\n')
if args[:2]==['image','inspect']: print('sha256:'+'a'*64)
elif args[:2]==['image','save']: pathlib.Path(args[args.index('-o')+1]).write_bytes(b'archive-for-test')
elif args and args[0]=='run' and '--entrypoint' in args and args[args.index('--entrypoint')+1]=='check':
 sys.exit(subprocess.run([os.environ['INSTALLER_CHECK'],'install']).returncode)
elif args[:3]==['volume','ls','-q'] and os.environ.get('EXISTING_VOLUME'): print('awg-panel_postgres')
''')
        self.executable("getent", "#!/bin/sh\nprintf '192.0.2.1 STREAM example\\n'\n")
        self.executable("ss", "#!/bin/sh\nif [ -n \"$BUSY_PORT\" ]; then echo LISTEN; fi\n")
        self.executable("flock", "#!/bin/sh\nexit 0\n")
        self.executable("sha256sum", '''#!/usr/bin/env python3
import hashlib,sys
p=sys.argv[1]
print(hashlib.sha256(open(p,'rb').read()).hexdigest()+'  '+p)
''')
        self.executable("curl", '''#!/usr/bin/env python3
import sys,json,os
args=sys.argv[1:]
with open(os.environ['INSTALLER_LOG'],'a') as f: f.write(json.dumps(['curl']+args)+'\\n')
assert '--resolve' in args and '--insecure' not in args and '-k' not in args
sys.exit(1 if os.environ.get('HTTPS_FAIL') else 0)
''')

    def executable(self, name, content):
        p = self.bin / name
        p.write_text(content)
        p.chmod(0o755)

    def install(self, answers="", **extra):
        # Only test scaffolding overrides host/root/package checks. Production has no bypass flag.
        script = f'''source {str(REPO / 'install.sh')!r}
INSTALL_ROOT="$INSTALLER_ROOT"
require_host() {{ :; }}
ensure_dependencies() {{ :; }}
if [[ ${{HTTPS_FAIL:-}} == 1 ]]; then sleep() {{ SECONDS=$((SECONDS + 301)); }}; fi
main
'''
        return subprocess.run(["bash", "-c", script], input=answers, text=True,
                              capture_output=True, env=dict(self.env, **extra), timeout=30)

    def test_first_install_and_retry_preserve_secrets(self):
        password = "a-test-password-123456"
        answers = f"operator\n{password}\n{password}\n9443\npanel.example.org\nops@example.org\ny\n"
        first = self.install(answers)
        self.assertEqual(first.returncode, 0, first.stderr)
        config = (self.root / ".env").read_bytes()
        self.assertNotIn(password.encode(), config)
        self.assertIn(b"ADMIN_USERNAME='operator'", config)
        self.assertIn(b"PUBLIC_URL='https://panel.example.org:9443'", config)
        self.assertEqual((self.root / ".env").stat().st_mode & 0o777, 0o600)
        self.assertIn("Панель установлена", first.stdout)
        commands = self.log.read_text()
        self.assertNotIn(password, commands)
        self.assertIn("--resolve", commands)
        self.assertIn("https://panel.example.org:9443/healthz", commands)
        saved_archive = (self.root / ".installer/runtime.tar").read_bytes()
        count = commands.count('"image", "save"')
        second = self.install()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual((self.root / ".env").read_bytes(), config)
        self.assertEqual((self.root / ".installer/runtime.tar").read_bytes(), saved_archive)
        self.assertEqual(self.log.read_text().count('"image", "save"'), count)

    def test_certificate_failure_keeps_configuration_for_retry(self):
        password = "a-test-password-123456"
        answers = f"operator\n{password}\n{password}\n9443\npanel.example.org\nops@example.org\ny\n"
        result = self.install(answers, HTTPS_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Панель установлена", result.stdout)
        self.assertIn("HTTPS не подтвердился", result.stderr)
        config = (self.root / ".env").read_bytes()
        retry = self.install()
        self.assertEqual(retry.returncode, 0, retry.stderr)
        self.assertEqual((self.root / ".env").read_bytes(), config)

    def test_busy_port_does_not_stop_other_services(self):
        password = "a-test-password-123456"
        answers = f"operator\n{password}\n{password}\n9443\npanel.example.org\nops@example.org\ny\n"
        result = self.install(answers, BUSY_PORT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("занят", result.stderr)
        self.assertFalse((self.root / ".env").exists())
        commands = self.log.read_text()
        self.assertNotIn('"build"', commands)
        self.assertNotIn('"stop"', commands)
        self.assertNotIn('"down"', commands)

    def test_lost_configuration_does_not_regenerate_database_keys(self):
        result = self.install(EXISTING_VOLUME="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("новые секреты", result.stderr)
        self.assertFalse((self.root / ".env").exists())
        self.assertNotIn('"build"', self.log.read_text())

    def test_manual_configuration_and_override_are_not_overwritten(self):
        config = self.root / ".env"
        config.write_text("ENCRYPTION_KEY='operator-managed'\n")
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(config.read_text(), "ENCRYPTION_KEY='operator-managed'\n")
        config.unlink()
        override = self.root / "compose.override.yml"
        override.write_text("# operator-managed\n")
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(override.read_text(), "# operator-managed\n")
        self.assertFalse(config.exists())

    def test_invalid_setup_does_not_persist_partial_configuration(self):
        password = "a-test-password-123456"
        result = self.install(f"operator\n{password}\n{password}\n9443\npanel.example.org\ninvalid-email\ny\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / ".env").exists())
        self.assertNotIn('"up"', self.log.read_text())


if __name__ == "__main__":
    unittest.main()
