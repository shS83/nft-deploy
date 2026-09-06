import fcntl
import importlib.util
import os
from pathlib import Path
import pty
import select
import struct
import subprocess
import sys
import tempfile
import termios
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('deployer', ROOT / 'nft-deploy.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TerminalTests(unittest.TestCase):
    def deployer(self):
        deployer = module.Deployer.__new__(module.Deployer)
        deployer.pwd = str(ROOT)
        deployer.failsafe_timer = 1
        deployer.backup_file = 'unused-backup'
        deployer.config_path = 'unused-config'
        return deployer

    def test_original_terminal_survives_sudo_terminal_closure(self):
        master, slave = pty.openpty()
        sudo_master, sudo_slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
        real_popen = subprocess.Popen
        # Exercise the actual launcher and countdown, but never firewall commands.
        child_code = '''
import importlib.util, sys
spec = importlib.util.spec_from_file_location('guard', sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
g = m.Failsafe.__new__(m.Failsafe)
g.timer = 1
sys.stdin.buffer.read()
g.countdown()
print('status-check-reached', flush=True)
print('stderr-connected', file=sys.stderr, flush=True)
'''
        def spawn(command, **kwargs):
            if kwargs.get('stdout') is None:
                kwargs['stdout'] = sudo_slave
            if kwargs.get('stderr') is None:
                kwargs['stderr'] = sudo_slave
            return real_popen([sys.executable, '-u', '-c', child_code, str(ROOT / 'nft-failsafe.py')], **kwargs)

        try:
            with patch.dict(os.environ, {'SUDO_TTY': os.ttyname(slave), 'TERM': 'xterm'}), patch.object(module.subprocess, 'Popen', side_effect=spawn):
                child = self.deployer().start_failsafe()
        finally:
            os.close(sudo_master)
            os.close(sudo_slave)
        try:
            child.stdin.close()
            self.assertEqual(child.wait(timeout=5), 0)
            output = b''
            while select.select([master], [], [], 0.1)[0]:
                output += os.read(master, 4096)
            self.assertIn(b'\x1b7\x1b[24;50H', output)
            self.assertIn('♳'.encode(), output)
            self.assertIn(b'status-check-reached', output)
            self.assertIn(b'stderr-connected', output)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()

    def test_invalid_terminal_aborts_without_launching_or_truncating(self):
        with tempfile.NamedTemporaryFile() as file:
            file.write(b'keep this')
            file.flush()
            with patch.dict(os.environ, {'SUDO_TTY': file.name}), patch.object(module.subprocess, 'Popen') as spawn:
                with self.assertRaisesRegex(SystemExit, 'does not point to a terminal'):
                    self.deployer().start_failsafe()
                spawn.assert_not_called()
            self.assertEqual(Path(file.name).read_bytes(), b'keep this')

    def test_missing_terminal_reports_open_error(self):
        with patch.dict(os.environ, {'SUDO_TTY': '/dev/nonexistent-nft-test-terminal'}), patch.object(module.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(SystemExit, 'Cannot open failsafe terminal'):
                self.deployer().start_failsafe()
            spawn.assert_not_called()


if __name__ == '__main__':
    unittest.main()
