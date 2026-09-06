import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('failsafe', ROOT / 'nft-failsafe.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def result(code=0, out=''):
    return subprocess.CompletedProcess([], code, out, '')


class FailsafeTests(unittest.TestCase):
    def guard(self, backup='backup', config='config'):
        with patch.object(module.shutil, 'which', return_value='/usr/bin/nft'):
            return module.Failsafe(0, backup, config)

    def test_disabled_boot_service_can_have_healthy_live_firewall(self):
        guard = self.guard()
        with patch.object(guard, 'run', side_effect=[result(1, 'disabled'), result(0, 'active'), result(0, 'table ip firewall {}')]):
            self.assertTrue(guard.check_main_status())

    def test_ruleset_permission_error_is_unhealthy(self):
        guard = self.guard()
        with patch.object(guard, 'run', side_effect=[result(), result(), result(1)]):
            self.assertFalse(guard.check_main_status())

    def test_empty_ruleset_is_unhealthy(self):
        guard = self.guard()
        with patch.object(guard, 'run', side_effect=[result(), result(), result()]):
            self.assertFalse(guard.check_main_status())

    def test_failed_restart_restores_backup_and_reports_deployment_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            backup = Path(directory) / 'backup'
            config = Path(directory) / 'config'
            backup.write_text('old rules')
            config.write_text('new rules')
            guard = self.guard(str(backup), str(config))
            with patch.object(guard, 'check_main_status', side_effect=[False, True]), patch.object(guard, 'run', side_effect=[result(1), result(), result()]) as run:
                self.assertFalse(guard.activate_failsafe())
                self.assertEqual(config.read_text(), 'old rules')
                self.assertEqual(backup.read_text(), 'old rules')
                self.assertEqual(run.call_args_list[1].args[0], ['/usr/bin/nft', '-f', str(config)])

    def test_countdown_only_shows_last_nine_seconds_and_all_symbols(self):
        guard = self.guard()
        guard.timer = 11
        with patch.object(module.time, 'monotonic', side_effect=[0, *range(12)]), patch.object(module.time, 'sleep'), patch.object(guard, 'print_above_prompt') as output:
            guard.countdown()
        frames = [call.args[0] for call in output.call_args_list]
        self.assertEqual(len(frames), 10)
        self.assertIn('  9 seconds', frames[0])
        self.assertIn('  8 seconds', frames[1])
        for frame, symbol in zip(frames[2:9], ('♹', '♸', '♷', '♶', '♵', '♴', '♳')):
            self.assertIn(symbol, frame)
            self.assertIn(str(module.c.gold), frame)
        self.assertEqual(frames[-1], '')

    def test_overlay_preserves_cursor_and_avoids_last_column(self):
        guard = self.guard()
        with patch.object(module.sys.stdout, 'isatty', return_value=True), patch.object(module.sys.stdout, 'fileno', return_value=42), patch.dict(module.os.environ, {'TERM': 'xterm'}), patch.object(module.os, 'get_terminal_size', return_value=(80, 24)), patch.object(module.os, 'write') as write:
            guard.print_above_prompt('hello')
        write.assert_called_once_with(42, b'\x1b7\x1b[24;50Hhello' + b' ' * 25 + b'\x1b8')

    def test_redirected_output_has_no_cursor_controls(self):
        guard = self.guard()
        with patch.object(module.sys.stdout, 'isatty', return_value=False), patch('builtins.print') as output:
            guard.print_above_prompt('countdown')
            guard.print_above_prompt('')
        output.assert_called_once_with('countdown', flush=True)


if __name__ == '__main__':
    unittest.main()
