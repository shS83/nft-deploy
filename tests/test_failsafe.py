import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('failsafe', ROOT / 'nft_failsafe.py')
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
        with patch.object(guard, 'run', side_effect=[result(1, 'disabled'), result(0, 'active'), result(0, 'table ip firewall {}'), result()]):
            self.assertFalse(guard.check_main_status())

    def test_ruleset_permission_error_is_unhealthy(self):
        guard = self.guard()
        with patch.object(guard, 'run', side_effect=[result(), result(), result(1), result()]):
            self.assertFalse(guard.check_main_status())

    def test_empty_ruleset_is_unhealthy(self):
        guard = self.guard()
        with patch.object(guard, 'run', side_effect=[result(), result(), result(), result()]):
            self.assertFalse(guard.check_main_status())

    def test_invalid_config_is_unhealthy_even_if_live_rules_are_loaded(self):
        guard = self.guard()
        with patch.object(
            guard,
            'run',
            side_effect=[
                result(0, 'enabled'),
                result(0, 'active'),
                result(0, 'table inet filter {}'),
                result(1),
            ],
        ) as run:
            self.assertFalse(guard.check_main_status())

        self.assertEqual(
            run.call_args_list[3].args[0],
            ['/usr/bin/nft', '-c', '-f', 'config'],
        )

    def test_status_prints_config_file_with_whitespace_preserved(self):
        configured = '''table inet filter {

  chain forward {
    type filter hook forward priority filter
    policy drop
  }
}
'''
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'nftables.conf'
            config.write_text(configured)
            guard = self.guard(config=str(config))
            output = io.StringIO()
            with patch.object(
                guard,
                'run',
                side_effect=[
                    result(0, 'enabled'),
                    result(0, 'active'),
                    result(0, 'table inet filter { chain forward { } }'),
                    result(),
                ],
            ), patch.object(
                module, 'highlight_ruleset', side_effect=lambda text: text
            ), contextlib.redirect_stdout(output):
                self.assertTrue(guard.check_main_status())

            self.assertIn(f'Ruleset:\n{configured}', output.getvalue())
            self.assertIn('\n\n  chain forward {\n', output.getvalue())
            self.assertNotIn('type filter hook forward priority filter; policy drop;', output.getvalue())

    def test_simulation_never_checks_or_changes_firewall(self):
        guard = self.guard()
        guard.simulate_failure = True
        with patch.object(guard, 'check_main_status') as check, patch.object(guard, 'run') as run, patch.object(module.shutil, 'copyfile') as copy, patch('builtins.print') as output:
            self.assertFalse(guard.activate_failsafe())
            check.assert_not_called()
            run.assert_not_called()
            copy.assert_not_called()
            self.assertTrue(any('SIMULATION' in call.args[0] for call in output.call_args_list))

    def test_failed_check_automatically_restores_backup_and_restarts(self):
        with tempfile.TemporaryDirectory() as directory:
            backup = Path(directory) / 'backup'
            config = Path(directory) / 'config'
            backup.write_text('old rules')
            config.write_text('broken rules')
            guard = self.guard(str(backup), str(config))
            with patch.object(guard, 'countdown'), patch.object(
                guard, 'check_main_status', side_effect=[False, True]
            ), patch.object(
                guard, 'run', side_effect=[result(), result()]
            ) as run, patch.object(module.time, 'sleep') as sleep, patch(
                'builtins.print'
            ) as output:
                self.assertTrue(guard.activate_failsafe())

            self.assertEqual(config.read_text(), 'old rules')
            self.assertEqual(run.call_args_list[0].args[0], ['/usr/bin/nft', '-c', '-f', str(backup)])
            self.assertEqual(run.call_args_list[1].args[0], ['systemctl', 'restart', 'nftables.service'])
            self.assertEqual(sleep.call_count, 3)
            self.assertIn('Press any key to continue...', output.call_args.args[0])

    def test_successful_failsafe_ends_with_continue_message(self):
        guard = self.guard()
        with patch.object(guard, 'countdown'), patch.object(
            guard, 'check_main_status', return_value=True
        ), patch('builtins.print') as output:
            self.assertTrue(guard.activate_failsafe())

        self.assertIn('Press any key to continue...', output.call_args.args[0])
        self.assertTrue(output.call_args.kwargs['flush'])

    def test_confirmed_rollback_restores_and_verifies(self):
        with tempfile.TemporaryDirectory() as directory:
            backup = Path(directory) / 'backup'
            config = Path(directory) / 'config'
            backup.write_text('old rules')
            config.write_text('new rules')
            guard = self.guard(str(backup), str(config))
            with patch.object(module.sys.stdin, 'isatty', return_value=True), patch.object(module.os, 'tcgetpgrp', return_value=module.os.getpgrp()), patch('builtins.input', return_value='yes'), patch.object(guard, 'check_main_status', return_value=True), patch.object(guard, 'run', side_effect=[result(), result()]) as run, patch.object(module.time, 'sleep'):
                self.assertTrue(guard.confirm_rollback())
                self.assertEqual(config.read_text(), 'old rules')
                self.assertEqual(backup.read_text(), 'old rules')
                self.assertEqual(run.call_args_list[0].args[0], ['/usr/bin/nft', '-c', '-f', str(backup)])
                self.assertEqual(run.call_args_list[1].args[0], ['systemctl', 'restart', 'nftables.service'])

    def test_declined_or_empty_answer_does_not_change_firewall(self):
        for answer in ('', 'e', 'unexpected'):
            with self.subTest(answer=answer):
                guard = self.guard()
                with patch.object(module.sys.stdin, 'isatty', return_value=True), patch.object(module.os, 'tcgetpgrp', return_value=module.os.getpgrp()), patch('builtins.input', return_value=answer), patch.object(guard, 'run') as run, patch.object(module.shutil, 'copyfile') as copy:
                    self.assertFalse(guard.confirm_rollback())
                    run.assert_not_called()
                    copy.assert_not_called()

    def test_background_rollback_never_reads_input(self):
        guard = self.guard()
        with patch.object(module.sys.stdin, 'isatty', return_value=True), patch.object(module.os, 'tcgetpgrp', return_value=-1), patch('builtins.input') as prompt:
            self.assertFalse(guard.confirm_rollback())
            prompt.assert_not_called()

    def test_invalid_backup_is_not_copied(self):
        guard = self.guard()
        with patch.object(module.sys.stdin, 'isatty', return_value=True), patch.object(module.os, 'tcgetpgrp', return_value=module.os.getpgrp()), patch('builtins.input', return_value='k'), patch.object(guard, 'run', return_value=result(1)) as run, patch.object(module.shutil, 'copyfile') as copy:
            self.assertFalse(guard.confirm_rollback())
            self.assertEqual(run.call_count, 1)
            copy.assert_not_called()

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
        for frame, symbol, color in zip(frames[2:9], ('♹', '♸', '♷', '♶', '♵', '♴', '♳'), (module.c.lime_green,) * 3 + (module.c.yellow,) * 2 + (module.c.bright_red,) * 2):
            self.assertIn(f'{color}{symbol}', frame)
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
