import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import nft_failsafe as m
from nft_defaults import get_default_rules


def result(code=0, out=''):
    return subprocess.CompletedProcess([], code, out, '')


class DefaultRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = Path(self.directory.name) / 'nftables.conf'
        self.config.write_text('broken configuration')
        with patch.object(m.shutil, 'which', return_value='nft'):
            self.guard = m.Failsafe(0, 'original-backup', str(self.config))

    def foreground(self):
        terminal = patch.object(m.sys.stdin, 'isatty', return_value=True)
        group = patch.object(m.os, 'tcgetpgrp', return_value=m.os.getpgrp())
        terminal.start()
        group.start()
        self.addCleanup(terminal.stop)
        self.addCleanup(group.stop)

    def test_confirmed_default_is_validated_backed_up_installed_and_restarted(self):
        self.foreground()
        with patch('builtins.input', return_value='y'), patch.object(self.guard, 'run', side_effect=[result(), result()]) as run, patch.object(self.guard, 'check_main_status', return_value=True), contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(self.guard.confirm_default_config())
        self.assertEqual(self.config.read_text(), get_default_rules())
        backups = list(self.config.parent.glob('nftables.conf.before-default-*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), 'broken configuration')
        self.assertEqual(run.call_args_list[0].args[0][:3], ['nft', '-c', '-f'])
        self.assertEqual(run.call_args_list[1].args[0], ['systemctl', 'restart', 'nftables.service'])
        self.assertEqual(self.guard.backup_file, 'original-backup')
        self.assertFalse(list(self.config.parent.glob('.nft-default-*')))

    def test_decline_does_not_change_config_or_run_commands(self):
        self.foreground()
        for answer in ('', 'n'):
            with patch('builtins.input', return_value=answer), patch.object(self.guard, 'run') as run, contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(self.guard.confirm_default_config())
            run.assert_not_called()
            self.assertEqual(self.config.read_text(), 'broken configuration')

    def test_background_shows_default_and_command_without_consuming_input(self):
        with patch.object(m.sys.stdin, 'isatty', return_value=False), patch('builtins.input') as prompt, patch.object(self.guard, 'run') as run, patch.object(m, 'highlight_ruleset', side_effect=lambda text: text), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertFalse(self.guard.confirm_default_config())
        self.assertIn(get_default_rules(), output.getvalue())
        self.assertIn('--restore-default', output.getvalue())
        prompt.assert_not_called()
        run.assert_not_called()

    def test_invalid_default_does_not_replace_config(self):
        self.foreground()
        with patch('builtins.input', return_value='yes'), patch.object(self.guard, 'run', return_value=result(1)), contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(self.guard.confirm_default_config())
        self.assertEqual(self.config.read_text(), 'broken configuration')
        self.assertFalse(list(self.config.parent.glob('nftables.conf.before-default-*')))

    def test_restart_failure_with_failed_service_offers_default_recovery(self):
        backup = Path(self.directory.name) / 'backup'
        backup.write_text('rollback config')
        self.guard.backup_file = str(backup)
        def unhealthy():
            self.guard.service_failed = True
            return False
        with patch.object(m.time, 'sleep'), patch.object(self.guard, 'run', side_effect=[result(), result(1)]), patch.object(self.guard, 'check_main_status', side_effect=unhealthy), patch.object(self.guard, 'confirm_default_config', return_value=True) as offer, contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(self.guard.rollback())
        offer.assert_called_once()
