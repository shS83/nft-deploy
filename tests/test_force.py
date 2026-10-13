import importlib.util
import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

m = load('deployer_force', 'nft-deploy.py')
f = load('failsafe_force', 'nft_failsafe.py')


class ForceTests(unittest.TestCase):
    def test_aliases_are_parsed_and_allowed_with_remove(self):
        for flag in ('--force', '-f'):
            d = m.Deployer.__new__(m.Deployer)
            d.args = ['nft-deploy', '-R', 'hmm', flag]
            d.remove_pattern = None
            with patch.object(d, 'remove_rule', return_value=0):
                self.assertEqual(d.check_args(), 0)
            self.assertTrue(d.force)

    def test_forced_deployment_skips_validation_and_leaves_failed_candidate_for_guard(self):
        for forced, load_code, expected in ((False, 0, 1), (True, 0, 0), (True, 1, 1)):
            with self.subTest(forced=forced, load_code=load_code), tempfile.TemporaryDirectory() as directory:
                d = m.Deployer.__new__(m.Deployer)
                d.config_path = str(Path(directory) / 'config')
                Path(d.config_path).write_text('original')
                d.ruleset = 'candidate'
                d.tmp_path = directory
                d.force = forced
                d.failsafe_timer = 15
                d.nft = 'nft'
                guard = Mock()
                with patch.object(m.os, 'geteuid', return_value=0), patch.object(d, 'check_env', return_value=0), patch.object(d, 'test_rules', return_value=1) as validate, patch.object(d, 'start_failsafe', return_value=guard) as start, patch.object(d, 'print_change_summary'), patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], load_code, '', 'load failed')) as run:
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(d._deploy_locked(), expected)
                    if forced and load_code:
                        self.assertNotIn('load failed', output.getvalue())
                        self.assertEqual(d.deployment_error, 'load failed')
                self.assertEqual(validate.call_count, 0 if forced else 1)
                self.assertEqual(run.call_count, 1 if forced else 0)
                self.assertEqual(start.call_count, 1 if forced else 0)
                self.assertEqual(Path(d.config_path).read_text(), 'candidate' if forced else 'original')
                if forced:
                    self.assertEqual(Path(d.backup_file).read_text(), 'original')
                    guard.stdin.write.assert_called_once_with(b'ok\n' if load_code == 0 else b'failed\nload failed')
                    guard.stdin.close.assert_called_once()

    def test_forced_guard_only_validates_backup_and_rolls_back_failed_load(self):
        with tempfile.TemporaryDirectory() as directory:
            backup = Path(directory) / 'backup'
            config = Path(directory) / 'config'
            backup.write_text('original')
            config.write_text('invalid')
            with patch.object(f.shutil, 'which', return_value='nft'):
                guard = f.Failsafe(0, str(backup), str(config), force=True)
            guard.deployment_failed = True
            def result(command):
                output = 'table inet filter {}' if command == ['nft', 'list', 'ruleset'] else ''
                return subprocess.CompletedProcess(command, 0, output, '')
            with patch.object(guard, 'countdown'), patch.object(f.time, 'sleep'), patch.object(guard, 'run', side_effect=result) as run:
                self.assertTrue(guard.activate_failsafe())
            validation_commands = [call.args[0] for call in run.call_args_list if '-c' in call.args[0]]
            self.assertEqual(validation_commands, [['nft', '-c', '-f', str(backup)]])
            self.assertEqual(config.read_text(), 'original')
            self.assertFalse(guard.deployment_failed)

    def test_forced_guard_still_rejects_invalid_backup(self):
        with patch.object(f.shutil, 'which', return_value='nft'):
            guard = f.Failsafe(0, 'backup', 'config', force=True)
        with patch.object(guard, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'invalid')), patch.object(guard, 'atomic_restore_config') as restore:
            self.assertFalse(guard.rollback())
        restore.assert_not_called()

    def test_guard_captures_errors_until_rollback(self):
        with patch.object(f.shutil, 'which', return_value='nft'):
            guard = f.Failsafe(0, 'backup', 'config', force=True)
        failure = subprocess.CompletedProcess([], 1, '', 'hidden diagnostic')
        with patch.object(f.subprocess, 'run', return_value=failure), contextlib.redirect_stdout(io.StringIO()) as output:
            guard.run(['nft', 'list', 'ruleset'])
            self.assertEqual(output.getvalue(), '')
            self.assertEqual(guard.diagnostics, ['hidden diagnostic'])
            self.assertFalse(guard.rollback())
        self.assertIn('hidden diagnostic', output.getvalue())

    def test_guard_errors_remain_visible_without_force(self):
        with patch.object(f.shutil, 'which', return_value='nft'):
            guard = f.Failsafe(0, 'backup', 'config')
        with patch.object(f.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'visible diagnostic')), contextlib.redirect_stdout(io.StringIO()) as output:
            guard.run(['nft', 'list', 'ruleset'])
        self.assertIn('visible diagnostic', output.getvalue())

    def test_failsafe_rejects_invalid_configuration_even_with_loaded_rules(self):
        for loaded, expected in ((True, False), (False, False)):
            guard = f.Failsafe.__new__(f.Failsafe)
            guard.nft = 'nft'
            guard.config_file = '/nonexistent/config'
            results = [subprocess.CompletedProcess([], 0, 'enabled', ''), subprocess.CompletedProcess([], 3, 'inactive', ''), subprocess.CompletedProcess([], 0, 'table inet filter {}' if loaded else '', ''), subprocess.CompletedProcess([], 1, '', 'invalid')]
            with patch.object(guard, 'run', side_effect=results):
                self.assertEqual(guard.check_main_status(), expected)

    def test_force_is_forwarded_to_guard_to_skip_status_validation(self):
        d = m.Deployer.__new__(m.Deployer)
        d.force = True
        d.pwd = str(ROOT)
        d.failsafe_timer = 15
        d.backup_file = 'backup'
        d.config_path = 'config'
        with patch.dict(m.os.environ, {'SUDO_TTY': ''}), patch.object(m.subprocess, 'Popen') as spawn:
            d.start_failsafe()
        self.assertIn('--force', spawn.call_args.args[0])
