import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('deployer_remove', ROOT / 'nft-deploy.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RemoveTests(unittest.TestCase):
    def setUp(self):
        root = patch.object(m.os, 'geteuid', return_value=0)
        root.start()
        self.addCleanup(root.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = Path(self.directory.name) / 'rules.conf'
        self.original = 'flush ruleset\ntable inet filter {\n chain input {\n  tcp dport 22 accept\n  tcp dport 443 accept\n }\n}\n'
        self.config.write_text(self.original)
        self.d = m.Deployer.__new__(m.Deployer)
        self.d.config_path = str(self.config)
        self.d.remove_pattern = 'tcp dport'
        self.d.ruleset = ''
        self.d.tmp_path = self.directory.name
        self.d.lock_fd = None
        self.d.lock_transferred = False

    def test_non_root_removal_reports_sudo_before_lock_access(self):
        with patch.object(m.os, 'geteuid', return_value=1000), patch.object(self.d, 'acquire_deploy_lock') as lock, patch('builtins.print') as output:
            self.assertEqual(self.d.remove_rule(), 1)
        lock.assert_not_called()
        self.assertIn('sudo', output.call_args.args[0])

    def test_decline_first_match_and_remove_only_second(self):
        with patch('builtins.input', side_effect=['n', 'y']) as prompt, patch.object(self.d, '_deploy_locked', return_value=0) as deploy:
            self.assertEqual(self.d.remove_rule(), 0)
        self.assertEqual(self.d.ruleset, self.original.replace('  tcp dport 443 accept\n', ''))
        self.assertIn(f'{m.c.green}Found: {m.c.cyan}', prompt.call_args.args[0])
        deploy.assert_called_once_with(replace_ruleset=True)

    def test_yes_continues_to_next_match_and_deploys_once(self):
        with patch('builtins.input', side_effect=['y', 'y']) as prompt, patch.object(self.d, '_deploy_locked', return_value=0) as deploy:
            self.assertEqual(self.d.remove_rule(), 0)
        self.assertEqual(prompt.call_count, 2)
        self.assertEqual(self.d.ruleset, self.original.replace('  tcp dport 22 accept\n', '').replace('  tcp dport 443 accept\n', ''))
        deploy.assert_called_once_with(replace_ruleset=True)

    def test_interrupt_after_yes_cancels_entire_operation(self):
        with patch('builtins.input', side_effect=['y', KeyboardInterrupt()]), patch.object(self.d, '_deploy_locked') as deploy:
            self.assertEqual(self.d.remove_rule(), 0)
        deploy.assert_not_called()
        self.assertEqual(self.config.read_text(), self.original)

    def test_decline_or_interrupt_never_deploys(self):
        for response in ('', 'yes', EOFError(), KeyboardInterrupt()):
            with self.subTest(response=response), patch('builtins.input', side_effect=response if isinstance(response, BaseException) else None, return_value=response), patch.object(self.d, '_deploy_locked') as deploy:
                self.assertEqual(self.d.remove_rule(), 0)
                deploy.assert_not_called()
                self.assertEqual(self.config.read_text(), self.original)

    def test_invalid_empty_or_unmatched_pattern_never_deploys(self):
        for pattern in ('[', '', 'nonexistent'):
            self.d.remove_pattern = pattern
            with patch('builtins.input') as prompt, patch.object(self.d, '_deploy_locked') as deploy:
                self.assertEqual(self.d.remove_rule(), 1)
                prompt.assert_not_called()
                deploy.assert_not_called()

    def test_changed_config_aborts(self):
        def confirm(_):
            self.config.write_text('changed')
            return 'y'
        with patch('builtins.input', side_effect=confirm), patch.object(self.d, '_deploy_locked') as deploy:
            self.assertEqual(self.d.remove_rule(), 1)
            deploy.assert_not_called()

    def test_cli_dispatch_and_missing_value(self):
        self.d.remove_pattern = None
        self.d.ports = []
        self.d.custom_file = ''
        self.d.comment = None
        self.d.args = ['nft-deploy', '--remove', 'dport 22', '--timer', '15']
        with patch.object(self.d, 'remove_rule', return_value=0) as remove:
            self.assertEqual(self.d.check_args(), 0)
            remove.assert_called_once()
        self.assertEqual(self.d.failsafe_timer, 15)
        self.d.args = ['nft-deploy', '--remove']
        with self.assertRaises(SystemExit):
            self.d.check_args()

    def test_short_alias_dispatch_and_missing_value(self):
        self.d.remove_pattern = None
        self.d.args = ['nft-deploy', '-R', 'hmm', '-t', '15']
        with patch.object(self.d, 'remove_rule', return_value=0) as remove:
            self.assertEqual(self.d.check_args(), 0)
        remove.assert_called_once()
        self.assertEqual(self.d.remove_pattern, 'hmm')
        self.assertEqual(self.d.failsafe_timer, 15)
        self.d.args = ['nft-deploy', '-R']
        with self.assertRaises(SystemExit):
            self.d.check_args()

    def test_all_removes_every_match_even_after_declining_first(self):
        self.config.write_text('# tcp dport comment\n' + self.original)
        with patch('builtins.input', side_effect=['n', 'a']), patch.object(self.d, '_deploy_locked', return_value=0) as deploy:
            self.assertEqual(self.d.remove_rule(), 0)
        self.assertEqual(self.d.ruleset, self.original.replace('  tcp dport 22 accept\n', '').replace('  tcp dport 443 accept\n', ''))
        deploy.assert_called_once_with(replace_ruleset=True)

    def test_search_finds_commented_rules_by_comment_text(self):
        first = '    # ip daddr 104.18.39.21 reject comment "hmm"\n'
        second = '    # ip daddr 157.240.205.60 reject comment "hmm"\n'
        original = 'chain output {\n' + first + second + '}\n'
        for answer, expected in [(['y', 'n'], original.replace(first, '')), (['a'], 'chain output {\n}\n')]:
            with self.subTest(answer=answer):
                self.config.write_text(original)
                self.d.remove_pattern = 'hmm'
                with patch('builtins.input', side_effect=answer) as prompt, patch.object(self.d, '_deploy_locked', return_value=0) as deploy:
                    self.assertEqual(self.d.remove_rule(), 0)
                self.assertIn(first.rstrip(), prompt.call_args_list[0].args[0])
                self.assertEqual(self.d.ruleset, expected)
                deploy.assert_called_once_with(replace_ruleset=True)

    def test_backup_then_guard_then_atomic_load(self):
        self.d.failsafe_timer = 0
        self.d.tmp_path = self.directory.name
        self.d.nft = '/usr/bin/nft'
        self.d.ruleset = self.original.replace('  tcp dport 22 accept\n', '')
        events = []
        backup = self.d.backup_first
        def save():
            events.append('backup')
            return backup()
        guard = Mock()
        def start():
            events.append('guard')
            self.assertEqual(self.config.read_text(), self.original)
            return guard
        def load(*args, **kwargs):
            events.append('load')
            self.assertEqual(Path(self.d.backup_file).read_text(), self.original)
            self.assertEqual(self.config.read_text(), self.d.ruleset)
            self.assertEqual(kwargs['input'], 'flush ruleset\n' + self.d.ruleset)
            return subprocess.CompletedProcess(args[0], 0, '', '')
        with patch.object(m.os, 'geteuid', return_value=0), patch.object(self.d, 'print_change_summary'), patch.object(self.d, 'check_env', return_value=0), patch.object(self.d, 'backup_first', side_effect=save), patch.object(self.d, 'test_rules', return_value=0), patch.object(self.d, 'start_failsafe', side_effect=start), patch.object(m.subprocess, 'run', side_effect=load):
            self.assertEqual(self.d._deploy_locked(replace_ruleset=True), 0)
        self.assertEqual(events, ['backup', 'guard', 'load'])
        guard.stdin.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
