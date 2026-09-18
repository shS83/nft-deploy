import contextlib
import difflib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('deployer_rules', ROOT / 'nft-deploy.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class CustomRulesTests(unittest.TestCase):
    def test_file_rules_replace_automatic_promethean_rules_and_preserve_ports(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'custom.conf'
            file.write_text('tcp dport 8443 accept\n')
            d = m.Deployer.__new__(m.Deployer)
            d.custom_input_file = str(file)
            d.custom_forward_file = ''
            d.custom_output_file = ''
            d.STATE = [d.State.INPUT]
            d.ports = [2222]
            d.network = '192.0.2.0/24'
            d.comment = None
            base = d.get_default_rules()
            with contextlib.redirect_stdout(io.StringIO()):
                merged = d.merge_ruleset(base)
            self.assertNotIn('Accept SMB/CIFS from local network', merged)
            self.assertIn('tcp dport 2222', merged)
            self.assertEqual(merged.count('tcp dport 8443 accept'), 1)
            self.assertLess(merged.index('chain input'), merged.index('tcp dport 8443'))
            self.assertLess(merged.index('tcp dport 8443'), merged.index('pkttype host'))
            self.assertLess(merged.index('tcp dport 8443'), merged.index('chain forward'))
            self.assertEqual(merged.split('chain forward')[1], base.split('chain forward')[1])

    def test_files_are_added_to_their_named_chains(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            input_file = directory / 'input.conf'
            forward_file = directory / 'forward.conf'
            output_file = directory / 'output.conf'
            input_file.write_text('tcp dport 1001 accept\n')
            forward_file.write_text('tcp dport 1002 accept\n')
            output_file.write_text('tcp dport 1003 accept\n')
            d = m.Deployer.__new__(m.Deployer)
            d.custom_input_file = str(input_file)
            d.custom_forward_file = str(forward_file)
            d.custom_output_file = str(output_file)
            d.ports = []
            d.network = '192.0.2.0/24'
            d.comment = None

            with contextlib.redirect_stdout(io.StringIO()):
                merged = d.merge_ruleset(d.get_default_rules(), 'tcp dport 1000 accept')

            input_chain, remainder = merged.split('chain forward', 1)
            forward_chain, output_chain = remainder.split('chain output', 1)
            self.assertIn('tcp dport 1001 accept', input_chain)
            self.assertIn('tcp dport 1002 accept', forward_chain)
            self.assertIn('tcp dport 1003 accept', output_chain)

    def test_missing_output_chain_is_created_with_accept_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            output_file = Path(directory) / 'output.conf'
            output_file.write_text('udp dport 53 accept\n')
            d = m.Deployer.__new__(m.Deployer)
            d.custom_input_file = ''
            d.custom_forward_file = ''
            d.custom_output_file = str(output_file)
            d.ports = []
            d.network = '192.0.2.0/24'
            d.comment = None

            with contextlib.redirect_stdout(io.StringIO()):
                merged = d.merge_ruleset(d.get_default_rules(), 'input-custom')

            output_chain = merged.split('chain output', 1)[1]
            self.assertIn('type filter hook output priority filter', output_chain)
            self.assertIn('policy accept', output_chain)
            self.assertIn('udp dport 53 accept', output_chain)

    def test_summary_uses_line_numbers_from_the_final_ruleset(self):
        d = m.Deployer.__new__(m.Deployer)
        d.custom_input_file = ''
        d.custom_forward_file = ''
        d.custom_output_file = ''
        d.STATE = [d.State.INPUT]
        d.ports = []
        d.network = '192.0.2.0/24'
        d.comment = None
        base = d.get_default_rules()
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            merged = d.merge_ruleset(base, 'tcp dport 1000 accept')

        changed_lines = []
        matcher = difflib.SequenceMatcher(
            None, base.splitlines(), merged.splitlines(), autojunk=False
        )
        for operation, _, _, final_start, final_end in matcher.get_opcodes():
            if operation in ('replace', 'insert'):
                changed_lines.extend(range(final_start + 1, final_end + 1))

        expected = (
            f'Number of changed lines: {m.c.bright_green}'
            f'{len(changed_lines)}{m.c.white}, lines: {m.c.golden_orange}'
            f'{", ".join(str(line) for line in changed_lines)}'
        )
        self.assertIn(expected, output.getvalue())

    def test_printed_base_is_silver_and_inserted_rules_are_green(self):
        d = m.Deployer.__new__(m.Deployer)
        d.custom_input_file = ''
        d.custom_forward_file = ''
        d.custom_output_file = ''
        d.STATE = [d.State.INPUT]
        d.ports = []
        d.network = '192.0.2.0/24'
        d.comment = None
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            d.merge_ruleset(d.get_default_rules(), 'tcp dport 1000 accept')

        rendered = output.getvalue()
        self.assertIn(f'{m.c.silver}table inet filter {{{m.c.reset}', rendered)
        self.assertIn(
            f'{m.c.green}    tcp dport 1000 accept{m.c.reset}', rendered
        )
        changed_line = next(
            line for line in rendered.splitlines() if 'tcp dport 1000 accept' in line
        )
        self.assertIn(str(m.c.cyan), changed_line)
        self.assertRegex(changed_line, r'\d+: ')

    def test_promethean_rules_are_used_when_no_rule_files_are_given(self):
        d = m.Deployer.__new__(m.Deployer)
        d.custom_input_file = ''
        d.custom_forward_file = ''
        d.custom_output_file = ''
        d.STATE = [d.State.INPUT]
        d.ports = []
        d.network = '192.0.2.0/24'
        d.comment = None

        with contextlib.redirect_stdout(io.StringIO()):
            merged = d.merge_ruleset(d.get_default_rules())

        self.assertIn('Accept SMB/CIFS from local network', merged)

    def test_tab_indented_file_rules_get_exactly_one_chain_indent(self):
        with tempfile.TemporaryDirectory() as directory:
            input_file = Path(directory) / 'input.conf'
            input_file.write_text('\ttcp dport 8443 accept\n')
            d = m.Deployer.__new__(m.Deployer)
            d.custom_input_file = str(input_file)
            d.custom_forward_file = ''
            d.custom_output_file = ''
            d.STATE = [d.State.INPUT]
            d.ports = []
            d.network = '192.0.2.0/24'
            d.comment = None

            with contextlib.redirect_stdout(io.StringIO()):
                merged = d.merge_ruleset(d.get_default_rules())

            self.assertIn('\n    tcp dport 8443 accept\n', merged)
            self.assertNotIn('\n        tcp dport 8443 accept\n', merged)

    def test_each_chain_inserts_before_its_own_pkttype_and_leaves_counter_last(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            forward_file = directory / 'forward.conf'
            output_file = directory / 'output.conf'
            forward_file.write_text('tcp dport 2000 accept\n')
            output_file.write_text('tcp dport 3000 accept\n')
            d = m.Deployer.__new__(m.Deployer)
            d.custom_input_file = ''
            d.custom_forward_file = str(forward_file)
            d.custom_output_file = str(output_file)
            d.STATE = [d.State.FORWARD, d.State.OUTPUT]
            d.ports = []
            d.network = '192.0.2.0/24'
            d.comment = None
            base = '''table inet filter {
  chain forward {
    type filter hook forward priority filter
    policy drop
    pkttype host reject
    counter
  }
  chain output {
    type filter hook output priority filter
    policy accept
    pkttype host reject
    counter
  }
}
'''

            with contextlib.redirect_stdout(io.StringIO()):
                merged = d.merge_ruleset(base)

            forward, output = merged.split('chain output', 1)
            self.assertLess(forward.index('tcp dport 2000'), forward.index('pkttype'))
            self.assertLess(output.index('tcp dport 3000'), output.index('pkttype'))
            self.assertRegex(forward, r'pkttype host reject\n    counter\n  }')
            self.assertRegex(output, r'pkttype host reject\n    counter\n  }')

    def test_multiple_files_per_chain_are_merged_in_argument_order(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            input_files = [directory / 'input-1', directory / 'input-2']
            forward_files = [
                directory / 'forward-1',
                directory / 'forward-2',
                directory / 'forward-3',
            ]
            output_files = [directory / 'output-1']
            for number, file in enumerate(input_files, start=1):
                file.write_text(f'tcp dport 10{number} accept\n')
            for number, file in enumerate(forward_files, start=1):
                file.write_text(f'tcp dport 20{number} accept\n')
            output_files[0].write_text('tcp dport 301 accept\n')

            d = m.Deployer.__new__(m.Deployer)
            d.custom_input_files = [str(file) for file in input_files]
            d.custom_forward_files = [str(file) for file in forward_files]
            d.custom_output_files = [str(file) for file in output_files]
            d.STATE = [d.State.INPUT, d.State.FORWARD, d.State.OUTPUT]
            d.ports = []
            d.network = '192.0.2.0/24'
            d.comment = None

            with contextlib.redirect_stdout(io.StringIO()):
                merged = d.merge_ruleset(d.get_default_rules())

            input_chain, remainder = merged.split('chain forward', 1)
            forward_chain, output_chain = remainder.split('chain output', 1)
            self.assertLess(input_chain.index('dport 101'), input_chain.index('dport 102'))
            self.assertLess(forward_chain.index('dport 201'), forward_chain.index('dport 202'))
            self.assertLess(forward_chain.index('dport 202'), forward_chain.index('dport 203'))
            self.assertIn('dport 301', output_chain)
            self.assertNotIn('Accept SMB/CIFS from local network', merged)

    def test_repeated_file_arguments_are_collected(self):
        d = m.Deployer.__new__(m.Deployer)
        d.args = [
            'nft-deploy.py',
            '--input-file', 'input-1',
            '--input-file', 'input-2',
            '--output-file', 'output-1',
            '--forward-file', 'forward-1',
            '--forward-file', 'forward-2',
            '--forward-file', 'forward-3',
            '--dry-run',
        ]
        d.STATE = [d.State.NONE]
        d.custom_input_files = []
        d.custom_forward_files = []
        d.custom_output_files = []
        d.dry_run = lambda: 0

        self.assertEqual(d.check_args(), 0)
        self.assertEqual(d.custom_input_files, ['input-1', 'input-2'])
        self.assertEqual(d.custom_output_files, ['output-1'])
        self.assertEqual(
            d.custom_forward_files, ['forward-1', 'forward-2', 'forward-3']
        )

    def test_short_options_select_current_rules_and_collect_files(self):
        d = m.Deployer.__new__(m.Deployer)
        d.args = [
            'nft-deploy.py', '-U', '-I', 'input', '-O', 'output',
            '-F', 'forward', '-p', '8443', '-m', 'web service',
            '-C', '/tmp/current.conf', '-t', '30', '-D',
        ]
        d.STATE = [d.State.NONE]
        d.use_current_rules = False
        d.custom_input_files = []
        d.custom_forward_files = []
        d.custom_output_files = []
        d.ports = []
        d.comment = None
        d.config_path = '/etc/nftables.conf'
        d.failsafe_timer = 15.0
        d.dry_run = lambda: 0

        self.assertEqual(d.check_args(), 0)
        self.assertTrue(d.use_current_rules)
        self.assertEqual(d.custom_input_files, ['input'])
        self.assertEqual(d.custom_output_files, ['output'])
        self.assertEqual(d.custom_forward_files, ['forward'])
        self.assertEqual(d.ports, [8443])
        self.assertEqual(d.comment, 'web service')
        self.assertEqual(d.config_path, '/tmp/current.conf')
        self.assertEqual(d.failsafe_timer, 30)

    def test_current_config_is_used_as_base_ruleset(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'nftables.conf'
            config.write_text('table inet existing {\n}\n')
            d = m.Deployer.__new__(m.Deployer)
            d.use_current_rules = True
            d.config_path = str(config)

            self.assertEqual(d.get_base_rules(), config.read_text())

    def test_short_status_option_runs_status_check(self):
        d = m.Deployer.__new__(m.Deployer)
        d.args = ['nft-deploy.py', '-s']
        d.failsafe_timer = 15.0
        d.backup_file = '/tmp/backup'

        with mock.patch.object(m, 'Failsafe') as failsafe:
            self.assertEqual(d.check_args(), 0)

        failsafe.assert_called_once_with(
            15.0, '/tmp/backup', '/etc/nftables.conf'
        )
        failsafe.return_value.check_main_status.assert_called_once_with()

    def test_short_help_option_runs_help(self):
        d = m.Deployer.__new__(m.Deployer)
        d.args = ['nft-deploy.py', '-h']

        with mock.patch.object(d, 'help', return_value=0) as help_method:
            self.assertEqual(d.check_args(), 0)

        help_method.assert_called_once_with()

    def test_default_profile_uses_detected_network_and_only_cifs_and_ssh(self):
        d = m.Deployer.__new__(m.Deployer)
        d.custom_input_files = []
        d.custom_forward_files = []
        d.custom_output_files = []
        d.use_default_profile = True
        d.STATE = [d.State.INPUT]
        d.ports = []
        d.network = '192.0.2.0/24'
        d.comment = None

        with contextlib.redirect_stdout(io.StringIO()):
            merged = d.merge_ruleset(d.get_default_rules())

        for port in (137, 138, 139, 445):
            self.assertIn(
                f'ip saddr 192.0.2.0/24 tcp dport {port}', merged
            )
        self.assertIn('tcp dport ssh accept comment "Allow sshd"', merged)
        self.assertNotIn('10.10.42.0/27', merged)
        self.assertNotIn('dport 8082', merged)
        self.assertLess(merged.index('dport 137'), merged.index('pkttype host'))

    def test_default_short_option_selects_input_profile(self):
        d = m.Deployer.__new__(m.Deployer)
        d.args = ['nft-deploy.py', '-d', '-X']
        d.STATE = [d.State.NONE]
        d.use_current_rules = False
        d.use_default_profile = False
        d.deploy = lambda: 0

        self.assertEqual(d.check_args(), 0)
        self.assertTrue(d.use_default_profile)
        self.assertIn(d.State.INPUT, d.STATE)

    def test_default_and_current_rules_are_mutually_exclusive(self):
        d = m.Deployer.__new__(m.Deployer)
        d.args = ['nft-deploy.py', '-d', '-U', '-D']
        d.STATE = [d.State.NONE]
        d.use_current_rules = False
        d.use_default_profile = False

        with self.assertRaisesRegex(SystemExit, '--default cannot be combined'):
            d.check_args()
