import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('deployer_close_ports', ROOT / 'nft-deploy.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ClosePortsTests(unittest.TestCase):
    def setUp(self):
        self.d = m.Deployer.__new__(m.Deployer)
        self.d.STATE = [self.d.State.NONE]
        self.d.ports = []
        self.d.close_ports = [80]
        self.d.port_chains = []
        self.d.network = '192.0.2.0/24'
        self.d.comment = None

    def merge(self, input_rules='', output_rules='', custom=''):
        base = ('table inet filter {\n'
                ' chain input {\n  type filter hook input priority filter;\n'
                '  policy drop;\n' + input_rules + '\n }\n'
                ' chain output {\n  type filter hook output priority filter;\n'
                '  policy accept;\n' + output_rules + '\n }\n}\n')
        with contextlib.redirect_stdout(io.StringIO()):
            return self.d.merge_ruleset(base, custom)

    def test_removes_only_selected_port_and_chain(self):
        result = self.merge('  tcp dport 80 accept comment "web"\n'
                            '  tcp dport 8080 accept\n  udp dport 80 accept',
                            '  tcp dport 80 accept')
        input_part, output_part = result.split(' chain output')
        self.assertNotIn('tcp dport 80 accept', input_part)
        self.assertNotIn('tcp dport 80 drop', input_part)
        self.assertIn('tcp dport 8080 accept', input_part)
        self.assertIn('udp dport 80 accept', input_part)
        self.assertIn('tcp dport 80 accept', output_part)

    def test_drop_precedes_broad_accept_and_keeps_sets(self):
        result = self.merge('  tcp dport { 80, 443 } accept\n  accept')
        self.assertIn('tcp dport { 80, 443 } accept', result)
        self.assertLess(result.index('tcp dport 80 drop'), result.index('tcp dport {'))
        self.assertGreater(result.index('tcp dport 80 drop'), result.index('policy drop;'))

    def test_comments_and_ranges_are_not_openings(self):
        result = self.merge('  # tcp dport 80 accept\n'
                            '  tcp dport 80-90 accept\n'
                            '  udp dport 53 accept comment "tcp dport 80 accept"')
        self.assertIn('tcp dport 80 drop', result)
        self.assertIn('tcp dport 80-90 accept', result)
        self.assertIn('udp dport 53 accept', result)

    def test_all_matching_openings_removed_after_custom_merge(self):
        self.d.STATE = [self.d.State.INPUT]
        result = self.merge('  tcp dport 80 accept\n  tcp dport == 80 counter accept;',
                            custom='tcp dport 80 accept comment "custom"')
        self.assertNotIn('dport 80 accept', result)
        self.assertNotIn('dport == 80', result)
        self.assertNotIn('dport 80 drop', result)

    def test_missing_forward_chain_created_and_multiple_chains_selected(self):
        self.d.port_chains = ['output', 'forward']
        result = self.merge('  tcp dport 80 accept', '  tcp dport 80 accept')
        self.assertEqual(result.count('tcp dport 80 accept'), 1)
        self.assertIn('chain forward', result)
        self.assertEqual(result.count('tcp dport 80 drop'), 1)

    def test_existing_generated_drop_not_duplicated(self):
        result = self.merge('  tcp dport 80 drop comment "User configured closed port"')
        self.assertEqual(result.count('tcp dport 80 drop'), 1)

    def test_empty_port_block_markers_removed(self):
        self.d.close_ports = [80, 443]
        result = self.merge('  # Begin of user configured ports\n'
                            '  tcp dport 80 accept\n  tcp dport 443 accept\n'
                            '  # End of user configured ports')
        self.assertNotIn('user configured ports', result)
        self.assertNotIn('tcp dport', result)

    def test_partially_empty_port_block_keeps_markers(self):
        result = self.merge('  # Begin of user configured ports\n'
                            '  tcp dport 80 accept\n  tcp dport 443 accept\n'
                            '  # End of user configured ports')
        self.assertIn('# Begin of user configured ports', result)
        self.assertIn('# End of user configured ports', result)
        self.assertIn('tcp dport 443 accept', result)

    def test_arbitrary_and_unpaired_comments_preserved(self):
        for before, after in (
            ('# My ports', '# Other rules'),
            ('# Begin of user configured ports', '# End of custom ruleset'),
            ('# Begin of user configured ports', '# Keep this note\n  # End of user configured ports'),
        ):
            with self.subTest(before=before, after=after):
                result = self.merge(f'  {before}\n  tcp dport 80 accept\n  {after}')
                self.assertIn(before, result)
                self.assertIn(after, result)
                self.assertNotIn('tcp dport 80 accept', result)

    def test_cleanup_is_limited_to_block_changed_by_removal(self):
        empty = '  # Begin of user configured ports\n  # End of user configured ports'
        result = self.merge(empty + '\n  tcp dport 80 accept', empty)
        self.assertEqual(result.count('# Begin of user configured ports'), 2)
        self.assertEqual(result.count('# End of user configured ports'), 2)

    def test_multiple_matching_blocks_and_custom_block_cleaned(self):
        self.d.STATE = [self.d.State.INPUT]
        block = ('  # Begin of user configured ports\n  tcp dport 80 accept\n'
                 '  # End of user configured ports\n')
        result = self.merge(block + block, custom='tcp dport 80 accept')
        self.assertNotIn('user configured ports', result)
        self.assertNotIn('custom ruleset', result)
        self.assertNotIn('tcp dport 80', result)

    def test_cli_aliases_and_chain_order(self):
        for alias in ('--close-port', '--close-ports', '-x'):
            with self.subTest(alias=alias):
                self.d.args = ['nft-deploy', alias, '443', '--output', '--forward', '--dry-run']
                self.d.close_ports = []
                with mock.patch.object(self.d, 'dry_run', return_value=0):
                    self.assertEqual(self.d.check_args(), 0)
                self.assertEqual(self.d.close_ports, [443])
                self.assertEqual(self.d.port_chains, ['output', 'forward'])

    def test_invalid_close_port(self):
        for value in ('0', '65536', 'abc', '', '80,', ',80', '80,,443', '80,abc', '80,65536'):
            self.d.args = ['nft-deploy', '--close-port', value]
            with self.subTest(value=value):
                with mock.patch.object(self.d, 'dry_run') as dry_run:
                    with self.assertRaises(SystemExit):
                        self.d.check_args()
                    dry_run.assert_not_called()
                self.assertEqual(self.d.close_ports, [80])

    def test_comma_separated_ports_and_repeated_options(self):
        for alias in ('--close-port', '--close-ports', '-x'):
            with self.subTest(alias=alias):
                self.d.close_ports = []
                self.d.args = ['nft-deploy', alias, '80, 443,8080', alias, '1,65535', '--dry-run']
                with mock.patch.object(self.d, 'dry_run', return_value=0):
                    self.assertEqual(self.d.check_args(), 0)
                self.assertEqual(self.d.close_ports, [80, 443, 8080, 1, 65535])

    def test_open_port_obeys_chain_selection(self):
        self.d.close_ports = []
        self.d.ports = [8080]
        self.d.port_chains = ['output']
        result = self.merge()
        input_part, output_part = result.split(' chain output')
        self.assertNotIn('tcp dport 8080', input_part)
        self.assertIn('tcp dport 8080', output_part)

    def test_open_port_aliases_accept_lists_and_repeated_options(self):
        for alias in ('--port', '--ports', '-p'):
            with self.subTest(alias=alias):
                self.d.ports = []
                self.d.close_ports = []
                self.d.args = ['nft-deploy', alias, '80, 443,8080', alias, '1',
                               alias, '65535', '--output', '--dry-run']
                with mock.patch.object(self.d, 'dry_run', return_value=0):
                    self.assertEqual(self.d.check_args(), 0)
                self.assertEqual(self.d.ports, [80, 443, 8080, 1, 65535])
                input_part, output_part = self.merge().split(' chain output')
                self.assertNotIn('tcp dport', input_part)
                for port in self.d.ports:
                    self.assertIn(f'tcp dport {port} ct state new accept', output_part)

    def test_invalid_open_port_lists_do_not_partially_add_ports(self):
        for alias in ('--port', '--ports', '-p'):
            for value in ('0', '65536', 'abc', '', '80,', ',80', '80,,443', '80,abc', '80,65536'):
                with self.subTest(alias=alias, value=value):
                    self.d.ports = [22]
                    self.d.args = ['nft-deploy', alias, value, '--dry-run']
                    with mock.patch.object(self.d, 'dry_run') as dry_run:
                        with self.assertRaises(SystemExit):
                            self.d.check_args()
                        dry_run.assert_not_called()
                    self.assertEqual(self.d.ports, [22])

    def test_open_port_aliases_require_a_value(self):
        for alias in ('--port', '--ports', '-p'):
            with self.subTest(alias=alias):
                self.d.args = ['nft-deploy', alias]
                with self.assertRaisesRegex(SystemExit, 'needs a value'):
                    self.d.check_args()
