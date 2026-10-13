import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('deployer_inline', ROOT / 'nft-deploy.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class InlineRulesTests(unittest.TestCase):
    def setUp(self):
        self.d = m.Deployer.__new__(m.Deployer)
        self.d.STATE = [self.d.State.NONE]
        self.d.ports = []
        self.d.close_ports = []
        self.d.comment = None
        self.d.network = '192.0.2.0/24'

    def parse(self, *args):
        self.d.args = ['nft-deploy', *args, '--dry-run']
        with mock.patch.object(self.d, 'dry_run', return_value=0):
            self.assertEqual(self.d.check_args(), 0)

    def merge(self, base=None):
        with contextlib.redirect_stdout(io.StringIO()):
            return self.d.merge_ruleset(self.d.get_default_rules() if base is None else base)

    def test_repeated_rules_target_named_chains_and_keep_order(self):
        self.parse('--output', '--input-rule', 'tcp dport 8443 accept comment "web"',
                   '--output-rule', 'udp dport 53 accept',
                   '--input-rule', 'udp dport 5353 accept',
                   '--forward-rule', 'ip saddr 192.0.2.0/24 accept')
        with mock.patch.object(self.d, 'get_promethean_rules') as automatic:
            result = self.merge()
            automatic.assert_not_called()
        for chain, rule in [('input', 'tcp dport 8443'), ('output', 'udp dport 53'),
                            ('forward', 'ip saddr 192.0.2.0/24')]:
            lines = result.splitlines()
            span = self.d._find_block(lines, m.re.compile(rf'^\s*chain\s+{chain}\s*\{{'))
            self.assertIn(rule, '\n'.join(lines[span[0]:span[1]]))
            self.assertIn(getattr(self.d.State, chain.upper()), self.d.STATE)
        self.assertLess(result.index('tcp dport 8443'), result.index('udp dport 5353'))
        self.assertNotIn(self.d.State.NONE, self.d.STATE)

    def test_missing_chain_created(self):
        self.parse('--output-rule', 'udp dport 53 accept')
        result = self.merge('table inet filter {\n}\n')
        self.assertIn('chain output', result)
        self.assertIn('policy accept', result)
        self.assertIn('udp dport 53 accept', result)

    def test_file_and_inline_rules_coexist(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / 'rules'
            filename.write_text('tcp dport 1234 accept\n')
            self.d.custom_input_files = [str(filename)]
            self.parse('--input-rule', 'tcp dport 5678 accept')
            result = self.merge()
        self.assertLess(result.index('tcp dport 1234'), result.index('tcp dport 5678'))

    def test_explicit_default_profile_kept(self):
        self.parse('--default', '--input-rule', 'udp dport 5353 accept')
        result = self.merge()
        self.assertIn('Accept SMB/CIFS from local network', result)
        self.assertIn('udp dport 5353 accept', result)

    def test_close_port_removes_inline_rule_and_markers(self):
        self.parse('--input-rule', 'tcp dport 8443 accept', '--close-port', '8443')
        result = self.merge()
        self.assertNotIn('tcp dport 8443', result)
        self.assertNotIn('inline input rules', result)

    def test_empty_multiline_and_missing_rule_rejected(self):
        for option in ('--input-rule', '--output-rule', '--forward-rule'):
            for value in ('', '  ', 'accept\ndrop', 'accept\n', 'accept\rdrop', '--dry-run'):
                with self.subTest(option=option, value=value):
                    with self.assertRaises(SystemExit):
                        self.parse(option, value)
            self.d.args = ['nft-deploy', option]
            with self.assertRaisesRegex(SystemExit, 'needs a rule'):
                self.d.check_args()
