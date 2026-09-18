import contextlib
import difflib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('deployer_rules', ROOT / 'nft-deploy.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class CustomRulesTests(unittest.TestCase):
    def test_file_rules_are_added_to_input_and_ports_are_preserved(self):
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
            defaults = d.get_promethean_rules()
            with contextlib.redirect_stdout(io.StringIO()):
                merged = d.merge_ruleset(base, defaults)
            self.assertIn(defaults, merged)
            self.assertIn('tcp dport 2222', merged)
            self.assertEqual(merged.count('tcp dport 8443 accept'), 1)
            self.assertLess(merged.index('chain input'), merged.index('tcp dport 8443'))
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
