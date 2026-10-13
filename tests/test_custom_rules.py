import contextlib
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
    def test_file_rules_replace_custom_defaults_and_explicit_ports_are_added(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'custom.conf'
            file.write_text('tcp dport 8443 accept\n')
            d = m.Deployer.__new__(m.Deployer)
            d.custom_file = str(file)
            d.ports = [2222]
            d.network = '192.0.2.0/24'
            d.comment = None
            base = d.get_default_rules()
            defaults = d.get_promethean_rules()
            with contextlib.redirect_stdout(io.StringIO()):
                merged = d.merge_ruleset(base, defaults, ports=d.ports)
            self.assertNotIn(defaults, merged)
            self.assertIn('tcp dport 2222', merged)
            self.assertEqual(merged.count('tcp dport 8443 accept'), 1)
            self.assertLess(merged.index('chain input'), merged.index('tcp dport 8443'))
            self.assertLess(merged.index('tcp dport 8443'), merged.index('pkttype host'))
            self.assertEqual(merged.split('chain forward')[1], base.split('chain forward')[1])
