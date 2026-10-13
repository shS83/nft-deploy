import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('deployer_prometheus', ROOT / 'nft-deploy.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class PrometheusTests(unittest.TestCase):
    def deployer(self, *args):
        d = m.Deployer.__new__(m.Deployer)
        d.args = ['nft-deploy', *args]
        d.STATE = [d.State.NONE]
        d.use_current_rules = False
        d.use_default_profile = False
        d.use_prometheus_profile = False
        d.ports = []
        d.network = '192.0.2.0/24'
        d.comment = None
        d.custom_input_files = []
        d.custom_forward_files = []
        d.custom_output_files = []
        d.custom_input_rules = []
        return d

    def test_profile_uses_default_base_and_complete_promethean_rules(self):
        d = self.deployer('--prometheus', '--dry-run')
        d.dry_run = Mock(return_value=0)
        self.assertEqual(d.check_args(), 0)
        d.dry_run.assert_called_once()
        self.assertEqual(d.get_base_rules(), d.get_default_rules())
        with contextlib.redirect_stdout(io.StringIO()):
            merged = d.merge_ruleset(d.get_base_rules())
        for rule in d.get_promethean_rules().splitlines():
            self.assertIn(rule.strip(), merged)
        self.assertLess(merged.index('Allow Codex'), merged.index('pkttype host'))

    def test_profile_preserved_with_additional_inline_rules(self):
        d = self.deployer('--prometheus', '--input-rule', 'udp dport 5353 accept', '--deploy')
        d.deploy = Mock(return_value=0)
        self.assertEqual(d.check_args(), 0)
        d.deploy.assert_called_once()
        with contextlib.redirect_stdout(io.StringIO()):
            merged = d.merge_ruleset(d.get_base_rules())
        self.assertIn('Allow Codex', merged)
        self.assertIn('udp dport 5353 accept', merged)

    def test_conflicting_profiles_are_rejected_in_either_order(self):
        for other in ('--default', '--use-current-rules'):
            for args in (('--prometheus', other), (other, '--prometheus')):
                with self.subTest(args=args), self.assertRaisesRegex(SystemExit, '--prometheus cannot be combined'):
                    self.deployer(*args).check_args()


if __name__ == '__main__':
    unittest.main()
