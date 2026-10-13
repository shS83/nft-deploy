import builtins
import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('deployer_optimize', ROOT / 'nft-deploy.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class OptimizeTests(unittest.TestCase):
    def deployer(self, config):
        deployer = m.Deployer.__new__(m.Deployer)
        deployer.config_path = str(config)
        deployer.tmp_path = str(config.parent / 'runtime')
        deployer.lock_fd = None
        deployer.lock_transferred = False
        deployer.nft = '/usr/sbin/nft'
        deployer.optimized = None
        deployer.backup_first = mock.Mock(return_value=True)
        return deployer

    @mock.patch.object(m, 'highlight_ruleset', return_value='COLORED RULESET\n')
    @mock.patch.object(m.subprocess, 'run')
    def test_optimized_rules_are_highlighted_and_saved_after_yes(self, run, highlight):
        run.return_value = mock.Mock(
            stdout='table inet filter {\n}\n', stderr='', returncode=0
        )
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'nftables.conf'
            config.write_text('old rules\n')
            deployer = self.deployer(config)
            output = io.StringIO()

            with contextlib.redirect_stdout(output), mock.patch.object(
                builtins, 'input', return_value='Yes'
            ) as prompt:
                result = deployer.optimize()

            self.assertEqual(result, 0)
            self.assertEqual(config.read_text(), run.return_value.stdout)
            highlight.assert_called_once_with(run.return_value.stdout)
            self.assertIn('COLORED RULESET', output.getvalue())
            self.assertIn('Optimized changes would be these:', prompt.call_args.args[0])
            self.assertIn(m.c.bright_blue, prompt.call_args.args[0])

    @mock.patch.object(m, 'highlight_ruleset', return_value='COLORED RULESET\n')
    @mock.patch.object(m.subprocess, 'run')
    def test_no_keeps_original_configuration(self, run, _highlight):
        run.return_value = mock.Mock(stdout='optimized\n', stderr='', returncode=0)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'nftables.conf'
            config.write_text('old rules\n')
            deployer = self.deployer(config)

            with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(
                builtins, 'input', return_value='No'
            ):
                result = deployer.optimize()

            self.assertEqual(result, 0)
            self.assertEqual(config.read_text(), 'old rules\n')


if __name__ == '__main__':
    unittest.main()
