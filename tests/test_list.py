import contextlib
import importlib.util
import io
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('deployer_list', ROOT / 'nft-deploy.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ListTests(unittest.TestCase):
    def test_aliases_read_selected_file_without_runtime_dependencies(self):
        text = 'table inet filter {\r\n\t# comment\r\n}\r\n'
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'rules.conf'
            config.write_bytes(text.encode())
            for flag in ('--list', '-l'):
                with self.subTest(flag=flag), patch.object(m, 'get_default_network') as network, patch.object(m.shutil, 'which', return_value=None), patch.object(m, 'highlight_ruleset', return_value='colored') as highlight:
                    d = m.Deployer(['nft-deploy', flag, '--config', str(config)], initialize_runtime=False)
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(d.check_args(), 0)
                    network.assert_not_called()
                    highlight.assert_called_once_with(text.expandtabs(4))
                    self.assertEqual(output.getvalue(), 'colored')

    def test_missing_file_reports_error(self):
        d = m.Deployer(['nft-deploy', '-l', '-C', '/nonexistent/nft.conf'], initialize_runtime=False)
        with contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(d.check_args(), 1)
        self.assertIn('Cannot read configuration', error.getvalue())

    def test_real_cli_preserves_configuration_text(self):
        text = 'table inet filter {\n\n\t# comment\n}\n'
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'rules.conf'
            config.write_text(text)
            result = subprocess.run([sys.executable, str(ROOT / 'nft-deploy.py'), '-l', '-C', str(config)], capture_output=True, text=True)
            self.assertEqual(config.read_text(), text)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(re.sub(r'\x1b\[[0-9;]*m', '', result.stdout), text.expandtabs(4))

    def test_listing_rejects_deployment_in_either_order(self):
        for flags in (('-l', '--deploy'), ('--deploy', '-l')):
            d = m.Deployer(['nft-deploy', *flags], initialize_runtime=False)
            with self.assertRaisesRegex(SystemExit, '--list can only'):
                d.check_args()
