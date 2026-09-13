import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("deployer_cli_ports", ROOT / "nft-deploy.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class CliPortsTests(unittest.TestCase):
    def test_compile_config_includes_ports_without_custom_file(self):
        with tempfile.TemporaryDirectory() as directory:
            deployer = m.Deployer.__new__(m.Deployer)
            deployer.custom_file = None
            deployer.ports = [1234]
            deployer.network = "192.0.2.0/24"
            deployer.comment = None
            deployer.config_path = "/etc/nftables.conf"
            deployer.dry_run_config_file = Path(directory) / "dry-run.conf"
            deployer.ruleset = ""

            with mock.patch.object(deployer, "get_default_rules", return_value="pkttype host"), \
                    mock.patch.object(deployer, "get_promethean_rules", return_value="allow defaults"), \
                    contextlib.redirect_stdout(io.StringIO()):
                result = deployer.compile_config(deploy=False)

            self.assertIn("allow defaults", result)
            self.assertIn("tcp dport 1234", result)


if __name__ == "__main__":
    unittest.main()
