from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / 'nft-deploy'


class LauncherTests(unittest.TestCase):
    def test_no_arguments_print_help_without_network_initialization(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / 'nft-deploy.py')],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Usage:', result.stdout)
        self.assertIn('--remove', result.stdout)

    def test_launcher_runs_from_another_directory_and_preserves_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            launcher = directory / 'nft-deploy'
            shutil.copy2(LAUNCHER, launcher)
            (directory / 'nft_failsafe.py').write_text('')
            (directory / 'nft-deploy.py').write_text(
                'import json, sys\nprint(json.dumps(sys.argv[1:]))\nsys.exit(7)\n'
            )
            python = directory / '.venv' / 'bin' / 'python3'
            python.parent.mkdir(parents=True)
            python.symlink_to(sys.executable)
            environment = dict(os.environ)
            environment.pop('NFTD_DIR', None)
            result = subprocess.run(
                ['bash', str(launcher), '--remove', 'comment "hmm"'],
                cwd='/', env=environment, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 7, result.stderr)
            self.assertEqual(json.loads(result.stdout), ['--remove', 'comment "hmm"'])

    def test_launcher_preserves_quoted_arguments(self):
        launcher = LAUNCHER.read_text()

        self.assertEqual(launcher.count('"$@"'), 2)
        self.assertNotIn('nft-deploy.py $@', launcher)

    def test_launcher_has_valid_bash_syntax(self):
        result = subprocess.run(
            ['bash', '-n', str(LAUNCHER)], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
