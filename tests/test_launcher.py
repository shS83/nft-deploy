from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / 'nft-deploy'


class LauncherTests(unittest.TestCase):
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
