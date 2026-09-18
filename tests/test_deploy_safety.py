import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]

deploy_spec = importlib.util.spec_from_file_location('deployer_safety', ROOT / 'nft-deploy.py')
deploy_module = importlib.util.module_from_spec(deploy_spec)
deploy_spec.loader.exec_module(deploy_module)

failsafe_spec = importlib.util.spec_from_file_location('failsafe_safety', ROOT / 'nft_failsafe.py')
failsafe_module = importlib.util.module_from_spec(failsafe_spec)
failsafe_spec.loader.exec_module(failsafe_module)


class DeploySafetyTests(unittest.TestCase):
    def deployer(self, directory):
        deployer = deploy_module.Deployer.__new__(deploy_module.Deployer)
        deployer.tmp_path = str(directory)
        deployer.lock_fd = None
        deployer.lock_transferred = False
        return deployer

    def test_lock_remains_held_by_inherited_failsafe_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            first = self.deployer(directory)
            second = self.deployer(directory)
            self.assertTrue(first.acquire_deploy_lock())
            child = subprocess.Popen(
                [sys.executable, '-c', 'import time; time.sleep(30)'],
                pass_fds=(first.lock_fd,),
            )
            try:
                first.lock_transferred = True
                first.release_deploy_lock()
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertFalse(second.acquire_deploy_lock())
            finally:
                child.terminate()
                child.wait(timeout=5)

            self.assertTrue(second.acquire_deploy_lock())
            second.release_deploy_lock()

    def test_atomic_restore_replaces_complete_file(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            backup = directory / 'backup'
            config = directory / 'nftables.conf'
            backup.write_text('valid backup\n')
            config.write_text('broken config\n')
            guard = failsafe_module.Failsafe.__new__(failsafe_module.Failsafe)
            guard.backup_file = str(backup)
            guard.config_file = str(config)

            guard.atomic_restore_config()

            self.assertEqual(config.read_text(), 'valid backup\n')
            self.assertEqual(list(directory.glob('.nftables.conf.rollback-*')), [])

    def test_failed_atomic_replace_leaves_original_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            backup = directory / 'backup'
            config = directory / 'nftables.conf'
            backup.write_text('valid backup\n')
            config.write_text('original config\n')
            guard = failsafe_module.Failsafe.__new__(failsafe_module.Failsafe)
            guard.backup_file = str(backup)
            guard.config_file = str(config)

            with mock.patch.object(failsafe_module.os, 'replace', side_effect=OSError('replace failed')):
                with self.assertRaisesRegex(OSError, 'replace failed'):
                    guard.atomic_restore_config()

            self.assertEqual(config.read_text(), 'original config\n')
            self.assertEqual(list(directory.glob('.nftables.conf.rollback-*')), [])


if __name__ == '__main__':
    unittest.main()
