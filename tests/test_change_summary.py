import contextlib
import importlib.util
import io
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('deployer_summary', ROOT / 'nft-deploy.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ChangeSummaryTests(unittest.TestCase):
    def render(self, states, proposed=False):
        deployer = m.Deployer.__new__(m.Deployer)
        deployer.STATE = states
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            deployer.print_change_summary(proposed=proposed)
        return output.getvalue()

    def test_deployed_chain_names_are_printed_once_in_order(self):
        output = self.render([
            m.Deployer.State.INPUT,
            m.Deployer.State.FORWARD,
            m.Deployer.State.INPUT,
        ])
        self.assertIn('Changes were made to', output)
        self.assertIn('INPUT, FORWARD', output)
        self.assertNotIn('INPUT, FORWARD, INPUT', output)

    def test_dry_run_uses_proposed_wording(self):
        output = self.render([m.Deployer.State.OUTPUT], proposed=True)
        self.assertIn('Changes were proposed to', output)
        self.assertIn('OUTPUT', output)

    def test_no_selected_chain_is_reported_as_none(self):
        output = self.render([m.Deployer.State.NONE])
        self.assertIn('NONE', output)


if __name__ == '__main__':
    unittest.main()
