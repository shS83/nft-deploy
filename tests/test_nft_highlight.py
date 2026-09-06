from pathlib import Path
import re
import tempfile
import unittest
from nft_highlight import highlight_ruleset, NANORC


class HighlightTests(unittest.TestCase):
    def render(self, syntax, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'syntax.nanorc'
            path.write_text(syntax)
            return highlight_ruleset(text, path)

    def test_later_rules_override_and_text_is_preserved(self):
        syntax = 'color red "accept"\ncolor yellow "\"[^\"]*\""\n'
        text = 'accept "accept"\n'
        colored = self.render(syntax, text)
        self.assertEqual(colored, '\033[31maccept\033[0m \033[33m"accept"\033[0m\n')
        self.assertEqual(re.sub(r'\x1b\[[0-9;]*m', '', colored), text)

    def test_background_and_multiple_expressions(self):
        colored = self.render('color ,green "[[:blank:]]+$"\ncolor brightred "foo" "bar"\n', 'foo bar  \n')
        self.assertEqual(colored, '\033[91mfoo\033[0m \033[91mbar\033[0m\033[42m  \033[0m\n')

    def test_missing_or_invalid_syntax_returns_plain_text(self):
        self.assertEqual(highlight_ruleset('plain', '/nonexistent/nft.nanorc'), 'plain')
        self.assertEqual(self.render('color green "["', 'plain'), 'plain')
        self.assertEqual(self.render('color unknown "plain"', 'plain'), 'plain')

    @unittest.skipUnless(NANORC.exists(), 'system nftables.nanorc is not installed')
    def test_installed_nftables_syntax(self):
        text = 'table inet filter {\n accept drop "$variable" @ports # comment\n}\n'
        colored = highlight_ruleset(text)
        for fragment in ('\033[32mtable', '\033[33minet', '\033[94maccept', '\033[31mdrop', '\033[91m$variable', '\033[91m@ports', '\033[36m # comment'):
            self.assertIn(fragment, colored)
        self.assertEqual(re.sub(r'\x1b\[[0-9;]*m', '', colored), text)

    def test_posix_backslashes_in_strings_and_symbols(self):
        syntax = '''color yellow ""([^"\\]|\\\\.)*"|'([^'\\]|\\\\.)*'"
color green "[][{}():;|`$<>!=&\\]"
'''
        text = '"escaped \\" quote" []\\'
        colored = self.render(syntax, text)
        self.assertIn('\033[33m', colored)
        self.assertIn('\033[32m[]\\', colored)
        self.assertEqual(re.sub(r'\x1b\[[0-9;]*m', '', colored), text)


if __name__ == '__main__':
    unittest.main()
