"""Render the single-line color rules used by nano's nftables syntax file."""
from pathlib import Path
import re


NANORC = Path('/usr/share/nano/nftables.nanorc')
RESET = '\033[0m'
COLORS = {name: index for index, name in enumerate(
    ('black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white')
)}


def _color(spec):
    foreground, _, background = spec.partition(',')
    codes = []
    for name, base in ((foreground, 30), (background, 40)):
        if not name:
            continue
        bright = name.startswith('bright')
        if bright:
            name = name[6:]
        codes.append(str(base + COLORS[name] + (60 if bright else 0)))
    return '\033[' + ';'.join(codes) + 'm'


def _pattern(expression):
    # GNU/POSIX word boundaries and character classes used by nftables.nanorc.
    expression = expression.replace(r'\<', r'(?<!\w)(?=\w)')
    expression = expression.replace(r'\>', r'(?<=\w)(?!\w)')
    for name, chars in (('blank', ' \t'), ('space', ' \t\r\n\v\f'),
                        ('alpha', 'A-Za-z'), ('alnum', 'A-Za-z0-9')):
        expression = expression.replace(f'[:{name}:]', chars)
    # Backslashes are literal inside POSIX bracket expressions. Python's re
    # instead treats them as escapes, including the backslash before a closing ].
    converted = []
    in_class = False
    first = False
    escaped = False
    for char in expression:
        if in_class:
            if char == ']' and not first:
                in_class = False
            converted.append('\\\\' if char == '\\' else char)
            if char != '^' or not first:
                first = False
        else:
            converted.append(char)
            if char == '[' and not escaped:
                in_class = True
                first = True
            if char == '\\' and not escaped:
                escaped = True
            else:
                escaped = False
    return ''.join(converted)


def highlight_ruleset(text, syntax_file=NANORC):
    """Apply later nano rules over earlier ones; return plain text on errors."""
    try:
        rules = []
        for line in Path(syntax_file).read_text().splitlines():
            declaration = re.match(r'^\s*(i?color)\s+(\S+)\s+"(.*)"\s*$', line)
            if declaration is None:
                continue
            kind, color, expressions = declaration.groups()
            style = _color(color)
            for expression in re.split(r'"\s+"', expressions):
                rules.append((re.compile(_pattern(expression), re.I if kind == 'icolor' else 0), style))
        output = []
        for line in text.splitlines(keepends=True):
            body = line.rstrip('\r\n')
            ending = line[len(body):]
            styles = [None] * len(body)
            for pattern, style in rules:
                for match in pattern.finditer(body):
                    styles[match.start():match.end()] = [style] * (match.end() - match.start())
            current = None
            for char, style in zip(body, styles):
                if style != current:
                    if current is not None:
                        output.append(RESET)
                    if style is not None:
                        output.append(style)
                    current = style
                output.append(char)
            if current is not None:
                output.append(RESET)
            output.append(ending)
        return ''.join(output)
    except (OSError, UnicodeError, KeyError, re.error):
        return text
