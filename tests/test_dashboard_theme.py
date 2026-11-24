"""The dashboard's colours, theme and marks (docs/dashboard-design.md): the tokens of the light
and the dark theme, the contrast of every text and mark pair they make, and no colour of its own
in a rule. Reads the shipped stylesheets as text; no server or browser.
"""

import importlib.util
import re
import unittest
from pathlib import Path

STATIC = Path(importlib.util.find_spec("depbee.dashboard").origin).parent / "static"
TOKEN = re.compile(r"(--[\w-]+)\s*:\s*([^;]+);")
COLOUR = re.compile(r"#[0-9a-fA-F]{6}\b")
BLOCKS = {
    "light": re.compile(r"^:root \{(.*?)^\}", re.S | re.M),
    "dark": re.compile(
        r'^@media \(prefers-color-scheme: dark\) \{\s*:root:not\(\[data-theme="light"\]\) \{'
        r"(.*?)\}\s*\}",
        re.S | re.M,
    ),
    "forced": re.compile(r'^:root\[data-theme="dark"\] \{(.*?)^\}', re.S | re.M),
}
# text (or a mark), and the grounds it is read on: 4.5:1 for each pair.
TEXT = {
    "--ink": ("--surface", "--sheet", "--head", "--honey-wash"),
    "--muted": ("--surface", "--sheet", "--head", "--honey-wash"),
    "--risk": ("--sheet", "--risk-wash", "--honey-wash"),
    "--hold": ("--sheet", "--hold-wash", "--honey-wash"),
    "--pass": ("--sheet", "--pass-wash", "--honey-wash"),
    "--fail": ("--sheet", "--fail-wash", "--honey-wash"),
    "--on-honey": ("--honey",),
    "--rail-ink": ("--rail-bg", "--rail-current"),
    "--rail-muted": ("--rail-bg", "--rail-current"),
    "--rail-risk": ("--rail-bg", "--rail-current"),
    "--rail-hold": ("--rail-bg", "--rail-current"),
    "--rail-pass": ("--rail-bg", "--rail-current"),
    "--rail-fail": ("--rail-bg", "--rail-current"),
    "--rail-none": ("--rail-bg", "--rail-current"),
}
# The glyph inside a mark, on each mark colour; and the rail's glyph on the rail's marks.
GLYPH = {
    "--glyph": ("--risk", "--hold", "--pass", "--fail", "--muted"),
    "--rail-glyph": ("--rail-risk", "--rail-hold", "--rail-pass", "--rail-fail", "--rail-none"),
}


def strip_comments(css):
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


def tokens(css, theme):
    found = BLOCKS[theme].search(strip_comments(css))
    return dict(TOKEN.findall(found.group(1))) if found else {}


def resolved(values, name):
    value = values[name].strip()
    while value.startswith("var("):
        value = values[value[4:-1].strip()].strip()
    return value


def luminance(colour):
    channels = [int(colour[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(first, second):
    high, low = sorted((luminance(first), luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


class ThemeTokenTests(unittest.TestCase):
    def setUp(self):
        self.css = (STATIC / "style.css").read_text("utf-8")
        self.light = tokens(self.css, "light")
        self.colours = {name for name, value in self.light.items() if COLOUR.fullmatch(value.strip())}

    def themes(self):
        """Each theme's full set of values: the dark one is the light one with its own colours."""
        return {"light": self.light, "dark": {**self.light, **tokens(self.css, "dark")}}

    def test_every_colour_token_has_a_dark_value(self):
        dark, forced = tokens(self.css, "dark"), tokens(self.css, "forced")
        self.assertTrue(self.colours)
        # Every colour is redefined, and nothing the light theme does not have.
        self.assertLessEqual(self.colours, set(dark))
        self.assertLessEqual(set(dark), set(self.light))
        self.assertEqual(dark, forced)

    def test_text_and_marks_meet_contrast(self):
        for theme, values in self.themes().items():
            for pairs, floor in ((TEXT, 4.5), (GLYPH, 3)):
                for text, grounds in pairs.items():
                    for ground in grounds:
                        ratio = contrast(resolved(values, text), resolved(values, ground))
                        self.assertGreaterEqual(ratio, floor, f"{theme}: {text} on {ground}")

    def test_no_colour_outside_the_tokens(self):
        for name in ("style.css", "overview.css"):
            css = strip_comments((STATIC / name).read_text("utf-8"))
            for block in BLOCKS.values():
                css = block.sub("", css)
            literals = re.findall(r"(?<=[\s:(,])#[0-9a-fA-F]{3,8}\b|\b(?:rgba?|hsla?)\(", css)
            self.assertEqual(literals, [], name)


if __name__ == "__main__":
    unittest.main()
