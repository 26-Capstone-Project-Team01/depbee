"""The dashboard's colours, theme and marks (docs/dashboard-design.md): the tokens of the light
and the dark theme, the contrast of every text and mark pair they make, and no colour of its own
in a rule. Reads the shipped stylesheets as text; no server or browser.
"""

import importlib.util
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_dashboard import BASE, SESSION, DashboardFixture, S

from depbee import history

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
        self.colours = {
            name for name, value in self.light.items() if COLOUR.fullmatch(value.strip())
        }

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


class MarkTests(unittest.TestCase):
    """A verdict's mark is a hexagon of its colour with a sign inside (style.css .cell)."""

    def test_every_kind_has_a_sign_of_its_own(self):
        from depbee.dashboard import app

        kinds = {"none"} | set(app.CELLS.values()) | set(app.APPLY_CELLS.values())
        kinds |= {cell for cell, _, _ in app.STATES.values()}
        kinds |= {cell for cell, _ in app.DECISIONS.values()}
        self.assertEqual(kinds, {"risk", "hold", "pass", "none", "fail", "stale", "gone"})
        css = strip_comments((STATIC / "style.css").read_text("utf-8"))
        signs = {}
        for kind in kinds:
            rule = re.search(rf"^\.cell\.{kind}::after \{{([^}}]*)\}}", css, re.M)
            self.assertIsNotNone(rule, kind)
            signs[kind] = re.search(r"clip-path: (polygon\([^)]*\))", rule.group(1)).group(1)
        self.assertEqual(len(set(signs.values())), len(kinds), signs)


def covered(path):
    """The code points of coverage.txt: lines of U+XXXX or U+XXXX-U+YYYY."""
    points = set()
    for line in path.read_text("utf-8").split():
        first, _, last = line.partition("-")
        points.update(range(int(first[2:], 16), int((last or first)[2:], 16) + 1))
    return points


class FontCoverageTests(unittest.TestCase):
    def test_the_subset_covers_every_character_the_console_can_show(self):
        """A new message with a syllable the bundled subset lacks would be drawn in another font:
        rebuild the fonts (scripts/build_dashboard_fonts.py) when this fails."""
        points = covered(STATIC / "fonts" / "coverage.txt")
        package = STATIC.parent.parent
        texts = [*STATIC.parent.glob("templates/*.html"), *package.rglob("*.py")]
        missing = sorted(
            {c for path in texts for c in path.read_text("utf-8") if ord(c) > 0x7E}
            - {chr(p) for p in points}
        )
        self.assertEqual(missing, [])


class FontTests(DashboardFixture):
    def test_the_two_fonts_are_served_and_nothing_else(self):
        self.assertEqual(self.app.FONTS, ("NotoSansKR-depbee.woff2", "JetBrainsMono-depbee.woff2"))
        for name in self.app.FONTS:
            response = self.get(f"/static/fonts/{name}")
            self.assertEqual(
                (response.status_code, response.headers["content-type"]), (200, "font/woff2")
            )
            self.assertEqual(response.content, (STATIC / "fonts" / name).read_bytes())
        for name in ("x.woff2", "OFL-NotoSansKR.txt", "coverage.txt", "%2e%2e/style.css"):
            self.assertEqual(self.get(f"/static/fonts/{name}").status_code, 404, name)

    def test_the_page_may_load_its_own_fonts_and_nothing_from_elsewhere(self):
        policy = self.get("/").headers["content-security-policy"]
        self.assertIn("font-src 'self'", policy)
        self.assertIn("default-src 'none'", policy)


class ThemeChoiceTests(unittest.TestCase):
    """The theme chosen on the rail, as saved in the user's settings folder (theme.py)."""

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        patched = mock.patch.dict(os.environ, {"DEPBEE_CONFIG_DIR": folder.name})
        patched.start()
        self.addCleanup(patched.stop)
        self.file = Path(folder.name) / "dashboard.json"
        from depbee.dashboard import theme

        self.theme = theme

    def test_each_press_moves_to_the_next_theme(self):
        self.assertEqual(self.theme.THEMES, ("system", "light", "dark"))
        self.assertEqual(
            [self.theme.next_of(v) for v in self.theme.THEMES], ["light", "dark", "system"]
        )

    def test_what_was_saved_is_loaded(self):
        self.assertEqual(self.theme.load(), "system")
        self.theme.save("dark")
        self.assertEqual(json.loads(self.file.read_text("utf-8")), {"theme": "dark"})
        self.assertEqual(self.theme.load(), "dark")

    def test_a_broken_file_is_the_system_theme(self):
        for text in ("{", '{"theme": "blue"}', '["dark"]', '{"theme": 1}', "x" * 70000):
            self.file.write_text(text, "utf-8")
            self.assertEqual(self.theme.load(), "system", text[:20])

    def test_an_unknown_theme_is_not_saved(self):
        with self.assertRaises(ValueError):
            self.theme.save("blue")
        self.assertFalse(self.file.exists())


class ThemeRouteTests(DashboardFixture):
    """The rail's theme form: a POST with the session that saves the choice and comes back."""

    def choose(self, value, back, session=SESSION, origin=BASE):
        return self.client.post(S + "/theme", data={"session": session, "theme": value, "back": back},
                                headers={"origin": origin}, follow_redirects=False)  # fmt: skip

    def stored(self):
        path = Path(os.environ["DEPBEE_CONFIG_DIR"]) / "dashboard.json"
        return json.loads(path.read_text("utf-8"))["theme"] if path.exists() else None

    def form(self, html):
        """The theme form's fields and its button's value and words, or None."""
        match = re.search(
            rf'<form class="theme" method="post" action="{S}/theme">(.*?)</form>', html, re.S
        )
        if not match:
            return None
        fields = dict(
            re.findall(r'<input type="hidden" name="(\w+)" value="([^"]*)">', match.group(1))
        )
        button = re.search(
            r'<button type="submit" name="theme" value="(\w+)">(.*?)</button>', match.group(1), re.S
        )
        return fields, button.group(1), re.sub(r"<[^>]+>", "", button.group(2))

    def test_a_page_offers_the_next_theme_and_comes_back_to_itself(self):
        history.register_project(self.project)
        html = self.page("/model")
        self.assertIn('<html lang="ko">', html)
        fields, value, words = self.form(html)
        self.assertEqual(fields, {"session": SESSION, "back": f"{S}/model"})
        self.assertEqual(value, "light")
        self.assertTrue(words.startswith("화면: 시스템 설정"), words)
        self.assertEqual(self.form(self.page("/?manage=1"))[0]["back"], f"{S}/?manage=1")

    def test_the_chosen_theme_is_on_every_page(self):
        history.register_project(self.project)
        response = self.choose("dark", f"{S}/?manage=1")
        self.assertEqual(
            (response.status_code, response.headers["location"]), (303, f"{S}/?manage=1")
        )
        self.assertEqual(self.stored(), "dark")
        html = self.page("/model")
        self.assertIn('<html lang="ko" data-theme="dark">', html)
        self.assertEqual(self.form(html)[1:], ("system", "화면: 어둡게. 시스템 설정 따르기"))

    def test_a_way_back_outside_the_console_goes_home(self):
        for back in ("https://evil.example/", "//evil.example/x", "/s/other-session/model",
                     f"{S}/previews/1/apply", f"{S}/theme", f"{S}/projects", "", f"{S}",
                     f"{S}/model\r\nX-Test: 1", f"{S}\\model", f"{S}//evil.example",
                     f"{S}/../model", f"{S}/static/style.css"):  # fmt: skip
            response = self.choose("light", back)
            self.assertEqual(
                (response.status_code, response.headers["location"]), (303, f"{S}/"), back
            )
        response = self.choose("light", f"{S}/projects/1/updates?item=3.2")
        self.assertEqual(response.headers["location"], f"{S}/projects/1/updates?item=3.2")

    def test_a_wrong_theme_or_session_changes_nothing(self):
        self.assertEqual(self.choose("blue", f"{S}/model").status_code, 400)
        self.assertEqual(self.choose("dark", f"{S}/model", session="wrong").status_code, 403)
        self.assertEqual(
            self.choose("dark", f"{S}/model", origin="http://evil.example").status_code, 403
        )
        self.assertIsNone(self.stored())

    def test_a_theme_that_cannot_be_saved_keeps_the_current_one(self):
        history.register_project(self.project)
        with mock.patch("depbee.dashboard.theme.save", side_effect=OSError("denied")):
            response = self.choose("dark", f"{S}/model")
        self.assertEqual(response.status_code, 503)
        self.assertIn("화면 테마를 저장하지 못했습니다", response.text)
        self.assertIsNone(self.form(response.text))
        self.assertIn('<html lang="ko">', self.page("/model"))

    def test_a_page_that_answers_a_post_has_no_theme_form(self):
        history.register_project(self.project)
        response = self.post("relative/folder", session=SESSION)
        self.assertEqual(response.status_code, 400)
        self.assertIsNone(self.form(response.text))

    def test_the_start_page_keeps_its_one_button(self):
        self.choose("dark", f"{S}/")
        html = self.page("/")
        self.assertIn('<html lang="ko" data-theme="dark">', html)
        self.assertIsNone(self.form(html))
        self.assertEqual(html.count("<button"), 1)


if __name__ == "__main__":
    unittest.main()
