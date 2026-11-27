"""The packages view's split of direct and indirect dependencies (templates/dep_split.html): the
two counts of the whole lockfile, the bar that repeats them, the keys as links of the kind
filter, and that an empty lockfile is a count while one that cannot be read is not.

Synthetic lockfiles in each test's folder, as in test_dashboard.py; no server, npm or registry.
"""

import re
import unittest
from html import unescape

import test_dashboard  # the module: its test classes, imported by name, would run again here
from test_workflow import package

from depbee import history

# A key: the element (a link, or words for a kind with none), its kind, the rest of its tag, then
# the count and what follows it in the key.
KEY = re.compile(
    r'<(a|span) class="dep-key (direct|nested)"([^>]*)>.*?<strong class="dep-count">(\d+)'
    r'<span class="dep-unit">개</span></strong>(.*?)</\1>\n', re.S,
)  # fmt: skip
BAR = re.compile(r'<svg class="dep-bar" aria-hidden="true">(.*?)</svg>')


def keys(html):
    """{kind: (element, address or None, marked as listed now, count, share as words or None)}"""
    found = {}
    for element, kind, tag, count, rest in KEY.findall(html):
        address = re.search(r'href="([^"]*)"', tag)
        share = re.search(r'<span class="dep-share">([^<]*)</span>', rest)
        found[kind] = (element, unescape(address[1]) if address else None,
                       'aria-current="true"' in tag, int(count), share[1] if share else None)  # fmt: skip
    return found


@unittest.skipUnless(test_dashboard.WEB, "needs the dashboard extra")
class DependencySplitTests(test_dashboard.DashboardFixture):
    def lockfile(self, declared, locations):
        """The project's lockfile: declared names in the root entry, a package at each location."""
        self.new["packages"] = {
            "": {"dependencies": dict.fromkeys(declared, "^1.0.0")},
            **{f"node_modules/{location}": package() for location in locations},
        }
        self.save_locks()
        history.register_project(self.project)

    def test_the_counts_are_of_the_whole_lockfile_whatever_the_list_shows(self):
        # hoisted sits at the top of node_modules without a declaration, and a second copy of
        # it sits under example: indirect both, and two installed locations.
        self.lockfile(["example"], ["example", "hoisted", "example/node_modules/hoisted"])
        for url in ("/projects/1", "/projects/1?q=example&scope=direct", "/projects/1?q=none",
                    "/projects/1?scope=nested&show=unchecked"):  # fmt: skip
            with self.subTest(url=url):
                html = self.page(url)
                found = keys(html)
                self.assertEqual({kind: key[3:] for kind, key in found.items()},
                                 {"direct": (1, "33%"), "nested": (2, "67%")})  # fmt: skip
                # The bar: the direct share solid, then the gap before the hatched rest.
                self.assertEqual(BAR.search(html)[1],
                                 '<rect class="direct" width="33.33%" height="100%"/>'
                                 '<rect class="gap" x="33.33%" width="2" height="100%"/>')  # fmt: skip
                self.assertIn("package-lock.json의 설치 위치 3곳을 셉니다.", html)
                self.assertIn("node_modules 바로 아래에 놓여도 선언하지 않았으면 간접 의존성", html)
        html = self.page("/projects/1")
        # What each kind means is in view, and the label is said, not only drawn.
        for words in ("직접 의존성</span>", "간접 의존성</span>", "package.json에 선언한 패키지",
                      "다른 패키지가 필요로 해서 설치된 패키지"):  # fmt: skip
            self.assertIn(words, html)
        # The one count line: the sentence it replaces is gone, its question mark is here.
        self.assertNotIn('class="tally"', html)
        self.assertEqual(html.count('popovertarget="help-reading"'), 1)
        self.assertLess(html.index('id="help-reading"'), html.index('class="dep-split"'))
        self.assertLess(html.index('class="dep-split"'), html.index('class="filter-tabs"'))

    def test_a_key_lists_its_kind_alone_and_keeps_the_search_and_the_tab(self):
        self.lockfile(["example"], ["example", "hoisted"])
        found = keys(self.page("/projects/1"))
        self.assertEqual({kind: key[:3] for kind, key in found.items()}, {
            "direct": ("a", "/projects/1?scope=direct", False),
            "nested": ("a", "/projects/1?scope=nested", False)})  # fmt: skip
        html = self.page("/projects/1?q=HOI&scope=nested&show=unchecked")
        found = keys(html)
        self.assertEqual({kind: key[:3] for kind, key in found.items()}, {
            "direct": ("a", "/projects/1?q=HOI&scope=direct&show=unchecked", False),
            # The kind listed now is marked, and its link lists every kind again.
            "nested": ("a", "/projects/1?q=HOI&show=unchecked", True)})  # fmt: skip
        self.assertIn("지금 이 종류만 보는 중입니다. 누르면 모든 종류를 봅니다", html)
        # The name searched for is written into the address encoded, never as markup.
        html = self.page("/projects/1?q=a%26b%22%3Cc")
        self.assertIn('href="/projects/1?q=a%26b%22%3Cc&amp;scope=direct"', html)
        # Every address a key names is one the view opens.
        for _, address, _, _, _ in found.values():
            self.assertEqual(self.get(address).status_code, 200, address)
        # The lists the keys open hold what the counts say.
        for kind, count in (("direct", 1), ("nested", 1)):
            listed = test_dashboard.package_rows(self.page(f"/projects/1?scope={kind}"))
            self.assertEqual(len(listed), count, kind)

    def test_a_kind_with_none_is_words_and_a_thin_share_is_still_drawn(self):
        self.lockfile(["example"], ["example"])
        html = self.page("/projects/1")
        self.assertEqual(keys(html), {"direct": ("a", "/projects/1?scope=direct", False, 1, "100%"),
                                      "nested": ("span", None, False, 0, "0%")})  # fmt: skip
        self.assertEqual(BAR.search(html)[1], '<rect class="direct" width="100.0%" height="100%"/>')
        # An address kept from before still has its way back to every kind.
        self.assertEqual(keys(self.page("/projects/1?scope=nested"))["nested"][:3],
                         ("a", "/projects/1", True))  # fmt: skip

        self.new["packages"].update(
            {f"node_modules/example/node_modules/n{index}": package() for index in range(199)})  # fmt: skip
        self.save_locks()
        html = self.page("/projects/1")
        self.assertEqual({kind: key[3:] for kind, key in keys(html).items()},
                         {"direct": (1, "1% 미만"), "nested": (199, "99% 초과")})  # fmt: skip
        self.assertIn('<rect class="direct" width="2%" height="100%"/>', html)

        # Nothing declared: no solid share at all, the whole bar is the hatched rest.
        self.new["packages"][""] = {}
        self.save_locks()
        html = self.page("/projects/1")
        self.assertEqual({kind: key[::3] for kind, key in keys(html).items()},
                         {"direct": ("span", 0), "nested": ("a", 200)})  # fmt: skip
        self.assertEqual(BAR.search(html)[1], "")
        self.assertNotIn('class="dep-split none"', html)

    def test_no_dependency_is_a_count_and_an_unreadable_lockfile_is_not(self):
        self.lockfile([], [])
        html = self.page("/projects/1")
        self.assertIn('<div class="dep-split none" role="group"', html)
        # Zero is said for both kinds, as words (nothing to list), with no share and no bar.
        self.assertEqual(keys(html), {"direct": ("span", None, False, 0, None),
                                      "nested": ("span", None, False, 0, None)})  # fmt: skip
        self.assertEqual(BAR.search(html)[1], "")
        self.assertIn("package-lock.json을 읽었고 설치 위치가 0곳입니다.", html)

        # A lockfile that cannot be read, then a folder that is gone: no count is claimed.
        self.head.write_text("{broken", encoding="utf-8")
        html = self.page("/projects/1")
        self.assertIn("package-lock.json을 읽을 수 없습니다", html)
        self.assertNotIn("dep-split", html)
        self.assertNotIn("dep-count", html)
        self.head.unlink()
        self.project.rmdir()
        self.assertNotIn("dep-split", self.page("/projects/1"))


if __name__ == "__main__":
    unittest.main()
