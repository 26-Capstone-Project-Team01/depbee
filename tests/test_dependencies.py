"""Dependency list of a project's package-lock.json (service.list_dependencies, SVC-07).

Synthetic lockfiles only, inside each test run's folder: no npm, registry or package code.
"""

from test_workflow import Fixture, package

from depbee.contracts import GuardError
from depbee.service import list_dependencies


class DependencyListTests(Fixture):
    def lock(self, version=3, **root):
        return {
            "lockfileVersion": version,
            "packages": {
                "": {"name": "app", **root},
                "node_modules/a": package("1.0.0"),
                "node_modules/a/node_modules/b": package("2.0.0"),
                "node_modules/b": package("3.0.0"),
                "node_modules/dev": package("4.0.0"),
                "node_modules/alias": {**package("5.0.0"), "name": "real-name"},
                "packages/ws": {"version": "0.0.1"},  # a workspace source folder, not installed
                "node_modules/ws": {"resolved": "packages/ws", "link": True},
            },
        }

    def test_direct_and_nested_in_v2_and_v3(self):
        root = {"dependencies": {"a": "^1.0.0", "alias": "npm:real-name@5"},
                "devDependencies": {"dev": "4"}, "optionalDependencies": {},
                "peerDependencies": {"ws": "*"}}  # fmt: skip
        for version in (2, 3):
            with self.subTest(version=version):
                self.write(self.head, self.lock(version, **root))
                self.assertEqual(list_dependencies(self.project), [
                    {"location": "node_modules/a", "name": "a", "version": "1.0.0",
                     "direct": True},
                    # b is a direct name only at the top; the copy under a is nested.
                    {"location": "node_modules/a/node_modules/b", "name": "b", "version": "2.0.0",
                     "direct": False},
                    {"location": "node_modules/alias", "name": "real-name", "version": "5.0.0",
                     "direct": True},
                    {"location": "node_modules/b", "name": "b", "version": "3.0.0",
                     "direct": False},
                    {"location": "node_modules/dev", "name": "dev", "version": "4.0.0",
                     "direct": True},
                    {"location": "node_modules/ws", "name": "ws", "version": None,
                     "direct": True},
                ])  # fmt: skip

    def test_declared_fields_of_each_location_only_when_asked(self):
        root = {"dependencies": {"a": "^1.0.0", "alias": "npm:real-name@5", "real-name": "^9"},
                "devDependencies": {"dev": "4", "b": "3"}, "optionalDependencies": {"a": "^1"},
                "peerDependencies": {"b": "*", "ws": "*"}}  # fmt: skip
        self.write(self.head, self.lock(**root))
        rows = list_dependencies(self.project, declared=True)
        self.assertEqual({row["location"]: row["declared"] for row in rows}, {
            "node_modules/a": ["dependencies", "optionalDependencies"],  # both, in field order
            "node_modules/a/node_modules/b": [],  # a nested copy of a declared name
            # Declared as "alias": the package's own name (real-name) is another declaration.
            "node_modules/alias": ["dependencies"],
            "node_modules/b": ["devDependencies", "peerDependencies"],
            "node_modules/dev": ["devDependencies"],
            "node_modules/ws": ["peerDependencies"],
        })  # fmt: skip
        self.assertEqual([row["direct"] for row in rows], [bool(row["declared"]) for row in rows])
        # Without the option the rows are as they were.
        plain = list_dependencies(self.project)
        self.assertEqual(plain, [{k: v for k, v in row.items() if k != "declared"} for row in rows])
        self.assertEqual(set(plain[0]), {"location", "name", "version", "direct"})

    def test_no_root_entry_means_no_direct_dependency(self):
        lock = self.lock()
        del lock["packages"][""]
        self.write(self.head, lock)
        self.assertFalse(any(row["direct"] for row in list_dependencies(self.project)))
        declared = list_dependencies(self.project, declared=True)
        self.assertEqual({tuple(row["declared"]) for row in declared}, {()})

    def test_unreadable_lockfiles_are_errors(self):
        cases = {
            "lockfileVersion 1": {"lockfileVersion": 1, "dependencies": {}},
            "no packages": {"lockfileVersion": 3},
            "bad entry": {"lockfileVersion": 3, "packages": {"node_modules/a": []}},
            "bad root": {"lockfileVersion": 3, "packages": {"": []}},
            "bad direct names": self.lock(dependencies=["a"]),
        }
        for label, lock in cases.items():
            with self.subTest(label):
                self.write(self.head, lock)
                with self.assertRaises(GuardError):
                    list_dependencies(self.project)
        self.head.write_bytes(b"{not json")
        with self.assertRaises(GuardError):
            list_dependencies(self.project)
        self.head.unlink()
        with self.assertRaises(FileNotFoundError):
            list_dependencies(self.project)
