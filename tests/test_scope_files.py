from __future__ import annotations

import os
import unittest

from soterion.scope import ScopeError, ScopeResolution, SkippedPath, load_scope, resolve_files
from tests.helpers import RepoTestCase, make_junction, make_symlink

INCLUDE_EVERYTHING = '[scope]\ninclude = ["**"]\n'


class FileSelection(RepoTestCase):
    def resolve(self, **sections: str) -> ScopeResolution:
        return resolve_files(load_scope(self.write_manifest(**sections)))

    def test_only_files_matching_include_are_in_scope(self) -> None:
        self.add_file("a.py")
        self.add_file("src/b.py")
        self.add_file("docs/c.md")

        self.assertEqual(self.resolve().files, ("a.py", "src/b.py"))

    def test_exclude_overrides_include(self) -> None:
        self.add_file("a.py")
        self.add_file("src/b.py")

        resolution = self.resolve(scope='[scope]\ninclude = ["**/*.py"]\nexclude = ["src/**"]\n')

        self.assertEqual(resolution.files, ("a.py",))

    def test_exclude_ignores_letter_case(self) -> None:
        self.add_file("a.py")
        self.add_file("Secrets/key.py")

        resolution = self.resolve(scope='[scope]\ninclude = ["**/*.py"]\nexclude = ["secrets/**"]\n')

        self.assertEqual(resolution.files, ("a.py",))

    def test_include_does_not_widen_across_letter_case(self) -> None:
        self.add_file("SRC/a.py")

        resolution = self.resolve(scope='[scope]\ninclude = ["src/**"]\n')

        self.assertEqual(resolution.files, ())

    def test_git_metadata_is_never_in_scope(self) -> None:
        self.add_file("a.py")
        self.add_file(".git/config")
        self.add_file(".git/hooks/pre-commit.py")
        self.add_file("vendor/lib/.git/config")
        self.add_file("vendor/lib/x.py")
        self.add_file("submodule/.git", "gitdir: ../.git/modules/submodule\n")

        resolution = self.resolve(scope=INCLUDE_EVERYTHING)

        self.assertEqual(resolution.files, ("a.py", "vendor/lib/x.py"))

    def test_file_symlink_pointing_outside_is_skipped_and_reported(self) -> None:
        self.add_file("a.py")
        secret = self.add_file("outside/secret.py", root=self.tmp)
        make_symlink(self.repo / "link.py", secret)

        resolution = self.resolve()

        self.assertEqual(resolution.files, ("a.py",))
        self.assertIn(SkippedPath("link.py", "link"), resolution.skipped)

    def test_directory_symlink_is_not_followed(self) -> None:
        self.add_file("a.py")
        self.add_file("outside/secret.py", root=self.tmp)
        make_symlink(self.repo / "linked", self.tmp / "outside")

        resolution = self.resolve()

        self.assertEqual(resolution.files, ("a.py",))
        self.assertIn(SkippedPath("linked", "link"), resolution.skipped)

    @unittest.skipUnless(os.name == "nt", "junctions exist only on Windows")
    def test_junction_is_not_followed(self) -> None:
        self.add_file("a.py")
        self.add_file("outside/secret.py", root=self.tmp)
        make_junction(self.repo / "linked", self.tmp / "outside")

        resolution = self.resolve()

        self.assertEqual(resolution.files, ("a.py",))
        self.assertIn(SkippedPath("linked", "link"), resolution.skipped)

    def test_oversized_file_is_skipped_and_reported(self) -> None:
        self.add_file("ok.py", "0123456789")
        self.add_file("big.py", "0123456789A")

        resolution = self.resolve(limits="[limits]\nmax_file_size_bytes = 10\n")

        self.assertEqual(resolution.files, ("ok.py",))
        self.assertEqual(resolution.skipped, (SkippedPath("big.py", "too_large"),))

    def test_out_of_scope_files_are_not_reported_as_skipped(self) -> None:
        self.add_file("a.py")
        self.add_file("notes.md", "0123456789A")

        resolution = self.resolve(limits="[limits]\nmax_file_size_bytes = 10\n")

        self.assertEqual(resolution.skipped, ())

    def test_total_size_over_the_limit_is_an_error(self) -> None:
        self.add_file("a.py", "0123456789")
        self.add_file("b.py", "0123456789")

        with self.assertRaises(ScopeError) as caught:
            self.resolve(limits="[limits]\nmax_total_bytes = 19\n")
        self.assertTrue(any("max_total_bytes" in problem for problem in caught.exception.problems))

    def test_total_size_exactly_at_the_limit_is_accepted(self) -> None:
        self.add_file("a.py", "0123456789")
        self.add_file("b.py", "0123456789")

        resolution = self.resolve(limits="[limits]\nmax_total_bytes = 20\n")

        self.assertEqual(resolution.files, ("a.py", "b.py"))

    def test_exceeding_max_files_is_an_error_not_a_truncated_list(self) -> None:
        self.add_file("a.py")
        self.add_file("b.py")

        with self.assertRaises(ScopeError) as caught:
            self.resolve(limits="[limits]\nmax_files = 1\n")
        self.assertTrue(any("max_files" in problem for problem in caught.exception.problems))


if __name__ == "__main__":
    unittest.main()
