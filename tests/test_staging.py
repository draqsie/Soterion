from __future__ import annotations

import os
import shutil
import unittest

from soterion.scope import Scope, ScopeResolution, SkippedPath, load_scope, resolve_files
from soterion.staging import staged_snapshot
from tests.helpers import RepoTestCase, make_junction, make_symlink


class Staging(RepoTestCase):
    def listed(self, **sections: str) -> tuple[Scope, ScopeResolution]:
        scope = load_scope(self.write_manifest(**sections))
        return scope, resolve_files(scope)

    def test_copies_exactly_the_in_scope_files(self) -> None:
        self.add_file("a.py", "A = 1\n")
        self.add_file("src/b.py", "B = 2\n")
        self.add_file("notes.md")
        self.add_file(".git/config")

        with staged_snapshot(*self.listed()) as snapshot:
            on_disk = sorted(
                path.relative_to(snapshot.root).as_posix()
                for path in snapshot.root.rglob("*")
                if path.is_file()
            )
            self.assertEqual(on_disk, ["a.py", "src/b.py"])
            self.assertEqual((snapshot.root / "src" / "b.py").read_bytes(), b"B = 2\n")
            self.assertEqual(snapshot.files, ("a.py", "src/b.py"))
            self.assertEqual(snapshot.skipped, ())

    def test_snapshot_is_outside_the_repository_and_removed_afterwards(self) -> None:
        self.add_file("a.py")

        with staged_snapshot(*self.listed()) as snapshot:
            root = snapshot.root
            self.assertTrue(root.is_dir())
            self.assertFalse(root.is_relative_to(self.repo))

        self.assertFalse(root.exists())

    def test_snapshot_is_removed_when_the_scan_raises(self) -> None:
        self.add_file("a.py")
        roots = []

        with self.assertRaises(RuntimeError):
            with staged_snapshot(*self.listed()) as snapshot:
                roots.append(snapshot.root)
                raise RuntimeError("scanner blew up")

        self.assertFalse(roots[0].exists())

    @unittest.skipUnless(os.name == "nt", "junctions exist only on Windows")
    def test_directory_swapped_for_a_junction_after_listing_is_not_copied(self) -> None:
        self.add_file("src/b.py", "inside\n")
        self.add_file("outside/b.py", "OUTSIDE CONTENT\n", root=self.tmp)
        scope, resolution = self.listed()
        shutil.rmtree(self.repo / "src")
        make_junction(self.repo / "src", self.tmp / "outside")

        with staged_snapshot(scope, resolution) as snapshot:
            self.assertFalse((snapshot.root / "src" / "b.py").exists())
            self.assertEqual(snapshot.files, ())
            self.assertEqual(snapshot.skipped, (SkippedPath("src/b.py", "link"),))

    def test_file_swapped_for_a_symlink_after_listing_is_not_copied(self) -> None:
        self.add_file("a.py", "inside\n")
        outside = self.add_file("outside/secret.py", "OUTSIDE CONTENT\n", root=self.tmp)
        scope, resolution = self.listed()
        (self.repo / "a.py").unlink()
        make_symlink(self.repo / "a.py", outside)

        with staged_snapshot(scope, resolution) as snapshot:
            self.assertFalse((snapshot.root / "a.py").exists())
            self.assertEqual(snapshot.skipped, (SkippedPath("a.py", "link"),))

    def test_file_that_grew_past_the_limit_after_listing_is_not_copied(self) -> None:
        self.add_file("a.py", "0123456789")
        scope, resolution = self.listed(limits="[limits]\nmax_file_size_bytes = 10\n")
        self.add_file("a.py", "0123456789A")

        with staged_snapshot(scope, resolution) as snapshot:
            self.assertFalse((snapshot.root / "a.py").exists())
            self.assertEqual(snapshot.files, ())
            self.assertEqual(snapshot.skipped, (SkippedPath("a.py", "too_large"),))

    def test_file_deleted_after_listing_is_reported(self) -> None:
        self.add_file("a.py")
        self.add_file("b.py")
        scope, resolution = self.listed()
        (self.repo / "a.py").unlink()

        with staged_snapshot(scope, resolution) as snapshot:
            self.assertEqual(snapshot.files, ("b.py",))
            self.assertEqual(snapshot.skipped, (SkippedPath("a.py", "unreadable"),))


if __name__ == "__main__":
    unittest.main()
