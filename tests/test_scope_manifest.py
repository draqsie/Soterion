from __future__ import annotations

import os
import shutil
import unittest

from soterion.scope import ScopeError, load_scope
from tests.helpers import RepoTestCase


class ValidManifest(RepoTestCase):
    def test_loads_repo_root_and_grants_only_listed_actions(self) -> None:
        scope = load_scope(self.write_manifest())

        self.assertEqual(scope.repo_root, self.repo)
        self.assertTrue(scope.permits("analyze"))
        self.assertFalse(scope.permits("propose-fix"))

    def test_propose_fix_is_granted_when_listed(self) -> None:
        scope = load_scope(
            self.write_manifest(actions='[actions]\nallowed = ["analyze", "propose-fix"]\n')
        )

        self.assertTrue(scope.permits("propose-fix"))
        self.assertFalse(scope.permits("merge"))

    def test_authorized_basis_with_reference_is_accepted(self) -> None:
        scope = load_scope(
            self.write_manifest(
                authorization=(
                    '[authorization]\nbasis = "authorized"\nattestation = true\n'
                    'reference = "engagement letter 2026-11"\n'
                )
            )
        )

        self.assertTrue(scope.permits("analyze"))


    def test_no_check_may_use_the_network_by_default(self) -> None:
        self.assertEqual(load_scope(self.write_manifest()).network_checks, frozenset())

    def test_network_access_is_granted_per_check(self) -> None:
        scope = load_scope(
            self.write_manifest(network='[network]\nallowed_checks = ["semgrep"]\n')
        )

        self.assertEqual(scope.network_checks, frozenset({"semgrep"}))


class RejectedManifest(RepoTestCase):
    def assert_rejected(self, mention: str, **sections: str) -> None:
        with self.assertRaises(ScopeError) as caught:
            load_scope(self.write_manifest(**sections))
        problems = caught.exception.problems
        self.assertTrue(any(mention in problem for problem in problems), problems)

    def test_missing_manifest_file(self) -> None:
        with self.assertRaises(ScopeError):
            load_scope(self.tmp / "does-not-exist.toml")

    def test_invalid_toml(self) -> None:
        self.assert_rejected("TOML", head="schema_version = = 1\n")

    def test_unsupported_schema_version(self) -> None:
        self.assert_rejected("schema_version", head="schema_version = 2\n")

    def test_missing_schema_version(self) -> None:
        self.assert_rejected("schema_version", head="")

    def test_missing_authorization(self) -> None:
        self.assert_rejected("authorization", authorization="")

    def test_attestation_must_be_true(self) -> None:
        self.assert_rejected(
            "attestation", authorization='[authorization]\nbasis = "owner"\nattestation = false\n'
        )

    def test_attestation_must_be_a_boolean(self) -> None:
        self.assert_rejected(
            "attestation", authorization='[authorization]\nbasis = "owner"\nattestation = "true"\n'
        )

    def test_unknown_authorization_basis(self) -> None:
        self.assert_rejected(
            "basis", authorization='[authorization]\nbasis = "curious"\nattestation = true\n'
        )

    def test_authorized_basis_requires_reference(self) -> None:
        self.assert_rejected(
            "reference", authorization='[authorization]\nbasis = "authorized"\nattestation = true\n'
        )

    def test_misspelled_key_is_not_silently_ignored(self) -> None:
        self.assert_rejected(
            "exlude", scope='[scope]\ninclude = ["**/*.py"]\nexlude = ["secrets/**"]\n'
        )

    def test_unknown_section(self) -> None:
        self.assert_rejected("network", actions='[actions]\nallowed = ["analyze"]\n[network]\nx = 1\n')

    def test_relative_repo_path(self) -> None:
        self.assert_rejected("repo_path", target='[target]\nrepo_path = "repo"\n')

    def test_url_is_not_a_repo_path(self) -> None:
        self.assert_rejected(
            "repo_path", target='[target]\nrepo_path = "https://example.com/org/repo"\n'
        )

    def test_missing_repo_directory(self) -> None:
        missing = (self.tmp / "missing").as_posix()
        self.assert_rejected("repo_path", target=f'[target]\nrepo_path = "{missing}"\n')

    def test_repo_path_that_is_a_file(self) -> None:
        file_path = self.add_file("not-a-dir.txt", root=self.tmp).as_posix()
        self.assert_rejected("repo_path", target=f'[target]\nrepo_path = "{file_path}"\n')

    @unittest.skipUnless(os.name == "nt", "UNC paths are a Windows concept")
    def test_network_share_is_rejected_before_any_access(self) -> None:
        self.assert_rejected("UNC", target="[target]\nrepo_path = '\\\\fileserver\\share\\repo'\n")

    def test_manifest_stored_inside_the_repo(self) -> None:
        outside = self.write_manifest()
        inside = self.repo / "scope.toml"
        shutil.copy(outside, inside)

        with self.assertRaises(ScopeError) as caught:
            load_scope(inside)
        self.assertTrue(any("inside" in problem for problem in caught.exception.problems))

    def test_include_is_required_and_must_be_a_non_empty_list_of_patterns(self) -> None:
        for scope_section in (
            "[scope]\n",
            "[scope]\ninclude = []\n",
            '[scope]\ninclude = "**"\n',
            "[scope]\ninclude = [1]\n",
            '[scope]\ninclude = [""]\n',
        ):
            with self.subTest(scope_section):
                self.assert_rejected("include", scope=scope_section)

    def test_include_pattern_cannot_leave_the_repo(self) -> None:
        for pattern in ("../**", "src/../../**", "/etc/**", "C:/Users/**", "src\\\\*.py"):
            with self.subTest(pattern):
                self.assert_rejected("include", scope=f'[scope]\ninclude = ["{pattern}"]\n')

    def test_exclude_pattern_cannot_leave_the_repo(self) -> None:
        self.assert_rejected(
            "exclude", scope='[scope]\ninclude = ["**/*.py"]\nexclude = ["../x"]\n'
        )

    def test_missing_actions(self) -> None:
        self.assert_rejected("actions", actions="")

    def test_unknown_action(self) -> None:
        self.assert_rejected("merge", actions='[actions]\nallowed = ["analyze", "merge"]\n')

    def test_propose_fix_without_analyze(self) -> None:
        self.assert_rejected("analyze", actions='[actions]\nallowed = ["propose-fix"]\n')

    def test_limits_must_be_positive_integers(self) -> None:
        for key, value in (
            ("max_file_size_bytes", "0"),
            ("max_file_size_bytes", "true"),
            ("max_file_size_bytes", '"big"'),
            ("max_files", "-1"),
            ("max_total_bytes", "0"),
        ):
            with self.subTest(key=key, value=value):
                self.assert_rejected(key, limits=f"[limits]\n{key} = {value}\n")

    def test_network_permission_must_be_a_list_of_check_ids(self) -> None:
        for value in ('"semgrep"', "[1]", '["Not A Check Id"]', "true"):
            with self.subTest(value):
                self.assert_rejected(
                    "allowed_checks", network=f"[network]\nallowed_checks = {value}\n"
                )

    def test_unknown_network_key(self) -> None:
        self.assert_rejected("allow_all", network="[network]\nallow_all = true\n")

    def test_all_problems_are_reported_together(self) -> None:
        with self.assertRaises(ScopeError) as caught:
            load_scope(self.write_manifest(authorization="", actions=""))

        problems = caught.exception.problems
        self.assertTrue(any("authorization" in problem for problem in problems), problems)
        self.assertTrue(any("actions" in problem for problem in problems), problems)


if __name__ == "__main__":
    unittest.main()
