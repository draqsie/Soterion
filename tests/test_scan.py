from __future__ import annotations

import dataclasses
import json
import unittest
from collections.abc import Sequence
from pathlib import Path

from soterion.findings import CheckResult, CheckStatus, ScanStatus
from soterion.scan import ParsedOutput, ScanReport, ToolCheck, run_scan
from soterion.scope import SkippedPath, load_scope
from soterion.staging import Snapshot
from tests.helpers import (
    RepoTestCase,
    emitting,
    fake_check,
    locate_python,
    parse_items,
    write_tool,
)

LIST_VISIBLE_FILES = """\
import json, os
seen = []
for folder, _, names in os.walk("."):
    for name in names:
        seen.append(os.path.relpath(os.path.join(folder, name), ".").replace(os.sep, "/"))
print(json.dumps({"cwd": os.path.realpath(os.getcwd()), "files": sorted(seen)}))
"""


class RunScan(RepoTestCase):
    def tool(self, name: str, source: str) -> Path:
        return write_tool(self.tmp / "tools", name, source)

    def scan(self, *checks: ToolCheck, **sections: str) -> ScanReport:
        return run_scan(load_scope(self.write_manifest(**sections)), checks, locate=locate_python)

    def test_completed_check_returns_its_findings(self) -> None:
        self.add_file("a.py")
        script = self.tool("reports", emitting([{"rule": "r1", "path": "a.py", "line": 1}]))

        report = self.scan(fake_check(script))

        self.assertEqual(report.checks, (CheckResult("fake", CheckStatus.COMPLETED),))
        self.assertEqual([f.rule_id for f in report.findings], ["r1"])
        self.assertEqual(report.findings[0].evidence[0].path, "a.py")
        self.assertEqual(report.summary.status, ScanStatus.FINDINGS)
        self.assertEqual(report.file_count, 1)

    def test_completed_check_without_findings_is_a_clean_result(self) -> None:
        self.add_file("a.py")

        report = self.scan(fake_check(self.tool("quiet", emitting([]))))

        self.assertEqual(report.summary.status, ScanStatus.NO_FINDINGS)

    def test_tool_runs_inside_the_snapshot_and_sees_only_in_scope_files(self) -> None:
        self.add_file("a.py")
        self.add_file("notes.md")
        self.add_file(".git/config")
        captured: list[dict[str, object]] = []

        def capture(raw: bytes) -> list[object]:
            captured.append(json.loads(raw))
            return []

        self.scan(fake_check(self.tool("lists", LIST_VISIBLE_FILES), parse=capture))

        self.assertEqual(captured[0]["files"], ["a.py"])
        self.assertFalse(Path(str(captured[0]["cwd"])).is_relative_to(self.repo))

    def test_check_can_run_from_the_container_so_no_scanned_file_sits_at_its_root(self) -> None:
        self.add_file("a.py")
        captured: list[dict[str, object]] = []

        def capture(raw: bytes) -> list[object]:
            captured.append(json.loads(raw))
            return []

        self.scan(
            fake_check(self.tool("lists", LIST_VISIBLE_FILES), parse=capture, run_in_container=True)
        )

        self.assertEqual(captured[0]["files"], ["files/a.py"])

    def test_tool_lookup_excludes_the_repository_and_the_snapshot(self) -> None:
        self.add_file("a.py")
        forbidden: list[Path] = []

        def locate(name: str, *, forbidden_roots: Sequence[Path] = ()) -> Path | None:
            forbidden.extend(forbidden_roots)
            return None

        run_scan(load_scope(self.write_manifest()), [fake_check(Path("unused"))], locate=locate)

        self.assertIn(self.repo, forbidden)
        temporary = [root for root in forbidden if root != self.repo]
        self.assertEqual(len(temporary), 2)  # the snapshot container and the scratch directory
        self.assertFalse(any(root.is_relative_to(self.repo) for root in temporary))

    def test_missing_tool_is_skipped_and_the_scan_is_incomplete(self) -> None:
        self.add_file("a.py")

        report = self.scan(fake_check(Path("unused"), tool="not-installed"))

        self.assertEqual(report.checks[0].status, CheckStatus.SKIPPED)
        self.assertIn("not-installed", report.checks[0].detail)
        self.assertEqual(report.summary.status, ScanStatus.INCOMPLETE)

    def test_check_without_relevant_files_is_not_applicable_and_does_not_run(self) -> None:
        self.add_file("a.py")
        marker = self.tmp / "ran.txt"
        script = self.tool("marks", f"open({str(marker)!r}, 'w').write('ran')\nprint('[]')\n")

        report = self.scan(fake_check(script, applies_to=lambda files: False))

        self.assertEqual(report.checks[0].status, CheckStatus.NOT_APPLICABLE)
        self.assertFalse(marker.exists())
        self.assertEqual(report.summary.status, ScanStatus.INCOMPLETE)

    def test_unexpected_exit_code_is_a_failed_check(self) -> None:
        self.add_file("a.py")

        report = self.scan(fake_check(self.tool("crashes", emitting([], exit_code=7))))

        self.assertEqual(report.checks[0].status, CheckStatus.FAILED)
        self.assertIn("7", report.checks[0].detail)
        self.assertEqual(report.summary.status, ScanStatus.INCOMPLETE)

    def test_exit_code_declared_as_success_is_accepted(self) -> None:
        self.add_file("a.py")
        script = self.tool(
            "found", emitting([{"rule": "r1", "path": "a.py", "line": 1}], exit_code=1)
        )

        report = self.scan(fake_check(script, success_exit_codes=frozenset({0, 1})))

        self.assertEqual(report.checks[0].status, CheckStatus.COMPLETED)
        self.assertEqual(len(report.findings), 1)

    def test_exit_code_meaning_nothing_to_check_makes_the_check_not_applicable(self) -> None:
        self.add_file("a.py")
        script = self.tool("nothing", emitting([], exit_code=128))

        report = self.scan(fake_check(script, not_applicable_exit_codes=frozenset({128})))

        self.assertEqual(report.checks[0].status, CheckStatus.NOT_APPLICABLE)

    def test_parser_can_be_given_the_snapshot_to_locate_evidence(self) -> None:
        self.add_file("a.py", "one\ntwo\n")
        seen: list[tuple[str, ...]] = []

        def parse(raw: bytes, snapshot: Snapshot) -> list[object]:
            seen.append(snapshot.files)
            self.assertTrue((snapshot.root / "a.py").is_file())
            return []

        report = self.scan(
            fake_check(self.tool("quiet", emitting([])), parse=parse, parse_with_snapshot=True)
        )

        self.assertEqual(report.checks[0].status, CheckStatus.COMPLETED)
        self.assertEqual(seen, [("a.py",)])

    def test_unparseable_output_is_a_failed_check(self) -> None:
        self.add_file("a.py")

        report = self.scan(fake_check(self.tool("garbage", "print('this is not json')\n")))

        self.assertEqual(report.checks[0].status, CheckStatus.FAILED)
        self.assertEqual(report.findings, ())

    def test_parser_returning_something_other_than_findings_is_a_failed_check(self) -> None:
        self.add_file("a.py")

        report = self.scan(
            fake_check(self.tool("quiet", emitting([])), parse=lambda raw: [{"rule": "r1"}])
        )

        self.assertEqual(report.checks[0].status, CheckStatus.FAILED)
        self.assertEqual(report.findings, ())

    def test_timeout_is_a_failed_check(self) -> None:
        self.add_file("a.py")
        script = self.tool("hangs", "import time\ntime.sleep(120)\n")

        report = self.scan(fake_check(script, timeout_seconds=1))

        self.assertEqual(report.checks[0].status, CheckStatus.FAILED)
        self.assertIn("timed out", report.checks[0].detail)

    def test_oversized_output_is_a_failed_check(self) -> None:
        self.add_file("a.py")
        script = self.tool("floods", "import sys\nsys.stdout.write('x' * 200_000)\n")

        report = self.scan(fake_check(script, max_output_bytes=1000))

        self.assertEqual(report.checks[0].status, CheckStatus.FAILED)

    def test_tool_that_cannot_start_is_a_failed_check(self) -> None:
        self.add_file("a.py")
        missing = self.tmp / "tools" / "gone.exe"

        report = run_scan(
            load_scope(self.write_manifest()),
            [fake_check(Path("unused"))],
            locate=lambda name, *, forbidden_roots=(): missing,
        )

        self.assertEqual(report.checks[0].status, CheckStatus.FAILED)

    def test_finding_for_a_file_outside_the_snapshot_is_dropped_and_fails_the_check(self) -> None:
        self.add_file("a.py")
        self.add_file("notes.md")
        script = self.tool(
            "strays",
            emitting(
                [
                    {"rule": "r1", "path": "a.py", "line": 1},
                    {"rule": "r2", "path": "notes.md", "line": 1},
                ]
            ),
        )

        report = self.scan(fake_check(script))

        self.assertEqual([f.rule_id for f in report.findings], ["r1"])
        self.assertEqual(report.checks[0].status, CheckStatus.FAILED)

    def test_finding_for_a_line_that_does_not_exist_is_dropped_and_fails_the_check(self) -> None:
        self.add_file("a.py", "one\ntwo\n")
        script = self.tool(
            "miscounts",
            emitting(
                [
                    {"rule": "r1", "path": "a.py", "line": 2},
                    {"rule": "r2", "path": "a.py", "line": 3},
                ]
            ),
        )

        report = self.scan(fake_check(script))

        self.assertEqual([f.rule_id for f in report.findings], ["r1"])
        self.assertEqual(report.checks[0].status, CheckStatus.FAILED)

    def test_finding_attributed_to_another_check_is_dropped_and_fails_the_check(self) -> None:
        self.add_file("a.py")
        script = self.tool(
            "impersonates", emitting([{"rule": "r1", "path": "a.py", "line": 1, "check": "other"}])
        )

        report = self.scan(fake_check(script))

        self.assertEqual(report.findings, ())
        self.assertEqual(report.checks[0].status, CheckStatus.FAILED)

    def test_check_that_needs_the_network_is_skipped_and_not_run_without_permission(self) -> None:
        self.add_file("a.py")
        marker = self.tmp / "ran.txt"
        script = self.tool("marks", f"open({str(marker)!r}, 'w').write('ran')\nprint('[]')\n")

        report = self.scan(fake_check(script, network_use="downloads rules from example.test"))

        self.assertEqual(report.checks[0].status, CheckStatus.SKIPPED)
        self.assertIn("network", report.checks[0].detail)
        self.assertFalse(marker.exists())
        self.assertEqual(report.summary.status, ScanStatus.INCOMPLETE)

    def test_check_that_needs_the_network_runs_when_the_manifest_allows_it(self) -> None:
        self.add_file("a.py")
        check = fake_check(
            self.tool("quiet", emitting([])), network_use="downloads rules from example.test"
        )

        report = self.scan(check, network='[network]\nallowed_checks = ["fake"]\n')

        self.assertEqual(report.checks[0].status, CheckStatus.COMPLETED)
        self.assertEqual(report.network_used, ("fake",))

    def test_network_permission_for_one_check_does_not_cover_another(self) -> None:
        self.add_file("a.py")
        check = fake_check(
            self.tool("quiet", emitting([])), network_use="downloads rules from example.test"
        )

        report = self.scan(check, network='[network]\nallowed_checks = ["other"]\n')

        self.assertEqual(report.checks[0].status, CheckStatus.SKIPPED)
        self.assertEqual(report.network_used, ())

    def test_problem_reported_by_the_parser_fails_the_check_but_keeps_its_findings(self) -> None:
        self.add_file("a.py")
        script = self.tool("reports", emitting([{"rule": "r1", "path": "a.py", "line": 1}]))
        parse = parse_items("fake")

        report = self.scan(
            fake_check(
                script, parse=lambda raw: ParsedOutput(parse(raw), problem="2 files not parsed")
            )
        )

        self.assertEqual(report.checks[0].status, CheckStatus.FAILED)
        self.assertIn("2 files not parsed", report.checks[0].detail)
        self.assertEqual([f.rule_id for f in report.findings], ["r1"])

    def test_limitation_reported_by_the_parser_is_shown_on_a_completed_check(self) -> None:
        self.add_file("a.py")
        script = self.tool("quiet", emitting([]))

        report = self.scan(
            fake_check(script, parse=lambda raw: ParsedOutput([], limitation="1 rule skipped"))
        )

        self.assertEqual(
            report.checks, (CheckResult("fake", CheckStatus.COMPLETED, "1 rule skipped"),)
        )
        self.assertEqual(report.summary.status, ScanStatus.NO_FINDINGS)

    def test_limitation_is_kept_in_the_detail_of_a_failed_check(self) -> None:
        self.add_file("a.py")
        script = self.tool("quiet", emitting([]))

        report = self.scan(
            fake_check(
                script,
                parse=lambda raw: ParsedOutput([], problem="1 file broken", limitation="1 rule skipped"),
            )
        )

        self.assertEqual(report.checks[0].status, CheckStatus.FAILED)
        self.assertIn("1 file broken", report.checks[0].detail)
        self.assertIn("1 rule skipped", report.checks[0].detail)

    def test_in_scope_file_the_tool_did_not_examine_fails_the_check(self) -> None:
        self.add_file("a.py")
        self.add_file("b.py")
        script = self.tool("quiet", emitting([]))

        report = self.scan(
            fake_check(
                script, parse=lambda raw: ParsedOutput([], examined_files=frozenset({"a.py"}))
            )
        )

        self.assertEqual(report.checks[0].status, CheckStatus.FAILED)
        self.assertIn("1 in-scope file", report.checks[0].detail)

    def test_check_completes_when_the_tool_examined_every_in_scope_file(self) -> None:
        self.add_file("a.py")
        self.add_file("b.py")
        script = self.tool("quiet", emitting([]))

        report = self.scan(
            fake_check(
                script,
                parse=lambda raw: ParsedOutput([], examined_files=frozenset({"a.py", "b.py"})),
            )
        )

        self.assertEqual(report.checks[0].status, CheckStatus.COMPLETED)

    def test_check_environment_can_point_the_tool_at_the_private_scratch_directory(self) -> None:
        self.add_file("a.py")
        captured: list[dict[str, str]] = []

        def capture(raw: bytes) -> list[object]:
            captured.append(json.loads(raw))
            return []

        script = self.tool(
            "home",
            "import json, os\n"
            "home = os.environ['TOOL_HOME']\n"
            "print(json.dumps({'home': home, 'is_dir': os.path.isdir(home),"
            " 'cwd': os.path.realpath(os.getcwd())}))\n",
        )

        self.scan(
            fake_check(
                script,
                parse=capture,
                environment=lambda snapshot: {"TOOL_HOME": str(snapshot.scratch)},
            )
        )

        self.assertTrue(captured[0]["is_dir"])
        self.assertFalse(Path(captured[0]["home"]).is_relative_to(Path(captured[0]["cwd"])))
        self.assertFalse(Path(captured[0]["home"]).is_relative_to(self.repo))

    def test_one_failed_check_does_not_stop_the_others(self) -> None:
        self.add_file("a.py")
        crashes = fake_check(self.tool("crashes", emitting([], exit_code=7)), check_id="first")
        reports = fake_check(
            self.tool("reports", emitting([{"rule": "r1", "path": "a.py", "line": 1}])),
            check_id="second",
        )

        report = self.scan(crashes, reports)

        self.assertEqual(
            [(c.check_id, c.status) for c in report.checks],
            [("first", CheckStatus.FAILED), ("second", CheckStatus.COMPLETED)],
        )
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.summary.status, ScanStatus.INCOMPLETE)

    def test_skipped_in_scope_file_is_reported_and_prevents_a_clean_result(self) -> None:
        self.add_file("a.py", "0123456789")
        self.add_file("big.py", "0123456789A")

        report = self.scan(
            fake_check(self.tool("quiet", emitting([]))),
            limits="[limits]\nmax_file_size_bytes = 10\n",
        )

        self.assertEqual(report.checks[0].status, CheckStatus.COMPLETED)
        self.assertEqual(report.skipped, (SkippedPath("big.py", "too_large"),))
        self.assertEqual(report.summary.status, ScanStatus.INCOMPLETE)

    def test_scan_without_any_checks_is_incomplete(self) -> None:
        self.add_file("a.py")

        self.assertEqual(self.scan().summary.status, ScanStatus.INCOMPLETE)

    def test_scope_that_does_not_permit_analyze_is_refused(self) -> None:
        self.add_file("a.py")
        scope = dataclasses.replace(load_scope(self.write_manifest()), allowed_actions=frozenset())

        with self.assertRaises(PermissionError):
            run_scan(scope, [], locate=locate_python)

    def test_duplicate_check_ids_are_refused_before_anything_runs(self) -> None:
        self.add_file("a.py")
        marker = self.tmp / "ran.txt"
        script = self.tool("marks", f"open({str(marker)!r}, 'w').write('ran')\nprint('[]')\n")

        with self.assertRaises(ValueError):
            self.scan(fake_check(script), fake_check(script))
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
