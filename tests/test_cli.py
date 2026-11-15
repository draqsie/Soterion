from __future__ import annotations

import contextlib
import io
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

from soterion.cli import display, main
from soterion.scan import ParsedOutput, ToolCheck
from tests.helpers import RepoTestCase, emitting, fake_check, locate_python, write_tool


def run_cli(*argv: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = main(list(argv))
    return code, stdout.getvalue(), stderr.getvalue()


class ScopeCheckCommand(RepoTestCase):
    def test_valid_scope_reports_counts_and_exits_zero(self) -> None:
        self.add_file("a.py")
        self.add_file("src/b.py")
        self.add_file("README.md")

        code, out, err = run_cli("scope-check", str(self.write_manifest()))

        self.assertEqual(code, 0)
        self.assertIn("2 files in scope", out)
        self.assertIn("0 paths skipped", out)
        self.assertIn("analyze", out)
        self.assertEqual(err, "")

    def test_skipped_paths_are_listed_with_reason(self) -> None:
        self.add_file("big.py", "0123456789A")

        code, out, _ = run_cli(
            "scope-check", str(self.write_manifest(limits="[limits]\nmax_file_size_bytes = 10\n"))
        )

        self.assertEqual(code, 0)
        self.assertIn("1 paths skipped", out)
        self.assertIn("big.py (too_large)", out)

    def test_rejected_scope_exits_two_and_lists_nothing(self) -> None:
        self.add_file("a.py")

        code, out, err = run_cli("scope-check", str(self.write_manifest(authorization="")))

        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("authorization", err)

    def test_file_contents_are_never_printed(self) -> None:
        self.add_file("a.py", "API_KEY = 'not-a-real-key-0000'\n")

        _, out, err = run_cli("scope-check", str(self.write_manifest()))

        self.assertNotIn("not-a-real-key-0000", out + err)


class ScanCommand(RepoTestCase):
    def run_scan_command(self, *checks: ToolCheck, **sections: str) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(
                ["scan", str(self.write_manifest(**sections))], checks=checks, locate=locate_python
            )
        return code, stdout.getvalue(), stderr.getvalue()

    def tool(self, name: str, source: str) -> Path:
        return write_tool(self.tmp / "tools", name, source)

    def test_clean_result_exits_zero_and_does_not_claim_absence_of_vulnerabilities(self) -> None:
        self.add_file("a.py")

        code, out, _ = self.run_scan_command(fake_check(self.tool("quiet", emitting([]))))

        self.assertEqual(code, 0)
        self.assertIn("fake: completed", out)
        self.assertIn("not proof", out)

    def test_clean_result_with_a_limitation_says_so(self) -> None:
        self.add_file("a.py")
        check = fake_check(
            self.tool("quiet", emitting([])),
            parse=lambda raw: ParsedOutput([], limitation="1 rule skipped"),
        )

        code, out, _ = self.run_scan_command(check)

        self.assertEqual(code, 0)
        self.assertIn("fake: completed - 1 rule skipped", out)
        self.assertIn("limitations", out)

    def test_clean_result_without_limitations_does_not_mention_any(self) -> None:
        self.add_file("a.py")

        _, out, _ = self.run_scan_command(fake_check(self.tool("quiet", emitting([]))))

        self.assertNotIn("limitations", out)

    def test_findings_exit_one_and_show_location_and_ratings(self) -> None:
        self.add_file("a.py")
        script = self.tool("reports", emitting([{"rule": "r1", "path": "a.py", "line": 1}]))

        code, out, _ = self.run_scan_command(fake_check(script))

        self.assertEqual(code, 1)
        self.assertIn("a.py:1", out)
        self.assertIn("high", out)
        self.assertIn("medium", out)
        self.assertIn("unverified", out)
        self.assertIn("false positive", out)

    def test_network_use_is_disclosed_when_a_check_used_it(self) -> None:
        self.add_file("a.py")
        check = fake_check(
            self.tool("quiet", emitting([])), network_use="downloads rules from example.test"
        )

        _, out, _ = self.run_scan_command(
            check, network='[network]\nallowed_checks = ["fake"]\n'
        )

        self.assertIn("Network access used by fake: downloads rules from example.test", out)

    def test_no_network_line_when_no_check_used_the_network(self) -> None:
        self.add_file("a.py")

        _, out, _ = self.run_scan_command(fake_check(self.tool("quiet", emitting([]))))

        self.assertIn("Network access used: none", out)

    def test_missing_tool_exits_three_and_names_the_check(self) -> None:
        self.add_file("a.py")

        code, out, _ = self.run_scan_command(fake_check(Path("unused"), tool="not-installed"))

        self.assertEqual(code, 3)
        self.assertIn("fake: skipped", out)
        self.assertIn("incomplete", out)
        self.assertNotIn("not proof", out)

    def test_failed_check_with_findings_still_exits_three(self) -> None:
        self.add_file("a.py")
        reports = fake_check(
            self.tool("reports", emitting([{"rule": "r1", "path": "a.py", "line": 1}])),
            check_id="first",
        )
        crashes = fake_check(self.tool("crashes", emitting([], exit_code=7)), check_id="second")

        code, out, _ = self.run_scan_command(reports, crashes)

        self.assertEqual(code, 3)
        self.assertIn("a.py:1", out)
        self.assertIn("second: failed", out)

    def test_build_without_any_checks_exits_three(self) -> None:
        self.add_file("a.py")

        code, out, _ = self.run_scan_command()

        self.assertEqual(code, 3)
        self.assertIn("incomplete", out)

    def test_rejected_scope_exits_two_before_any_check_runs(self) -> None:
        self.add_file("a.py")
        marker = self.tmp / "ran.txt"
        script = self.tool("marks", f"open({str(marker)!r}, 'w').write('ran')\nprint('[]')\n")

        code, out, err = self.run_scan_command(fake_check(script), authorization="")

        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("authorization", err)
        self.assertFalse(marker.exists())


class ToolsDirOption(RepoTestCase):
    """Uses the real tool lookup; the stand-in scanner is the Python interpreter itself."""

    def run_scan_command(self, *extra: str) -> tuple[int, str]:
        self.add_file("a.py")
        script = write_tool(self.tmp / "tools", "quiet", emitting([]))
        check = fake_check(script, tool=Path(sys.executable).stem)
        stdout = io.StringIO()
        with mock.patch.dict(os.environ, {"PATH": ""}), contextlib.redirect_stdout(stdout):
            code = main(["scan", str(self.write_manifest()), *extra], checks=[check])
        return code, stdout.getvalue()

    def test_tool_is_found_in_the_given_directory(self) -> None:
        code, out = self.run_scan_command("--tools-dir", str(Path(sys.executable).parent))

        self.assertEqual(code, 0)
        self.assertIn("fake: completed", out)

    def test_without_the_option_a_tool_missing_from_path_is_skipped(self) -> None:
        code, out = self.run_scan_command()

        self.assertEqual(code, 3)
        self.assertIn("fake: skipped", out)

    def test_default_scan_lists_every_shipped_check_even_when_none_can_run(self) -> None:
        self.add_file("a.py")
        stdout = io.StringIO()
        with mock.patch.dict(os.environ, {"PATH": ""}), contextlib.redirect_stdout(stdout):
            code = main(["scan", str(self.write_manifest())])

        self.assertEqual(code, 3)
        for check_id in ("gitleaks", "semgrep", "osv-scanner"):
            self.assertIn(f"{check_id}: skipped", stdout.getvalue())

    def test_relative_tools_directory_is_a_usage_error(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            self.run_scan_command("--tools-dir", "tools")

        self.assertEqual(caught.exception.code, 2)


class Display(unittest.TestCase):
    def test_control_characters_from_file_names_are_neutralized(self) -> None:
        self.assertEqual(display("a\x1b[31mb\r\n.py"), "a?[31mb??.py")

    def test_ordinary_unicode_names_are_kept(self) -> None:
        self.assertEqual(display("src/şifre çözücü.py"), "src/şifre çözücü.py")


if __name__ == "__main__":
    unittest.main()
