from __future__ import annotations

import contextlib
import io
import unittest
from pathlib import Path

from soterion.cli import display, main
from soterion.scan import ToolCheck
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


class Display(unittest.TestCase):
    def test_control_characters_from_file_names_are_neutralized(self) -> None:
        self.assertEqual(display("a\x1b[31mb\r\n.py"), "a?[31mb??.py")

    def test_ordinary_unicode_names_are_kept(self) -> None:
        self.assertEqual(display("src/şifre çözücü.py"), "src/şifre çözücü.py")


if __name__ == "__main__":
    unittest.main()
