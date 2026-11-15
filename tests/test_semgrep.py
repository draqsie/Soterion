from __future__ import annotations

import json
import os
import unittest
from collections.abc import Sequence
from pathlib import Path

from soterion.checks.semgrep import SEMGREP, parse_report
from soterion.findings import CheckStatus, ScanStatus
from soterion.scan import ParsedOutput, ScanReport, run_scan
from soterion.scope import load_scope
from tests.helpers import RepoTestCase, real_tool_locator

ALLOW_NETWORK = '[network]\nallowed_checks = ["semgrep"]\n'
SHELL_TRUE_RULE = "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"

# Modelled on what semgrep 1.185.0 printed for files staged under files/.
RESULT = {
    "check_id": SHELL_TRUE_RULE,
    "path": "files\\app.py",
    "start": {"line": 8, "col": 12, "offset": 101},
    "end": {"line": 8, "col": 45, "offset": 134},
    "extra": {
        "message": "Found 'subprocess' function 'call' with 'shell=True'. This is dangerous.",
        "severity": "ERROR",
        "metadata": {
            "confidence": "MEDIUM",
            "cwe": ["CWE-78: Improper Neutralization of Special Elements used in an OS Command"],
            "owasp": ["A03:2021 - Injection"],
            "shortlink": "https://sg.run/example",
            "license": "Semgrep Rules License v1.0.",
        },
        "lines": "requires login",
        "fingerprint": "requires login",
        "engine_kind": "OSS",
        "validation_state": "NO_VALIDATOR",
    },
}
PARTIAL_PARSE_ERROR = {
    "code": 3,
    "level": "warn",
    "type": ["PartialParsing", [{"path": "files\\broken.py"}]],
    "message": "Syntax error at line files\\broken.py:2:\n `SECRET_LOOKING_SOURCE_TEXT` was unexpected",
    "path": "files\\broken.py",
}


def snippet_error(rule: str) -> dict[str, object]:
    """A rule could not parse an embedded snippet; the file itself parsed fine."""
    path = "files\\.github\\workflows\\ci.yml"
    return {
        "code": 3,
        "level": "warn",
        "type": ["PartialParsing", [{"path": path, "start": {"line": 11}, "end": {"line": 11}}]],
        "message": (
            f"Syntax error at line {path}:11:\n When parsing a snippet as Bash for "
            f"metavariable-pattern in rule '{rule}', `SECRET_LOOKING_SOURCE_TEXT` was unexpected"
        ),
        "path": path,
        "spans": [{"file": path, "start": {"line": 11, "col": 20}, "end": {"line": 11, "col": 58}}],
    }


def report(
    results: Sequence[dict[str, object]] = (),
    errors: Sequence[dict[str, object]] = (),
    scanned: Sequence[str] = ("files\\app.py",),
) -> bytes:
    document = {
        "version": "1.185.0",
        "results": list(results),
        "errors": list(errors),
        "paths": {"scanned": list(scanned)},
        "skipped_rules": [],
    }
    return json.dumps(document).encode("utf-8")


def with_extra(**changes: object) -> dict[str, object]:
    return {**RESULT, "extra": {**RESULT["extra"], **changes}}  # type: ignore[dict-item]


class ParseReport(unittest.TestCase):
    def test_maps_a_result_to_a_finding(self) -> None:
        parsed = parse_report(report([RESULT]))
        (finding,) = parsed.findings
        data = finding.to_dict()
        del data["fingerprint"]
        remediation = data.pop("remediation")

        self.assertEqual(
            data,
            {
                "check_id": "semgrep",
                "rule_id": SHELL_TRUE_RULE,
                "title": "subprocess-shell-true",
                "severity": "high",
                "confidence": "medium",
                "impact": RESULT["extra"]["message"],  # type: ignore[index]
                "verification": "unverified",
                "evidence": [{"path": "app.py", "start_line": 8, "end_line": 8}],
            },
        )
        self.assertIn("https://sg.run/example", remediation)
        self.assertEqual(parsed.problem, "")

    def test_severity_names_are_mapped_to_the_common_scale(self) -> None:
        expected = {
            "CRITICAL": "critical",
            "ERROR": "high",
            "HIGH": "high",
            "WARNING": "medium",
            "MEDIUM": "medium",
            "INFO": "low",
            "LOW": "low",
        }
        for reported, want in expected.items():
            with self.subTest(reported):
                (finding,) = parse_report(report([with_extra(severity=reported)])).findings
                self.assertEqual(finding.severity.value, want)

    def test_unknown_severity_is_an_error_rather_than_a_guess(self) -> None:
        with self.assertRaises(ValueError):
            parse_report(report([with_extra(severity="SPICY")]))

    def test_missing_confidence_is_reported_as_low(self) -> None:
        (finding,) = parse_report(report([with_extra(metadata={})])).findings

        self.assertEqual(finding.confidence.value, "low")

    def test_reference_that_is_not_an_https_link_is_left_out(self) -> None:
        for link in ("javascript:alert(1)", "http://sg.run/x", "https://sg.run/x\x1b[31m", 7):
            with self.subTest(link):
                (finding,) = parse_report(
                    report([with_extra(metadata={"shortlink": link})])
                ).findings
                self.assertNotIn(str(link), finding.remediation)

    def test_reports_which_files_the_tool_examined(self) -> None:
        parsed = parse_report(report(scanned=["files\\app.py", "files\\sub\\b.py"]))

        self.assertEqual(parsed.examined_files, frozenset({"app.py", "sub/b.py"}))

    def test_tool_errors_become_a_problem_without_quoting_source_text(self) -> None:
        parsed = parse_report(report([RESULT], errors=[PARTIAL_PARSE_ERROR]))

        self.assertEqual(len(parsed.findings), 1)
        self.assertIn("1 error", parsed.problem)
        self.assertIn("PartialParsing", parsed.problem)
        self.assertNotIn("SECRET_LOOKING_SOURCE_TEXT", parsed.problem)

    def test_rule_that_could_not_read_an_embedded_snippet_is_a_limitation_not_a_failure(self) -> None:
        parsed = parse_report(
            report(
                [RESULT],
                errors=[snippet_error("yaml.github-actions.security.curl-eval.curl-eval")],
                scanned=["files\\app.py", "files\\.github\\workflows\\ci.yml"],
            )
        )

        self.assertEqual(parsed.problem, "")
        self.assertIn("1 rule evaluation", parsed.limitation)
        self.assertIn(".github/workflows/ci.yml", parsed.limitation)
        self.assertNotIn("SECRET_LOOKING_SOURCE_TEXT", parsed.limitation)

    def test_same_rule_and_line_reported_twice_is_counted_once(self) -> None:
        error = snippet_error("yaml.github-actions.security.curl-eval.curl-eval")

        parsed = parse_report(report(errors=[error, error]))

        self.assertIn("1 rule evaluation", parsed.limitation)

    def test_file_level_parse_error_stays_a_problem_next_to_a_snippet_limitation(self) -> None:
        parsed = parse_report(
            report(errors=[snippet_error("yaml.rule.one"), PARTIAL_PARSE_ERROR])
        )

        self.assertIn("1 error", parsed.problem)
        self.assertIn("1 rule evaluation", parsed.limitation)

    def test_snippet_wording_does_not_downgrade_an_error_level_entry(self) -> None:
        error = {**snippet_error("yaml.rule.one"), "level": "error"}

        parsed = parse_report(report(errors=[error]))

        self.assertIn("1 error", parsed.problem)
        self.assertEqual(parsed.limitation, "")

    def test_snippet_warning_for_a_file_outside_the_snapshot_stays_an_error(self) -> None:
        error = {**snippet_error("yaml.rule.one"), "path": "elsewhere\\ci.yml"}

        parsed = parse_report(report(errors=[error]))

        self.assertIn("1 error", parsed.problem)
        self.assertEqual(parsed.limitation, "")

    def test_result_outside_the_snapshot_directory_is_an_error(self) -> None:
        for path in ("other\\app.py", "C:\\Users\\someone\\app.py", "files\\..\\x.py", ""):
            with self.subTest(path), self.assertRaises(ValueError):
                parse_report(report([{**RESULT, "path": path}]))

    def test_malformed_report_is_an_error(self) -> None:
        missing_paths = json.dumps({"results": [], "errors": []}).encode()
        for raw in (b"", b"not json", b"[]", b"{}", missing_paths, report([{"check_id": "x"}])):
            with self.subTest(raw), self.assertRaises(ValueError):
                parse_report(raw)

    def test_returns_parsed_output(self) -> None:
        self.assertIsInstance(parse_report(report()), ParsedOutput)


class SemgrepNetworkPermission(RepoTestCase):
    def test_is_skipped_without_running_unless_the_manifest_allows_its_network_use(self) -> None:
        self.add_file("a.py")

        def locate(name: str, *, forbidden_roots: Sequence[Path] = ()) -> Path | None:
            raise AssertionError("the tool must not even be looked up")

        result = run_scan(load_scope(self.write_manifest()), [SEMGREP], locate=locate)

        self.assertEqual(result.checks[0].status, CheckStatus.SKIPPED)
        self.assertIn("semgrep.dev", result.checks[0].detail)


VULNERABLE = """\
import subprocess


def run(cmd):
    return subprocess.call(cmd, shell=True)
"""


# Deliberately vulnerable fixture: untrusted pull-request text reaches a shell.
WORKFLOW = """\
name: ci
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: greet
        run: echo "${{ github.event.pull_request.title }}"
"""


class SemgrepIntegration(RepoTestCase):
    """Runs the real semgrep binary and downloads rules; needs explicit opt-in to run."""

    def setUp(self) -> None:
        super().setUp()
        if os.environ.get("SOTERION_TEST_NETWORK") != "1":
            raise unittest.SkipTest("set SOTERION_TEST_NETWORK=1 to run tests that use the network")
        self.locate = real_tool_locator("semgrep")

    def scan(self) -> ScanReport:
        manifest = self.write_manifest(scope='[scope]\ninclude = ["**"]\n', network=ALLOW_NETWORK)
        return run_scan(load_scope(manifest), [SEMGREP], locate=self.locate)

    def located(self, result: ScanReport) -> list[tuple[str, int, str]]:
        return sorted(
            (f.evidence[0].path, f.evidence[0].start_line, f.rule_id) for f in result.findings
        )

    def test_reports_a_shell_injection_risk_with_file_and_line(self) -> None:
        self.add_file("src/app.py", VULNERABLE)

        result = self.scan()

        self.assertEqual(result.checks[0].status, CheckStatus.COMPLETED, result.checks[0].detail)
        self.assertEqual(self.located(result), [("src/app.py", 5, SHELL_TRUE_RULE)])
        self.assertEqual(result.findings[0].severity.value, "high")

    def test_repository_without_matches_completes_with_no_findings(self) -> None:
        self.add_file("a.py", "x = 1\n")

        result = self.scan()

        self.assertEqual(result.checks[0].status, CheckStatus.COMPLETED, result.checks[0].detail)
        self.assertEqual(result.summary.status, ScanStatus.NO_FINDINGS)

    def test_repository_content_cannot_suppress_a_finding(self) -> None:
        self.add_file("hidden/app.py", VULNERABLE)
        self.add_file("nested/app.py", VULNERABLE)
        self.add_file("inline.py", VULNERABLE.replace("shell=True)", "shell=True)  # nosemgrep"))
        self.add_file(".semgrepignore", "hidden/\n")
        self.add_file("nested/.semgrepignore", "app.py\n")

        result = self.scan()

        self.assertEqual(result.checks[0].status, CheckStatus.COMPLETED, result.checks[0].detail)
        self.assertEqual(
            self.located(result),
            [
                ("hidden/app.py", 5, SHELL_TRUE_RULE),
                ("inline.py", 5, SHELL_TRUE_RULE),
                ("nested/app.py", 5, SHELL_TRUE_RULE),
            ],
        )

    def test_file_that_cannot_be_parsed_makes_the_check_incomplete_but_keeps_findings(self) -> None:
        self.add_file("app.py", VULNERABLE)
        self.add_file("broken.py", "def broken(:\n    return (\n")

        result = self.scan()

        self.assertEqual(result.checks[0].status, CheckStatus.FAILED)
        self.assertEqual(self.located(result), [("app.py", 5, SHELL_TRUE_RULE)])
        self.assertEqual(result.summary.status, ScanStatus.INCOMPLETE)

    def test_reports_a_container_running_as_root_in_a_dockerfile(self) -> None:
        self.add_file("Dockerfile", 'FROM python:3.12-slim\nCOPY . /app\nCMD ["python", "/app/app.py"]\n')

        result = self.scan()

        self.assertEqual(result.checks[0].status, CheckStatus.COMPLETED, result.checks[0].detail)
        self.assertEqual(
            self.located(result),
            [("Dockerfile", 3, "dockerfile.security.missing-user.missing-user")],
        )

    def test_reports_script_injection_in_a_workflow_without_failing_on_its_expressions(self) -> None:
        self.add_file(".github/workflows/ci.yml", WORKFLOW)

        result = self.scan()

        self.assertEqual(result.checks[0].status, CheckStatus.COMPLETED, result.checks[0].detail)
        self.assertIn(
            (
                ".github/workflows/ci.yml",
                8,
                "yaml.github-actions.security.run-shell-injection.run-shell-injection",
            ),
            self.located(result),
        )
        self.assertIn("embedded snippet", result.checks[0].detail)

    def test_binary_file_in_scope_does_not_make_the_check_incomplete(self) -> None:
        self.add_file("a.py", "x = 1\n")
        (self.repo / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00")

        result = self.scan()

        self.assertEqual(result.checks[0].status, CheckStatus.COMPLETED, result.checks[0].detail)


if __name__ == "__main__":
    unittest.main()
