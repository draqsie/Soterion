from __future__ import annotations

import dataclasses
import json
import unittest

from soterion.checks.gitleaks import GITLEAKS, parse_report
from soterion.findings import (
    CheckResult,
    CheckStatus,
    Confidence,
    Evidence,
    Finding,
    ScanStatus,
    Severity,
    VerificationStatus,
)
from soterion.redact import MASK, SensitiveSpan
from soterion.scan import ParsedOutput, ScanReport, run_scan
from soterion.scope import load_scope
from tests.helpers import (
    RepoTestCase,
    emitting,
    fake_api_value,
    fake_check,
    fake_github_token,
    locate_python,
    real_tool_locator,
    write_tool,
)

# One entry exactly as gitleaks 8.30.1 printed it for a file staged at files/src/app.py.
REPORT_ENTRY = {
    "RuleID": "github-pat",
    "Description": (
        "Uncovered a GitHub Personal Access Token, potentially leading to unauthorized "
        "repository access and sensitive content exposure."
    ),
    "StartLine": 3,
    "EndLine": 3,
    "StartColumn": 18,
    "EndColumn": 57,
    "Match": "REDACTED",
    "Secret": "REDACTED",
    "File": "files/src/app.py",
    "SymlinkFile": "",
    "Commit": "",
    "Entropy": 4.553056,
    "Author": "",
    "Email": "",
    "Date": "",
    "Message": "",
    "Tags": [],
    "Fingerprint": "files/src/app.py:github-pat:3",
}


def report(*entries: dict[str, object]) -> bytes:
    return json.dumps(list(entries)).encode("utf-8")


def parse_findings(raw: bytes) -> list[Finding]:
    return list(parse_report(raw).findings)


class ParseReport(unittest.TestCase):
    def test_maps_a_report_entry_to_a_finding(self) -> None:
        (finding,) = parse_findings(report(REPORT_ENTRY))
        data = finding.to_dict()
        del data["fingerprint"]
        remediation = data.pop("remediation")

        self.assertEqual(
            data,
            {
                "check_id": "gitleaks",
                "rule_id": "github-pat",
                "title": "Possible hardcoded secret (github-pat)",
                "severity": "high",
                "confidence": "medium",
                "impact": REPORT_ENTRY["Description"],
                "verification": "unverified",
                "evidence": [{"path": "src/app.py", "start_line": 3, "end_line": 3}],
            },
        )
        self.assertIn("rotate", remediation)

    def test_empty_report_has_no_findings(self) -> None:
        self.assertEqual(parse_findings(b"[]"), [])

    def test_reports_where_the_secret_is_so_it_can_be_masked_elsewhere(self) -> None:
        # Measured on gitleaks 8.30.1: columns are 1-based byte offsets, and one too
        # high on every line after the first. Both readings are passed on.
        spans = parse_report(report(REPORT_ENTRY)).sensitive_spans

        self.assertIn(SensitiveSpan("src/app.py", 3, 16, 56), spans)
        self.assertIn(SensitiveSpan("src/app.py", 3, 17, 57), spans)

    def test_secret_spanning_several_lines_is_reported_line_by_line(self) -> None:
        entry = {**REPORT_ENTRY, "StartLine": 1, "EndLine": 3, "StartColumn": 1, "EndColumn": 30}

        spans = parse_report(report(entry)).sensitive_spans

        self.assertIn(SensitiveSpan("src/app.py", 1, 0, None), spans)
        self.assertIn(SensitiveSpan("src/app.py", 2, 0, None), spans)
        self.assertIn(SensitiveSpan("src/app.py", 3, 0, 29), spans)
        self.assertIn(SensitiveSpan("src/app.py", 3, 0, 30), spans)

    def test_secret_value_never_reaches_the_finding_even_if_the_tool_printed_it(self) -> None:
        leaked = "ghp_" + "A" * 36
        entry = {**REPORT_ENTRY, "Match": f'TOKEN = "{leaked}"', "Secret": leaked}

        (finding,) = parse_findings(report(entry))

        self.assertNotIn(leaked, json.dumps(finding.to_dict()))

    def test_windows_path_separators_are_normalized(self) -> None:
        (finding,) = parse_findings(report({**REPORT_ENTRY, "File": "files\\src\\app.py"}))

        self.assertEqual(finding.evidence[0].path, "src/app.py")

    def test_entry_without_a_description_still_states_an_impact(self) -> None:
        (finding,) = parse_findings(report({**REPORT_ENTRY, "Description": ""}))

        self.assertIn("credential", finding.impact)

    def test_entry_outside_the_snapshot_directory_is_an_error(self) -> None:
        for path in ("other/app.py", "C:/Users/someone/app.py", "files/../outside.py", "files", ""):
            with self.subTest(path), self.assertRaises(ValueError):
                parse_report(report({**REPORT_ENTRY, "File": path}))

    def test_malformed_report_is_an_error(self) -> None:
        for raw in (b"", b"not json", b"{}", b'["text"]', report({"RuleID": "github-pat"})):
            with self.subTest(raw), self.assertRaises(ValueError):
                parse_report(raw)


class GitleaksIntegration(RepoTestCase):
    """Runs the real gitleaks binary; skipped unless SOTERION_TEST_TOOLS_DIR provides it."""

    def setUp(self) -> None:
        super().setUp()
        self.locate = real_tool_locator("gitleaks")
        self.token = fake_github_token()

    def scan(self) -> ScanReport:
        manifest = self.write_manifest(scope='[scope]\ninclude = ["**"]\n')
        return run_scan(load_scope(manifest), [GITLEAKS], locate=self.locate)

    def test_reports_a_hardcoded_token_with_file_and_line_but_not_its_value(self) -> None:
        self.add_file("src/app.py", f'import os\n\nGITHUB_TOKEN = "{self.token}"\n')

        result = self.scan()

        self.assertEqual(result.checks, (CheckResult("gitleaks", CheckStatus.COMPLETED),))
        self.assertTrue(result.secrets_located)
        self.assertEqual(result.check_info[0].tool_version, "8.30.1")
        (finding,) = result.findings
        self.assertEqual(finding.rule_id, "github-pat")
        self.assertEqual(finding.evidence[0].path, "src/app.py")
        self.assertEqual(finding.evidence[0].start_line, 3)
        self.assertNotIn(self.token, json.dumps(finding.to_dict()))

    def test_tool_output_is_redacted_before_it_reaches_the_parser(self) -> None:
        self.add_file("src/app.py", f'GITHUB_TOKEN = "{self.token}"\n')
        raw_reports: list[bytes] = []

        def capture(raw: bytes) -> ParsedOutput:
            raw_reports.append(raw)
            return parse_report(raw)

        manifest = self.write_manifest(scope='[scope]\ninclude = ["**"]\n')
        result = run_scan(
            load_scope(manifest), [dataclasses.replace(GITLEAKS, parse=capture)], locate=self.locate
        )

        self.assertEqual(len(result.findings), 1)
        self.assertNotIn(self.token.encode(), raw_reports[0])

    def test_secret_quoted_by_another_scanner_is_masked_in_everything_the_scan_returns(self) -> None:
        # Values with no recognizable shape, so only masking by exact value can catch
        # them. gitleaks reports the whole `name = "value"` match, not the value.
        first, second, third = (fake_api_value(seed) for seed in (1, 2, 3))
        self.add_file("first_line.py", f'api_key = "{first}"\n')
        self.add_file("later_line.py", f'import os\n\nclient_secret = "{second}"\n')
        self.add_file("after_non_ascii.py", f'# şifre\nş = 1; auth_token = "{third}"\n')
        tokens = (first, second, third)
        # A stand-in scanner whose finding and whose failure detail quote the secrets.
        quoting = fake_check(
            write_tool(self.tmp / "tools", "quiet", emitting([])),
            check_id="quoting",
            parse=lambda raw: ParsedOutput(
                [
                    Finding(
                        check_id="quoting",
                        rule_id="quotes-code",
                        title="Hardcoded value",
                        evidence=(Evidence("first_line.py", 1, 1),),
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        impact=" / ".join(f"matched {token} here" for token in tokens),
                        remediation="Remove it.",
                        verification=VerificationStatus.UNVERIFIED,
                    )
                ],
                problem=f"could not parse the line containing {second}",
            ),
        )

        manifest = self.write_manifest(scope='[scope]\ninclude = ["**"]\n')
        result = run_scan(
            load_scope(manifest),
            [quoting, GITLEAKS],
            locate=lambda name, *, forbidden_roots=(): (
                locate_python(name) or self.locate(name, forbidden_roots=forbidden_roots)
            ),
        )

        everything = json.dumps(
            [finding.to_dict() for finding in result.findings]
            + [check.detail for check in result.checks]
        ) + repr(result)
        self.assertEqual(len(result.findings), 4)
        for token in tokens:
            self.assertNotIn(token, everything)
        self.assertIn(MASK, everything)
        self.assertGreaterEqual(result.redactions, 4)

    def test_repository_without_secrets_completes_with_no_findings(self) -> None:
        self.add_file("a.py", "x = 1\n")

        result = self.scan()

        self.assertEqual(result.checks, (CheckResult("gitleaks", CheckStatus.COMPLETED),))
        self.assertEqual(result.summary.status, ScanStatus.NO_FINDINGS)

    def test_repository_content_cannot_suppress_a_finding(self) -> None:
        self.add_file("app.py", f'TOKEN = "{self.token}"  # gitleaks:allow\n')
        self.add_file(".gitleaksignore", "app.py:github-pat:1\nfiles/app.py:github-pat:1\n")
        self.add_file(".gitleaks.toml", '[allowlist]\npaths = [".*"]\n')

        result = self.scan()

        self.assertEqual(result.checks, (CheckResult("gitleaks", CheckStatus.COMPLETED),))
        self.assertEqual(
            [(f.evidence[0].path, f.evidence[0].start_line) for f in result.findings],
            [("app.py", 1)],
        )


if __name__ == "__main__":
    unittest.main()
