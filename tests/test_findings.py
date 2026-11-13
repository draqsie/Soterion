from __future__ import annotations

import unittest

from soterion.findings import (
    CheckResult,
    CheckStatus,
    Confidence,
    Evidence,
    Finding,
    ScanStatus,
    Severity,
    VerificationStatus,
    summarize,
)


def make_evidence(**overrides: object) -> Evidence:
    fields: dict[str, object] = {"path": "src/app.py", "start_line": 10, "end_line": 12}
    fields.update(overrides)
    return Evidence(**fields)  # type: ignore[arg-type]


def make_finding(**overrides: object) -> Finding:
    fields: dict[str, object] = {
        "check_id": "semgrep",
        "rule_id": "python.sql-injection",
        "title": "Possible SQL injection",
        "evidence": (make_evidence(),),
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "impact": "Attacker-controlled input may reach a SQL query.",
        "remediation": "Use parameterized queries.",
        "verification": VerificationStatus.UNVERIFIED,
    }
    fields.update(overrides)
    return Finding(**fields)  # type: ignore[arg-type]


class EvidenceValidation(unittest.TestCase):
    def test_path_must_stay_inside_the_repo(self) -> None:
        for path in ("/etc/passwd", "C:/Windows/win.ini", "../other/app.py", "src/../../x.py", "src\\app.py", ""):
            with self.subTest(path), self.assertRaises(ValueError):
                make_evidence(path=path)

    def test_lines_are_one_based_and_ordered(self) -> None:
        for start, end in ((0, 1), (-1, 1), (5, 4)):
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                make_evidence(start_line=start, end_line=end)

    def test_single_line_evidence_is_valid(self) -> None:
        self.assertEqual(make_evidence(start_line=7, end_line=7).end_line, 7)


class FindingValidation(unittest.TestCase):
    def test_finding_without_evidence_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            make_finding(evidence=())

    def test_required_text_fields_cannot_be_blank(self) -> None:
        for field in ("check_id", "rule_id", "title", "impact", "remediation"):
            with self.subTest(field), self.assertRaises(ValueError):
                make_finding(**{field: "  "})

    def test_ratings_must_be_enum_members_not_free_text(self) -> None:
        for field, value in (
            ("severity", "high"),
            ("confidence", "certain"),
            ("verification", "verified"),
        ):
            with self.subTest(field), self.assertRaises(ValueError):
                make_finding(**{field: value})

    def test_serializes_every_required_field(self) -> None:
        data = make_finding().to_dict()
        fingerprint = data.pop("fingerprint")

        self.assertRegex(fingerprint, r"^[0-9a-f]{16}$")
        self.assertEqual(
            data,
            {
                "check_id": "semgrep",
                "rule_id": "python.sql-injection",
                "title": "Possible SQL injection",
                "severity": "high",
                "confidence": "medium",
                "impact": "Attacker-controlled input may reach a SQL query.",
                "remediation": "Use parameterized queries.",
                "verification": "unverified",
                "evidence": [{"path": "src/app.py", "start_line": 10, "end_line": 12}],
            },
        )

    def test_fingerprint_identifies_rule_and_location_not_wording(self) -> None:
        original = make_finding()

        self.assertEqual(original.fingerprint, make_finding(title="Reworded title").fingerprint)
        self.assertNotEqual(
            original.fingerprint,
            make_finding(evidence=(make_evidence(start_line=11),)).fingerprint,
        )
        self.assertNotEqual(original.fingerprint, make_finding(rule_id="python.xss").fingerprint)


class CheckResultValidation(unittest.TestCase):
    def test_non_completed_check_must_say_why(self) -> None:
        for status in (CheckStatus.FAILED, CheckStatus.SKIPPED, CheckStatus.NOT_APPLICABLE):
            with self.subTest(status), self.assertRaises(ValueError):
                CheckResult("semgrep", status)

    def test_completed_check_needs_no_detail(self) -> None:
        self.assertEqual(CheckResult("semgrep", CheckStatus.COMPLETED).detail, "")


class Summary(unittest.TestCase):
    completed = CheckResult("semgrep", CheckStatus.COMPLETED)
    failed = CheckResult("osv", CheckStatus.FAILED, "scanner exited with code 3")
    skipped = CheckResult("gitleaks", CheckStatus.SKIPPED, "binary not installed")
    not_applicable = CheckResult("dockerfile", CheckStatus.NOT_APPLICABLE, "no Dockerfile in scope")

    def test_no_checks_run_is_not_a_clean_result(self) -> None:
        self.assertEqual(summarize([], []).status, ScanStatus.INCOMPLETE)

    def test_all_checks_completed_without_findings(self) -> None:
        self.assertEqual(summarize([self.completed], []).status, ScanStatus.NO_FINDINGS)

    def test_not_applicable_checks_do_not_block_a_clean_result(self) -> None:
        summary = summarize([self.completed, self.not_applicable], [])

        self.assertEqual(summary.status, ScanStatus.NO_FINDINGS)

    def test_only_not_applicable_checks_is_not_a_clean_result(self) -> None:
        self.assertEqual(summarize([self.not_applicable], []).status, ScanStatus.INCOMPLETE)

    def test_failed_check_makes_the_scan_incomplete(self) -> None:
        summary = summarize([self.completed, self.failed], [])

        self.assertEqual(summary.status, ScanStatus.INCOMPLETE)
        self.assertEqual(summary.incomplete_checks, ("osv",))

    def test_skipped_check_makes_the_scan_incomplete(self) -> None:
        summary = summarize([self.completed, self.skipped], [])

        self.assertEqual(summary.status, ScanStatus.INCOMPLETE)
        self.assertEqual(summary.incomplete_checks, ("gitleaks",))

    def test_in_scope_paths_that_were_skipped_prevent_a_clean_result(self) -> None:
        summary = summarize([self.completed], [], skipped_path_count=1)

        self.assertEqual(summary.status, ScanStatus.INCOMPLETE)
        self.assertEqual(summary.skipped_path_count, 1)

    def test_findings_from_completed_checks(self) -> None:
        summary = summarize([self.completed], [make_finding(), make_finding(rule_id="python.xss")])

        self.assertEqual(summary.status, ScanStatus.FINDINGS)
        self.assertEqual(summary.finding_count, 2)

    def test_incomplete_scan_still_counts_its_findings(self) -> None:
        summary = summarize([self.completed, self.failed], [make_finding()])

        self.assertEqual(summary.status, ScanStatus.INCOMPLETE)
        self.assertEqual(summary.finding_count, 1)

    def test_finding_from_an_unreported_check_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            summarize([self.completed], [make_finding(check_id="mystery")])

    def test_finding_from_a_check_that_did_not_run_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            summarize([self.completed, self.skipped], [make_finding(check_id="gitleaks")])

    def test_duplicate_check_ids_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            summarize([self.completed, self.completed], [])


if __name__ == "__main__":
    unittest.main()
