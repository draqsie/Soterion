from __future__ import annotations

import dataclasses
import json
import os
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from soterion.findings import (
    CheckResult,
    CheckStatus,
    Finding,
    Severity,
    summarize,
)
from soterion.report import (
    JSON_REPORT_NAME,
    MARKDOWN_REPORT_NAME,
    ReportError,
    build_report,
    prepare_output_dir,
    render_markdown,
    write_json_report,
    write_reports,
)
from soterion.scan import CheckInfo, ScanReport
from soterion.scope import SkippedPath, load_scope
from tests.helpers import RepoTestCase, make_junction
from tests.test_findings import make_evidence, make_finding

GENERATED_AT = datetime(2026, 11, 16, 14, 30, 5, tzinfo=timezone(timedelta(hours=3)))


def scan_report(
    checks: list[CheckResult],
    findings: list[Finding],
    *,
    skipped: tuple[SkippedPath, ...] = (),
    info: tuple[CheckInfo, ...] = (),
    redactions: int = 0,
) -> ScanReport:
    return ScanReport(
        checks=tuple(checks),
        findings=tuple(findings),
        skipped=skipped,
        file_count=3,
        summary=summarize(checks, findings, skipped_path_count=len(skipped)),
        network_used=tuple(item.check_id for item in info if item.network_use),
        check_info=info,
        redactions=redactions,
    )


class BuildReport(RepoTestCase):
    def document(self, report: ScanReport, **sections: str) -> dict[str, object]:
        scope = load_scope(self.write_manifest(**sections))
        return build_report(scope, report, generated_at=GENERATED_AT)

    def test_header_identifies_the_format_the_generator_and_the_time_in_utc(self) -> None:
        document = self.document(scan_report([CheckResult("semgrep", CheckStatus.COMPLETED)], []))

        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(document["generator"]["name"], "soterion")
        self.assertEqual(document["generated_at"], "2026-11-16T11:30:05Z")

    def test_clean_scan_is_complete_and_does_not_claim_absence_of_vulnerabilities(self) -> None:
        document = self.document(scan_report([CheckResult("semgrep", CheckStatus.COMPLETED)], []))

        result = document["result"]
        self.assertEqual(result["status"], "no_findings")
        self.assertIs(result["complete"], True)
        self.assertIn("not proof", result["statement"])

    def test_incomplete_scan_is_marked_incomplete_and_says_why(self) -> None:
        checks = [
            CheckResult("gitleaks", CheckStatus.COMPLETED),
            CheckResult("semgrep", CheckStatus.SKIPPED, "semgrep was not found on PATH"),
        ]

        document = self.document(scan_report(checks, [make_finding(check_id="gitleaks")]))

        result = document["result"]
        self.assertEqual(result["status"], "incomplete")
        self.assertIs(result["complete"], False)
        self.assertEqual(result["incomplete_checks"], ["semgrep"])
        self.assertEqual(result["finding_count"], 1)
        self.assertIn("incomplete", result["statement"])

    def test_every_check_is_listed_with_its_state_tool_and_rule_set(self) -> None:
        checks = [
            CheckResult("semgrep", CheckStatus.COMPLETED, "1 rule skipped"),
            CheckResult("osv-scanner", CheckStatus.SKIPPED, "needs network access"),
        ]
        info = (
            CheckInfo("semgrep", "semgrep", "1.185.0", "p/default", "downloads rules"),
            CheckInfo("osv-scanner", "osv-scanner", "unknown", "OSV database", ""),
        )

        document = self.document(scan_report(checks, [], info=info))

        self.assertEqual(
            document["checks"],
            [
                {
                    "id": "semgrep",
                    "status": "completed",
                    "detail": "1 rule skipped",
                    "tool": "semgrep",
                    "tool_version": "1.185.0",
                    "rule_set": "p/default",
                    "network_use": "downloads rules",
                },
                {
                    "id": "osv-scanner",
                    "status": "skipped",
                    "detail": "needs network access",
                    "tool": "osv-scanner",
                    "tool_version": "unknown",
                    "rule_set": "OSV database",
                    "network_use": "",
                },
            ],
        )

    def test_scope_is_recorded_without_the_full_path_of_the_repository(self) -> None:
        document = self.document(
            scan_report([CheckResult("semgrep", CheckStatus.COMPLETED)], []),
            scope='[scope]\ninclude = ["**/*.py"]\nexclude = ["tests/**"]\n',
            network='[network]\nallowed_checks = ["semgrep"]\n',
        )

        scope = document["scope"]
        self.assertEqual(scope["repository"], "repo")
        self.assertEqual(scope["authorization"], {"basis": "owner", "verified": False})
        self.assertEqual(scope["include"], ["**/*.py"])
        self.assertEqual(scope["exclude"], ["tests/**"])
        self.assertEqual(scope["allowed_actions"], ["analyze"])
        self.assertEqual(scope["network_checks"], ["semgrep"])
        self.assertNotIn(str(self.tmp), json.dumps(document))
        self.assertNotIn(self.tmp.as_posix(), json.dumps(document))

    def test_skipped_paths_and_masking_are_reported(self) -> None:
        report = scan_report(
            [CheckResult("semgrep", CheckStatus.COMPLETED)],
            [],
            skipped=(SkippedPath("big.py", "too_large"),),
            redactions=4,
        )

        document = self.document(report)

        self.assertEqual(document["skipped_paths"], [{"path": "big.py", "reason": "too_large"}])
        self.assertEqual(document["masking"], {"values_masked": 4, "secrets_located": False})
        self.assertEqual(document["files_examined"], 3)

    def test_report_says_when_located_secrets_were_available_for_masking(self) -> None:
        report = dataclasses.replace(
            scan_report([CheckResult("gitleaks", CheckStatus.COMPLETED)], []), secrets_located=True
        )

        self.assertIs(self.document(report)["masking"]["secrets_located"], True)

    def test_findings_keep_every_field_and_are_ordered_by_severity_then_location(self) -> None:
        findings = [
            make_finding(rule_id="low-b", severity=Severity.LOW, evidence=(make_evidence(path="b.py"),)),
            make_finding(rule_id="critical", severity=Severity.CRITICAL),
            make_finding(rule_id="low-a", severity=Severity.LOW, evidence=(make_evidence(path="a.py"),)),
            make_finding(rule_id="high", severity=Severity.HIGH),
        ]

        document = self.document(scan_report([CheckResult("semgrep", CheckStatus.COMPLETED)], findings))

        listed = document["findings"]
        self.assertEqual([item["rule_id"] for item in listed], ["critical", "high", "low-a", "low-b"])
        for field in (
            "fingerprint",
            "check_id",
            "title",
            "severity",
            "confidence",
            "impact",
            "remediation",
            "verification",
            "evidence",
        ):
            self.assertIn(field, listed[0])

    def test_findings_from_different_checks_at_the_same_place_point_at_each_other(self) -> None:
        secret = make_finding(check_id="gitleaks", rule_id="generic-api-key")
        pattern = make_finding(check_id="semgrep", rule_id="hardcoded-secret")
        elsewhere = make_finding(
            check_id="semgrep", rule_id="other", evidence=(make_evidence(start_line=40, end_line=41),)
        )
        same_check = make_finding(check_id="semgrep", rule_id="second-rule")
        checks = [
            CheckResult("gitleaks", CheckStatus.COMPLETED),
            CheckResult("semgrep", CheckStatus.COMPLETED),
        ]

        document = self.document(scan_report(checks, [secret, pattern, elsewhere, same_check]))

        related = {item["rule_id"]: item["same_location_as"] for item in document["findings"]}
        self.assertEqual(related["generic-api-key"], sorted([pattern.fingerprint, same_check.fingerprint]))
        self.assertEqual(related["hardcoded-secret"], [secret.fingerprint])
        self.assertEqual(related["other"], [])

    def test_document_is_plain_json(self) -> None:
        document = self.document(
            scan_report([CheckResult("semgrep", CheckStatus.COMPLETED)], [make_finding()])
        )

        self.assertEqual(json.loads(json.dumps(document)), document)


HOSTILE = (
    "# Injected heading\n\n<script>alert(1)</script> [click](https://evil.example/x) "
    "| a | b |\n```\nfenced\n``` then `` two ` one"
)
HOSTILE_MARKERS = ("Injected", "<script", "evil.example", "click", "fenced", "| a |", "<b>")


def outside_code_spans(line: str) -> str:
    """What a Markdown reader interprets on a line: everything not inside a code span.

    Written independently of the code under test, following the CommonMark rule
    that a code span opened by N backticks is closed by the next run of exactly N.
    """
    kept: list[str] = []
    position = 0
    while position < len(line):
        if line[position] != "`":
            kept.append(line[position])
            position += 1
            continue
        end = position
        while end < len(line) and line[end] == "`":
            end += 1
        fence = end - position
        cursor, closing = end, -1
        while cursor < len(line):
            if line[cursor] != "`":
                cursor += 1
                continue
            run_end = cursor
            while run_end < len(line) and line[run_end] == "`":
                run_end += 1
            if run_end - cursor == fence:
                closing = cursor
                break
            cursor = run_end
        if closing < 0:
            kept.append(line[position:end])
            position = end
        else:
            position = closing + fence
    return "".join(kept)


class MarkdownReport(RepoTestCase):
    def markdown(self, report: ScanReport, **sections: str) -> str:
        scope = load_scope(self.write_manifest(**sections))
        return render_markdown(build_report(scope, report, generated_at=GENERATED_AT))

    def test_incomplete_scan_is_announced_before_anything_else(self) -> None:
        checks = [
            CheckResult("gitleaks", CheckStatus.COMPLETED),
            CheckResult("semgrep", CheckStatus.SKIPPED, "semgrep was not found on PATH"),
        ]

        lines = self.markdown(scan_report(checks, [])).splitlines()

        self.assertEqual(lines[0], "# Soterion scan report")
        self.assertIn("SCAN INCOMPLETE", lines[2])
        self.assertIn("Do not treat this as a clean result", "\n".join(lines[:6]))

    def test_complete_scan_carries_no_incomplete_banner_and_no_claim_of_safety(self) -> None:
        text = self.markdown(scan_report([CheckResult("semgrep", CheckStatus.COMPLETED)], []))

        self.assertNotIn("SCAN INCOMPLETE", text)
        self.assertIn("not proof", text)
        self.assertIn("No findings were reported", text)

    def test_every_check_is_listed_with_state_tool_version_rules_and_note(self) -> None:
        checks = [
            CheckResult("semgrep", CheckStatus.COMPLETED, "1 rule skipped"),
            CheckResult("osv-scanner", CheckStatus.SKIPPED, "needs network access"),
        ]
        info = (
            CheckInfo("semgrep", "semgrep", "1.185.0", "p/default", "downloads rules"),
            CheckInfo("osv-scanner", "osv-scanner", "unknown", "OSV database", ""),
        )

        text = self.markdown(scan_report(checks, [], info=info))

        self.assertIn("- **semgrep**: completed", text)
        self.assertIn("` 1.185.0 `", text)
        self.assertIn("` p/default `", text)
        self.assertIn("` downloads rules `", text)
        self.assertIn("` 1 rule skipped `", text)
        self.assertIn("- **osv-scanner**: skipped", text)
        self.assertIn("` needs network access `", text)

    def test_finding_shows_location_ratings_rule_and_guidance(self) -> None:
        text = self.markdown(
            scan_report([CheckResult("semgrep", CheckStatus.COMPLETED)], [make_finding()])
        )

        self.assertIn("### 1. ` Possible SQL injection `", text)
        self.assertIn("high severity, medium confidence, unverified", text)
        self.assertIn("` src/app.py `, lines 10-12", text)
        self.assertIn("` python.sql-injection `", text)
        self.assertIn("` Attacker-controlled input may reach a SQL query. `", text)
        self.assertIn("` Use parameterized queries. `", text)

    def test_findings_at_the_same_place_refer_to_each_other_by_number(self) -> None:
        secret = make_finding(check_id="gitleaks", rule_id="generic-api-key")
        pattern = make_finding(check_id="semgrep", rule_id="hardcoded-secret")
        checks = [
            CheckResult("gitleaks", CheckStatus.COMPLETED),
            CheckResult("semgrep", CheckStatus.COMPLETED),
        ]

        text = self.markdown(scan_report(checks, [secret, pattern]))

        self.assertIn("Same location as: finding 2 (semgrep)", text)
        self.assertIn("Same location as: finding 1 (gitleaks)", text)

    def test_skipped_paths_masking_and_scope_are_shown(self) -> None:
        report = scan_report(
            [CheckResult("semgrep", CheckStatus.COMPLETED)],
            [],
            skipped=(SkippedPath("big.py", "too_large"),),
            redactions=4,
        )

        text = self.markdown(report, scope='[scope]\ninclude = ["**/*.py"]\nexclude = ["tests/**"]\n')

        self.assertIn("- ` big.py `: too_large", text)
        self.assertIn("4 value(s) masked", text)
        self.assertIn("could only be masked by shape", text)
        self.assertIn("self-declared, not verified", text)
        self.assertIn("` **/*.py `", text)
        self.assertIn("` tests/** `", text)

    def test_scanner_and_repository_text_cannot_change_the_structure_of_the_document(self) -> None:
        hostile_finding = make_finding(
            title=HOSTILE,
            impact=HOSTILE,
            remediation=HOSTILE,
            rule_id="rule`with``ticks",
            evidence=(make_evidence(path="docs/<b>[x](y)/`z`.py"),),
        )
        report = scan_report(
            [CheckResult("semgrep", CheckStatus.FAILED, HOSTILE)],
            [hostile_finding],
            skipped=(SkippedPath("odd`name<b>.py", HOSTILE),),
            info=(CheckInfo("semgrep", "semgrep", HOSTILE, HOSTILE, HOSTILE),),
        )

        text = self.markdown(report)

        headings = [line for line in text.splitlines() if outside_code_spans(line).startswith("#")]
        self.assertEqual(sum(line.startswith("### ") for line in headings), 1)
        self.assertEqual(sum(line.startswith("# ") for line in headings), 1)
        for line in text.splitlines():
            visible = outside_code_spans(line)
            self.assertNotIn("`", visible, line)
            for marker in HOSTILE_MARKERS:
                self.assertNotIn(marker, visible, line)

    def test_ends_with_how_to_read_the_report(self) -> None:
        text = self.markdown(scan_report([CheckResult("semgrep", CheckStatus.COMPLETED)], []))

        self.assertIn("## How to read this report", text)
        self.assertIn("may be a false positive", text)
        self.assertTrue(text.endswith("\n"))


class OutputDirectory(RepoTestCase):
    def test_missing_directory_is_created(self) -> None:
        target = self.tmp / "out" / "reports"

        prepared = prepare_output_dir(target, self.repo)

        self.assertEqual(prepared, target)
        self.assertTrue(target.is_dir())

    def test_directory_inside_the_repository_is_refused_and_not_created(self) -> None:
        for target in (self.repo, self.repo / "reports", self.repo / "a" / "b"):
            with self.subTest(target), self.assertRaises(ReportError):
                prepare_output_dir(target, self.repo)
        self.assertEqual(list(self.repo.iterdir()), [])

    def test_relative_directory_is_refused(self) -> None:
        with self.assertRaises(ReportError):
            prepare_output_dir(Path("reports"), self.repo)

    def test_path_that_is_a_file_is_refused(self) -> None:
        target = self.add_file("reports", root=self.tmp)

        with self.assertRaises(ReportError):
            prepare_output_dir(target, self.repo)

    @unittest.skipUnless(os.name == "nt", "junctions exist only on Windows")
    def test_directory_that_leads_into_the_repository_through_a_junction_is_refused(self) -> None:
        (self.repo / "docs").mkdir()
        make_junction(self.tmp / "looks-outside", self.repo / "docs")

        with self.assertRaises(ReportError):
            prepare_output_dir(self.tmp / "looks-outside", self.repo)


class WriteJsonReport(RepoTestCase):
    def test_writes_the_document_and_leaves_nothing_else_behind(self) -> None:
        directory = prepare_output_dir(self.tmp / "out", self.repo)
        document = {"schema_version": 1, "text": "şifre çözücü", "items": [1, 2]}

        path = write_json_report(document, directory)

        self.assertEqual(path, directory / JSON_REPORT_NAME)
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), document)
        self.assertEqual([item.name for item in directory.iterdir()], [JSON_REPORT_NAME])

    def test_replaces_an_earlier_report(self) -> None:
        directory = prepare_output_dir(self.tmp / "out", self.repo)
        write_json_report({"run": 1}, directory)

        path = write_json_report({"run": 2}, directory)

        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"run": 2})


class WriteReports(RepoTestCase):
    def test_writes_json_and_markdown_from_the_same_document(self) -> None:
        scope = load_scope(self.write_manifest())
        report = scan_report([CheckResult("semgrep", CheckStatus.COMPLETED)], [make_finding()])
        document = build_report(scope, report, generated_at=GENERATED_AT)
        directory = prepare_output_dir(self.tmp / "out", self.repo)

        written = write_reports(document, directory)

        self.assertEqual(
            [path.name for path in written], [JSON_REPORT_NAME, MARKDOWN_REPORT_NAME]
        )
        self.assertEqual(
            sorted(item.name for item in directory.iterdir()),
            sorted([JSON_REPORT_NAME, MARKDOWN_REPORT_NAME]),
        )
        self.assertEqual(json.loads(written[0].read_text(encoding="utf-8")), document)
        self.assertEqual(written[1].read_text(encoding="utf-8"), render_markdown(document))


if __name__ == "__main__":
    unittest.main()
