from __future__ import annotations

import json
import os
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path

from soterion.checks.osv import OSV_SCANNER, parse_report
from soterion.findings import CheckStatus, Finding
from soterion.scan import ScanReport, run_scan
from soterion.scope import load_scope
from soterion.staging import Snapshot
from tests.helpers import RepoTestCase, real_tool_locator

ALLOW_NETWORK = '[network]\nallowed_checks = ["osv-scanner"]\n'
REQUIREMENTS = "idna==3.10\nRequests==2.19.0\n"

# Shapes follow what osv-scanner 2.7.1 printed; advisory content is abbreviated.
REQUESTS_VULNERABILITIES = [
    {
        "id": "PYSEC-2018-28",
        "aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"],
        "affected": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "c45d7c49ea75"}]},
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]},
                ],
            }
        ],
    },
    {
        "id": "GHSA-x84v-xcm2-53pg",
        "aliases": ["CVE-2018-18074"],
        "summary": "Insufficiently Protected Credentials in Requests",
        "affected": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}
                ],
            }
        ],
    },
]
REQUESTS_GROUP = {
    "ids": ["PYSEC-2018-28", "GHSA-x84v-xcm2-53pg"],
    "aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg", "PYSEC-2018-28"],
    "max_severity": "7.5",
}


class SnapshotTestCase(unittest.TestCase):
    """A hand-built snapshot holding one requirements file, as a scan would stage it."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        workspace = Path(tmp.name).resolve()
        root = workspace / "scan" / "files"
        root.mkdir(parents=True)
        (workspace / "scratch").mkdir()
        (root / "requirements.txt").write_bytes(REQUIREMENTS.encode())
        self.snapshot = Snapshot(
            root=root,
            files=("requirements.txt",),
            skipped=(),
            container=root.parent,
            scratch=workspace / "scratch",
        )

    def report(
        self,
        groups: Sequence[dict[str, object]] = (REQUESTS_GROUP,),
        vulnerabilities: Sequence[dict[str, object]] = tuple(REQUESTS_VULNERABILITIES),
        source: str | None = None,
    ) -> bytes:
        path = source or (self.snapshot.root / "requirements.txt").as_posix()
        package = {"name": "requests", "version": "2.19.0", "ecosystem": "PyPI"}
        entry = {"package": package, "vulnerabilities": list(vulnerabilities), "groups": list(groups)}
        document = {"results": [{"source": {"path": path, "type": "lockfile"}, "packages": [entry]}]}
        return json.dumps(document).encode("utf-8")

    def parse(self, raw: bytes) -> list[Finding]:
        return list(parse_report(raw, self.snapshot))


class ParseReport(SnapshotTestCase):
    def test_maps_an_advisory_group_to_one_finding_at_the_declaring_line(self) -> None:
        (finding,) = self.parse(self.report())
        data = finding.to_dict()

        self.assertEqual(data["check_id"], "osv-scanner")
        self.assertEqual(data["rule_id"], "CVE-2018-18074")
        self.assertEqual(data["title"], "requests 2.19.0 is affected by CVE-2018-18074")
        self.assertEqual(data["severity"], "high")
        self.assertEqual(data["confidence"], "high")
        self.assertEqual(data["verification"], "unverified")
        self.assertEqual(
            data["evidence"], [{"path": "requirements.txt", "start_line": 2, "end_line": 2}]
        )
        self.assertIn("Insufficiently Protected Credentials in Requests", data["impact"])
        self.assertIn("reachable", data["impact"])
        self.assertIn("2.20.0", data["remediation"])
        self.assertNotIn("c45d7c49ea75", data["remediation"])

    def test_cvss_score_is_mapped_to_the_common_scale(self) -> None:
        expected = {
            "10.0": "critical",
            "9.0": "critical",
            "8.9": "high",
            "7.0": "high",
            "6.9": "medium",
            "4.0": "medium",
            "3.9": "low",
            "0.1": "low",
        }
        for score, want in expected.items():
            with self.subTest(score):
                (finding,) = self.parse(self.report([{**REQUESTS_GROUP, "max_severity": score}]))
                self.assertEqual(finding.severity.value, want)

    def test_advisory_without_a_score_is_medium_and_says_no_score_was_published(self) -> None:
        for score in ("", None, "not-a-number"):
            with self.subTest(score):
                (finding,) = self.parse(self.report([{**REQUESTS_GROUP, "max_severity": score}]))
                self.assertEqual(finding.severity.value, "medium")
                self.assertIn("No severity score", finding.impact)

    def test_identifier_preference_is_cve_then_ghsa_then_first_id(self) -> None:
        cases = (
            (["GHSA-aaaa-bbbb-cccc", "CVE-2020-0001"], "CVE-2020-0001"),
            (["PYSEC-2020-1", "GHSA-aaaa-bbbb-cccc"], "GHSA-aaaa-bbbb-cccc"),
            (["PYSEC-2020-1"], "PYSEC-2020-1"),
        )
        for aliases, want in cases:
            with self.subTest(aliases):
                group = {"ids": ["PYSEC-2020-1"], "aliases": aliases, "max_severity": "5.0"}
                (finding,) = self.parse(self.report([group], vulnerabilities=[]))
                self.assertEqual(finding.rule_id, want)

    def test_advisory_without_a_fixed_version_says_so(self) -> None:
        group = {"ids": ["PYSEC-2020-1"], "aliases": ["PYSEC-2020-1"], "max_severity": "5.0"}

        (finding,) = self.parse(self.report([group], vulnerabilities=[{"id": "PYSEC-2020-1"}]))

        self.assertIn("No fixed version", finding.remediation)

    def test_package_line_is_found_despite_case_and_separator_differences(self) -> None:
        (self.snapshot.root / "requirements.txt").write_bytes(b"# pinned\n\nREQUESTS == 2.19.0\n")

        (finding,) = self.parse(self.report())

        self.assertEqual(finding.evidence[0].start_line, 3)

    def test_line_with_the_matching_version_wins_over_a_similarly_named_package(self) -> None:
        (self.snapshot.root / "requirements.txt").write_bytes(
            b"requests-toolbelt==1.0.0\nrequests==2.19.0\n"
        )

        (finding,) = self.parse(self.report())

        self.assertEqual(finding.evidence[0].start_line, 2)

    def test_package_not_found_in_the_file_points_at_its_first_line(self) -> None:
        (self.snapshot.root / "requirements.txt").write_bytes(b"-r other.txt\n")

        (finding,) = self.parse(self.report())

        self.assertEqual(finding.evidence[0].start_line, 1)

    def test_package_without_advisories_yields_no_finding(self) -> None:
        self.assertEqual(self.parse(self.report(groups=[], vulnerabilities=[])), [])

    def test_source_outside_the_snapshot_is_an_error(self) -> None:
        outside = (self.snapshot.scratch / "requirements.txt").as_posix()
        for source in (outside, "C:/Windows/win.ini", "requirements.txt"):
            with self.subTest(source), self.assertRaises(ValueError):
                self.parse(self.report(source=source))

    def test_malformed_report_is_an_error(self) -> None:
        no_package = json.dumps({"results": [{"source": {"path": "x"}, "packages": [{}]}]}).encode()
        for raw in (b"", b"not json", b"[]", b"{}", no_package):
            with self.subTest(raw), self.assertRaises(ValueError):
                self.parse(raw)

    def test_identifier_with_unexpected_characters_is_an_error(self) -> None:
        group = {"ids": ["X"], "aliases": ["CVE-2020-1\x1b[31m"], "max_severity": "5.0"}

        with self.assertRaises(ValueError):
            self.parse(self.report([group], vulnerabilities=[]))


class OsvNetworkPermission(RepoTestCase):
    def test_is_skipped_without_running_unless_the_manifest_allows_its_network_use(self) -> None:
        self.add_file("requirements.txt", REQUIREMENTS)

        def locate(name: str, *, forbidden_roots: Sequence[Path] = ()) -> Path | None:
            raise AssertionError("the tool must not even be looked up")

        manifest = self.write_manifest(scope='[scope]\ninclude = ["**"]\n')
        result = run_scan(load_scope(manifest), [OSV_SCANNER], locate=locate)

        self.assertEqual(result.checks[0].status, CheckStatus.SKIPPED)
        self.assertIn("api.osv.dev", result.checks[0].detail)


class OsvIntegration(RepoTestCase):
    """Runs the real osv-scanner and queries osv.dev; needs explicit opt-in to run."""

    def setUp(self) -> None:
        super().setUp()
        if os.environ.get("SOTERION_TEST_NETWORK") != "1":
            raise unittest.SkipTest("set SOTERION_TEST_NETWORK=1 to run tests that use the network")
        self.locate = real_tool_locator("osv-scanner")

    def scan(self) -> ScanReport:
        manifest = self.write_manifest(scope='[scope]\ninclude = ["**"]\n', network=ALLOW_NETWORK)
        return run_scan(load_scope(manifest), [OSV_SCANNER], locate=self.locate)

    def located(self, result: ScanReport) -> set[tuple[str, int, str]]:
        return {(f.evidence[0].path, f.evidence[0].start_line, f.rule_id) for f in result.findings}

    def test_reports_a_known_vulnerable_pin_with_file_and_line(self) -> None:
        self.add_file("requirements.txt", "# pinned\nrequests==2.19.0\n")

        result = self.scan()

        self.assertEqual(result.checks[0].status, CheckStatus.COMPLETED, result.checks[0].detail)
        self.assertIn(("requirements.txt", 2, "CVE-2018-18074"), self.located(result))

    def test_repository_without_dependency_manifests_is_not_applicable(self) -> None:
        self.add_file("a.py", "x = 1\n")

        result = self.scan()

        self.assertEqual(result.checks[0].status, CheckStatus.NOT_APPLICABLE)
        self.assertEqual(result.findings, ())

    def test_repository_content_cannot_suppress_a_vulnerability(self) -> None:
        self.add_file("requirements.txt", "requests==2.19.0\n")
        self.add_file("sub/requirements.txt", "requests==2.19.0\n")
        self.add_file("osv-scanner.toml", '[[PackageOverrides]]\nname = "requests"\nignore = true\n')
        self.add_file(
            "sub/osv-scanner.toml", '[[IgnoredVulns]]\nid = "GHSA-x84v-xcm2-53pg"\n'
        )

        result = self.scan()

        self.assertEqual(result.checks[0].status, CheckStatus.COMPLETED, result.checks[0].detail)
        located = self.located(result)
        self.assertIn(("requirements.txt", 1, "CVE-2018-18074"), located)
        self.assertIn(("sub/requirements.txt", 1, "CVE-2018-18074"), located)


if __name__ == "__main__":
    unittest.main()
