from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from soterion.findings import CheckResult, CheckStatus
from soterion.redact import MASK, Redactor, SensitiveSpan, collect_sensitive_values
from tests.helpers import fake_github_token
from tests.test_findings import make_finding


class RedactorText(unittest.TestCase):
    def test_known_value_is_masked_wherever_it_appears(self) -> None:
        redactor = Redactor(["s3cr3t-value-42"])

        masked = redactor.text("found s3cr3t-value-42 and again s3cr3t-value-42.")

        self.assertEqual(masked, f"found {MASK} and again {MASK}.")
        self.assertEqual(redactor.count, 2)

    def test_longer_value_is_masked_before_a_value_it_contains(self) -> None:
        redactor = Redactor(["abcdef-token", "abcdef-token-extended"])

        self.assertEqual(redactor.text("x abcdef-token-extended y"), f"x {MASK} y")

    def test_values_too_short_to_be_secrets_are_not_used(self) -> None:
        redactor = Redactor(["the", "id", ""])

        self.assertEqual(redactor.text("the id of the thing"), "the id of the thing")
        self.assertEqual(redactor.count, 0)

    def test_text_without_secrets_is_unchanged(self) -> None:
        text = "Upgrade requests from 2.19.0 to 2.20.0 (CVE-2018-18074)."

        self.assertEqual(Redactor([]).text(text), text)

    def test_well_known_token_shapes_are_masked_without_being_known_in_advance(self) -> None:
        github = fake_github_token()
        cloud_key = "AKIA" + "Q7" * 8
        chat_token = "xoxb-" + "1234567890-" + "abcdefghij"
        redactor = Redactor([])

        masked = redactor.text(f"a {github} b {cloud_key} c {chat_token} d")

        self.assertEqual(masked, f"a {MASK} b {MASK} c {MASK} d")

    def test_private_key_block_is_masked_as_a_whole(self) -> None:
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"
        block = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n{body}\n-----END RSA PRIVATE KEY-----"

        masked = Redactor([]).text(f"key: {block} end")

        self.assertEqual(masked, f"key: {MASK} end")

    def test_email_address_is_masked(self) -> None:
        masked = Redactor([]).text("contact jane.doe@example.org for access")

        self.assertEqual(masked, f"contact {MASK} for access")


class RedactorRecords(unittest.TestCase):
    def test_finding_text_fields_are_masked_and_location_is_kept(self) -> None:
        secret = "s3cr3t-value-42"
        finding = make_finding(
            title=f"title {secret}", impact=f"impact {secret}", remediation=f"fix {secret}"
        )

        masked = Redactor([secret]).finding(finding)

        self.assertEqual(masked.title, f"title {MASK}")
        self.assertEqual(masked.impact, f"impact {MASK}")
        self.assertEqual(masked.remediation, f"fix {MASK}")
        self.assertEqual(masked.evidence, finding.evidence)
        self.assertEqual(masked.fingerprint, finding.fingerprint)

    def test_check_detail_is_masked(self) -> None:
        check = CheckResult("semgrep", CheckStatus.FAILED, "could not parse s3cr3t-value-42")

        masked = Redactor(["s3cr3t-value-42"]).check(check)

        self.assertEqual(masked, CheckResult("semgrep", CheckStatus.FAILED, f"could not parse {MASK}"))


class CollectSensitiveValues(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def write(self, name: str, content: bytes) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def test_reads_the_bytes_a_span_points_at(self) -> None:
        self.write("src/app.py", b'import os\r\n\r\nTOKEN = "s3cr3t-value-42"\r\n')

        values = collect_sensitive_values(self.root, [SensitiveSpan("src/app.py", 3, 9, 24)])

        self.assertEqual(values, frozenset({"s3cr3t-value-42"}))

    def test_surrounding_quotes_and_spaces_are_not_part_of_the_value(self) -> None:
        self.write("a.py", b'TOKEN = "s3cr3t-value-42"\n')

        values = collect_sensitive_values(self.root, [SensitiveSpan("a.py", 1, 7, 25)])

        self.assertEqual(values, frozenset({"s3cr3t-value-42"}))

    def test_offsets_are_bytes_so_earlier_non_ascii_text_does_not_shift_the_value(self) -> None:
        line = 'ş = "s3cr3t-value-42"\n'.encode()
        self.write("a.py", line)
        start = line.index(b"s3cr3t")

        values = collect_sensitive_values(self.root, [SensitiveSpan("a.py", 1, start, start + 15)])

        self.assertEqual(values, frozenset({"s3cr3t-value-42"}))

    def test_value_is_extracted_when_the_span_covers_a_whole_assignment(self) -> None:
        # A scanner may report `name = "value"` as the match rather than the value.
        for line in (
            b'api_key = "s3cr3t-value-42"\n',
            b"password: s3cr3t-value-42\n",
            b"AUTH_TOKEN=s3cr3t-value-42\n",
            b'  "apiKey": "s3cr3t-value-42",\n',
        ):
            with self.subTest(line):
                self.write("a.txt", line)

                values = collect_sensitive_values(self.root, [SensitiveSpan("a.txt", 1)])

                self.assertIn("s3cr3t-value-42", values)

    def test_name_of_the_setting_is_not_treated_as_a_secret(self) -> None:
        self.write("a.py", b'client_secret = "s3cr3t-value-42"\n')

        values = collect_sensitive_values(self.root, [SensitiveSpan("a.py", 1)])

        self.assertNotIn("client_secret", values)

    def test_span_without_an_end_covers_the_rest_of_the_line(self) -> None:
        self.write("key.pem", b"-----BEGIN KEY-----\nQUJDREVGR0hJSktMTU5P\n-----END KEY-----\n")

        values = collect_sensitive_values(self.root, [SensitiveSpan("key.pem", 2)])

        self.assertEqual(values, frozenset({"QUJDREVGR0hJSktMTU5P"}))

    def test_span_that_points_nowhere_is_ignored(self) -> None:
        self.write("a.py", b"x = 1\n")
        spans = [SensitiveSpan("a.py", 99), SensitiveSpan("missing.py", 1), SensitiveSpan("a.py", 0)]

        self.assertEqual(collect_sensitive_values(self.root, spans), frozenset())

    def test_span_cannot_make_the_scan_read_a_file_outside_the_snapshot(self) -> None:
        self.write("snapshot/a.py", b"x = 1\n")
        self.write("outside.txt", b"s3cr3t-value-42\n")

        values = collect_sensitive_values(
            self.root / "snapshot", [SensitiveSpan("../outside.txt", 1)]
        )

        self.assertEqual(values, frozenset())


if __name__ == "__main__":
    unittest.main()
