"""Data model for findings and for the outcome of each check.

Two rules are enforced here in code rather than left to reporting:

* a finding cannot exist without file-and-line evidence, a severity, a
  confidence, an impact, a remediation and a verification status;
* "no findings" can only be reported when checks actually completed. A failed
  or skipped check makes the scan incomplete, never clean.

Evidence deliberately carries no source snippet yet: snippets may contain
secrets and will only be added together with redaction.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    """How likely the finding is a true positive, as far as the tool can tell."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VerificationStatus(StrEnum):
    UNVERIFIED = "unverified"  # reported by a scanner, not independently confirmed
    VERIFIED = "verified"  # confirmed by a deterministic check


class CheckStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "not_applicable"


class ScanStatus(StrEnum):
    NO_FINDINGS = "no_findings"
    FINDINGS = "findings"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True)
class Evidence:
    path: str  # repository-relative, forward slashes
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        path = self.path
        if not isinstance(path, str) or not path:
            raise ValueError("evidence path is required")
        if "\\" in path or ":" in path or path.startswith("/") or ".." in path.split("/"):
            raise ValueError("evidence path must be relative to the repository root")
        if type(self.start_line) is not int or type(self.end_line) is not int:
            raise ValueError("evidence lines must be integers")
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("evidence lines must be 1-based and ordered")

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "start_line": self.start_line, "end_line": self.end_line}


@dataclass(frozen=True)
class Finding:
    check_id: str
    rule_id: str
    title: str
    evidence: tuple[Evidence, ...]
    severity: Severity
    confidence: Confidence
    impact: str
    remediation: str
    verification: VerificationStatus

    def __post_init__(self) -> None:
        for name in ("check_id", "rule_id", "title", "impact", "remediation"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"finding {name} is required")
        if not self.evidence or not all(isinstance(item, Evidence) for item in self.evidence):
            raise ValueError("finding requires at least one piece of file-and-line evidence")
        for name, kind in (
            ("severity", Severity),
            ("confidence", Confidence),
            ("verification", VerificationStatus),
        ):
            if not isinstance(getattr(self, name), kind):
                raise ValueError(f"finding {name} must be a {kind.__name__}")

    @property
    def fingerprint(self) -> str:
        """Stable identity (check, rule, first location) used to re-check the same finding."""
        first = self.evidence[0]
        key = "\x00".join((self.check_id, self.rule_id, first.path, str(first.start_line)))
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "check_id": self.check_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "impact": self.impact,
            "remediation": self.remediation,
            "verification": self.verification.value,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    status: CheckStatus
    detail: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.check_id, str) or not self.check_id.strip():
            raise ValueError("check_id is required")
        if not isinstance(self.status, CheckStatus):
            raise ValueError("check status must be a CheckStatus")
        if self.status is not CheckStatus.COMPLETED and not self.detail.strip():
            raise ValueError("a check that did not complete must say why")


@dataclass(frozen=True)
class ScanSummary:
    status: ScanStatus
    finding_count: int
    incomplete_checks: tuple[str, ...]
    skipped_path_count: int = 0


def summarize(
    checks: Sequence[CheckResult], findings: Sequence[Finding], *, skipped_path_count: int = 0
) -> ScanSummary:
    """Decide the overall outcome. Incomplete always wins over 'no findings'.

    ``skipped_path_count`` is the number of in-scope paths that no check could
    see (links, oversized or unreadable files). Any such gap means the scope
    was not fully examined, so the result cannot be reported as clean.
    """
    by_id: dict[str, CheckResult] = {}
    for check in checks:
        if check.check_id in by_id:
            raise ValueError(f"duplicate check result: {check.check_id}")
        by_id[check.check_id] = check

    did_not_run = (CheckStatus.SKIPPED, CheckStatus.NOT_APPLICABLE)
    for finding in findings:
        source = by_id.get(finding.check_id)
        if source is None or source.status in did_not_run:
            raise ValueError(f"finding refers to a check that did not run: {finding.check_id}")

    incomplete = tuple(
        check.check_id
        for check in checks
        if check.status in (CheckStatus.FAILED, CheckStatus.SKIPPED)
    )
    any_completed = any(check.status is CheckStatus.COMPLETED for check in checks)

    if incomplete or not any_completed or skipped_path_count > 0:
        status = ScanStatus.INCOMPLETE
    elif findings:
        status = ScanStatus.FINDINGS
    else:
        status = ScanStatus.NO_FINDINGS
    return ScanSummary(
        status=status,
        finding_count=len(findings),
        incomplete_checks=incomplete,
        skipped_path_count=skipped_path_count,
    )
