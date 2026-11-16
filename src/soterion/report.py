"""Reports: what a scan found, what it could not check, and under which scope.

A report is built only from a ``ScanReport``, whose text has already passed the
redaction pass, so nothing here handles unmasked scanner or repository text.
Reports are written to a directory the operator names. That directory must be
outside the analyzed repository: analysis is read-only for the repository.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from soterion import __version__
from soterion.findings import CheckStatus, Finding, ScanStatus, Severity
from soterion.scan import ScanReport
from soterion.scope import Scope

REPORT_SCHEMA_VERSION = 1
JSON_REPORT_NAME = "soterion-report.json"

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}
_NOTES = (
    "Findings are scanner reports. Each may be a false positive and needs human review.",
    "No finding is proof of exploitability, and no result is proof that the code is free of "
    "vulnerabilities.",
    "Only the checks listed in this report ran, with the rule sets and tool versions shown. "
    "A check that is skipped, failed or not applicable examined nothing.",
    "Text from scanners and from the repository was passed through a masking step. Masking "
    "covers located secret values and a few well-known shapes; it is not a guarantee.",
)


class ReportError(ValueError):
    """A report cannot be written where the operator asked."""


def result_statement(report: ScanReport) -> str:
    """One sentence that says what the result does and does not mean."""
    summary = report.summary
    limited = any(
        check.status is CheckStatus.COMPLETED and check.detail for check in report.checks
    )
    caveat = " Some checks completed with limitations; see the check list." if limited else ""
    if summary.status is ScanStatus.NO_FINDINGS:
        return (
            "No findings from the checks listed. "
            "This is not proof that the code is free of vulnerabilities." + caveat
        )
    if summary.status is ScanStatus.FINDINGS:
        return (
            f"{summary.finding_count} finding(s). Each is a scanner report and may be "
            "a false positive; review the evidence before acting." + caveat
        )
    reasons = []
    if not any(check.status is CheckStatus.COMPLETED for check in report.checks):
        reasons.append("no check completed")
    if summary.incomplete_checks:
        reasons.append(f"checks that did not complete: {', '.join(summary.incomplete_checks)}")
    if summary.skipped_path_count:
        reasons.append(f"{summary.skipped_path_count} in-scope path(s) were not examined")
    return (
        f"Scan incomplete ({'; '.join(reasons)}). {summary.finding_count} finding(s) so far. "
        "Do not treat this as a clean result."
    )


def build_report(scope: Scope, report: ScanReport, *, generated_at: datetime) -> dict[str, Any]:
    """The report as plain data, ready to be serialized."""
    summary = report.summary
    info = {item.check_id: item for item in report.check_info}
    findings = sorted(report.findings, key=_finding_order)
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generator": {"name": "soterion", "version": __version__},
        "generated_at": generated_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "result": {
            "status": summary.status.value,
            "complete": summary.status is not ScanStatus.INCOMPLETE,
            "statement": result_statement(report),
            "finding_count": summary.finding_count,
            "incomplete_checks": list(summary.incomplete_checks),
            "skipped_path_count": summary.skipped_path_count,
        },
        "scope": {
            # The directory name only: a full path would put the operator's
            # account name and folder layout into a document meant to be shared.
            "repository": scope.repo_root.name,
            "authorization": {"basis": scope.authorization_basis, "verified": False},
            "include": list(scope.include),
            "exclude": list(scope.exclude),
            "allowed_actions": sorted(scope.allowed_actions),
            "network_checks": sorted(scope.network_checks),
            "limits": {
                "max_file_size_bytes": scope.max_file_size_bytes,
                "max_files": scope.max_files,
                "max_total_bytes": scope.max_total_bytes,
            },
        },
        "files_examined": report.file_count,
        "skipped_paths": [{"path": item.path, "reason": item.reason} for item in report.skipped],
        "checks": [
            {
                "id": check.check_id,
                "status": check.status.value,
                "detail": check.detail,
                "tool": info[check.check_id].tool if check.check_id in info else "",
                "tool_version": (
                    info[check.check_id].tool_version if check.check_id in info else "unknown"
                ),
                "rule_set": info[check.check_id].rule_set if check.check_id in info else "",
                "network_use": info[check.check_id].network_use if check.check_id in info else "",
            }
            for check in report.checks
        ],
        "masking": {
            "values_masked": report.redactions,
            # False: no secret-locating check completed, so text could only be
            # masked by well-known shapes, not by the actual values in the code.
            "secrets_located": report.secrets_located,
        },
        "findings": [
            {**finding.to_dict(), "same_location_as": _same_location(finding, findings)}
            for finding in findings
        ],
        "notes": list(_NOTES),
    }


def _finding_order(finding: Finding) -> tuple[int, str, int, str, str]:
    first = finding.evidence[0]
    return (
        _SEVERITY_ORDER[finding.severity],
        first.path,
        first.start_line,
        finding.check_id,
        finding.rule_id,
    )


def _same_location(finding: Finding, findings: list[Finding]) -> list[str]:
    """Fingerprints of findings from other checks whose evidence overlaps this one's.

    Two tools flagging the same lines usually describe one problem. They are
    linked rather than merged, so nothing a tool reported is dropped.
    """
    mine = finding.evidence[0]
    related = []
    for other in findings:
        theirs = other.evidence[0]
        if (
            other.check_id != finding.check_id
            and theirs.path == mine.path
            and theirs.start_line <= mine.end_line
            and mine.start_line <= theirs.end_line
        ):
            related.append(other.fingerprint)
    return sorted(related)


def prepare_output_dir(output_dir: Path, repo_root: Path) -> Path:
    """Validate and create the directory reports go to. Raises ReportError.

    The directory must be absolute and must not be, or lead into, the analyzed
    repository; links on the way are resolved before that is decided. Nothing
    is created when it is refused.
    """
    if not output_dir.is_absolute():
        raise ReportError("the output directory must be an absolute path")
    repository = repo_root.resolve()
    if _inside(output_dir.resolve(), repository):
        raise ReportError(
            "the output directory is inside the analyzed repository; reports are never "
            "written into the repository"
        )
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        raise ReportError("the output directory cannot be created or is not a directory") from None
    return output_dir.resolve()


def _inside(path: Path, directory: Path) -> bool:
    return path == directory or path.is_relative_to(directory)


def write_json_report(document: dict[str, Any], directory: Path) -> Path:
    """Write the JSON report into a prepared directory, replacing an earlier one."""
    target = directory / JSON_REPORT_NAME
    temporary = directory / f".{JSON_REPORT_NAME}.{os.getpid()}.tmp"
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    try:
        temporary.write_bytes(text.encode("utf-8"))
        os.replace(temporary, target)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise ReportError(f"the report could not be written to {target.name}") from None
    return target
