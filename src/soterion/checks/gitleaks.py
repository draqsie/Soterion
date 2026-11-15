"""Hardcoded-secret detection with gitleaks (developed against gitleaks 8.30.1).

Three properties of gitleaks shape this adapter; each was measured against the
real binary and is covered by an integration test:

* Its report contains the secret itself unless ``--redact`` is passed. We pass
  it, and additionally never copy the ``Secret`` or ``Match`` fields, so a
  finding carries only the rule, file and line.
* A ``.gitleaks.toml`` or ``.gitleaksignore`` at the root of the scanned
  directory, and ``gitleaks:allow`` comments, let the scanned content silence
  findings. ``--gitleaks-ignore-path`` does not prevent the ignore file from
  being loaded. We therefore scan from the snapshot's container, so that no
  copied file is at the scanned root and gitleaks falls back to its built-in
  rules, and pass ``--ignore-gitleaks-allow``. The runner does not forward the
  caller's ``GITLEAKS_CONFIG`` variables either.
* It exits 1 both for "leaks found" and for fatal errors. ``--exit-code 0``
  makes leaks exit 0, so any non-zero exit is an error.

gitleaks only matches patterns; it does not contact any service to test whether
a credential is live, and neither does this adapter. Findings are unverified.
"""

from __future__ import annotations

import json

from soterion.findings import Confidence, Evidence, Finding, Severity, VerificationStatus
from soterion.scan import ToolCheck
from soterion.staging import Snapshot, snapshot_relative

CHECK_ID = "gitleaks"

_DEFAULT_IMPACT = (
    "A credential stored in the repository can be used by anyone who can read the code "
    "or its history."
)
_REMEDIATION = (
    "If this is a real credential, treat it as compromised: revoke and rotate it, then load "
    "it from a secret store or environment variable instead of the source. Deleting the line "
    "does not remove it from version-control history."
)


def parse_report(raw: bytes) -> list[Finding]:
    """Convert a gitleaks JSON report into findings. Raises ValueError if it is malformed."""
    try:
        entries = json.loads(raw)
    except ValueError:
        raise ValueError("gitleaks report is not valid JSON") from None
    if not isinstance(entries, list):
        raise ValueError("gitleaks report is not a list")
    return [_to_finding(entry) for entry in entries]


def _to_finding(entry: object) -> Finding:
    if not isinstance(entry, dict):
        raise ValueError("gitleaks report entry is not an object")
    try:
        rule, reported_path = entry["RuleID"], entry["File"]
        start_line, end_line = entry["StartLine"], entry["EndLine"]
    except KeyError as missing:
        raise ValueError(f"gitleaks report entry has no {missing}") from None
    if not isinstance(rule, str) or not isinstance(reported_path, str):
        raise ValueError("gitleaks report entry has a non-text rule or file")

    description = entry.get("Description")
    impact = description.strip() if isinstance(description, str) else ""
    return Finding(
        check_id=CHECK_ID,
        rule_id=rule,
        title=f"Possible hardcoded secret ({rule})",
        evidence=(Evidence(snapshot_relative(reported_path), start_line, end_line),),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        impact=impact or _DEFAULT_IMPACT,
        remediation=_REMEDIATION,
        verification=VerificationStatus.UNVERIFIED,
    )


def _arguments(snapshot: Snapshot) -> list[str]:
    return [
        "dir",
        ".",
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--redact",
        "--ignore-gitleaks-allow",
        "--exit-code",
        "0",
        "--no-banner",
        "--no-color",
        "--log-level",
        "error",
    ]


GITLEAKS = ToolCheck(
    check_id=CHECK_ID,
    tool="gitleaks",
    applies_to=lambda files: bool(files),
    arguments=_arguments,
    parse=parse_report,
    run_in_container=True,
)
