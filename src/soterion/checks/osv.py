"""Known vulnerabilities in dependencies with OSV-Scanner (developed against 2.7.1).

What was measured against the real binary, and how this adapter responds:

* The tool looks up the packages it finds by querying api.osv.dev, so the check
  only runs when the scope manifest allows its network use. Transitive
  resolution is switched off (``--no-resolve``): it would contact a second
  service, and only what a manifest or lockfile actually states is checked.
* An ``osv-scanner.toml`` in any scanned directory can ignore a package or an
  advisory, which lets the analyzed content hide vulnerabilities. ``--config``
  with an empty file of our own overrides all of them.
* Exit code 1 means vulnerabilities were found, 128 means no dependency
  manifest was found (reported as "not applicable"), anything else is an error.
* The report names the manifest and the package but no line, so the line that
  declares the package is looked up in the copied file: the first line that
  mentions both name and version, else the first that mentions the name, else
  line 1 of the manifest.

A finding means the declared version falls in an advisory's affected range.
Whether the vulnerable code is reachable from the project is not analyzed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from soterion.findings import Confidence, Evidence, Finding, Severity, VerificationStatus
from soterion.scan import ToolCheck
from soterion.staging import FILES_DIRNAME, Snapshot

CHECK_ID = "osv-scanner"

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,79}")
_PACKAGE_TEXT = re.compile(r"[^\x00-\x1f\x7f]{1,200}")
_MAX_FIXED_VERSIONS = 8
_REACHABILITY = "Whether the vulnerable code is reachable from this project was not analyzed."
_NO_SCORE = "No severity score is published for this advisory, so it is shown as medium."


def parse_report(raw: bytes, snapshot: Snapshot) -> list[Finding]:
    """Convert OSV-Scanner's JSON report. Raises ValueError if it is malformed."""
    try:
        document = json.loads(raw)
    except ValueError:
        raise ValueError("osv-scanner output is not valid JSON") from None
    try:
        return [
            finding
            for result in document["results"]
            for finding in _findings_for_source(result, snapshot)
        ]
    except (KeyError, TypeError, AttributeError):
        raise ValueError("osv-scanner output has an unexpected shape") from None


def _findings_for_source(result: dict[str, object], snapshot: Snapshot) -> list[Finding]:
    path = _relative_source(result["source"]["path"], snapshot)  # type: ignore[index]
    lines = (snapshot.root / path).read_bytes().decode("utf-8", errors="replace").splitlines()
    findings: list[Finding] = []
    for entry in result["packages"]:  # type: ignore[attr-defined]
        package = entry["package"]
        name, version = _text(package["name"]), _text(package["version"])
        advisories = {item["id"]: item for item in entry.get("vulnerabilities", [])}
        line = _declaring_line(lines, name, version)
        for group in entry.get("groups", []):
            findings.append(_to_finding(path, line, name, version, group, advisories))
    return findings


def _relative_source(reported: object, snapshot: Snapshot) -> str:
    if not isinstance(reported, str) or not Path(reported).is_absolute():
        raise ValueError("osv-scanner reported a manifest path that is not absolute")
    try:
        relative = Path(reported).resolve().relative_to(snapshot.root).as_posix()
    except (OSError, ValueError):
        raise ValueError("osv-scanner reported a manifest outside the snapshot") from None
    if relative not in snapshot.files:
        raise ValueError("osv-scanner reported a manifest that is not in scope")
    return relative


def _text(value: object) -> str:
    if not isinstance(value, str) or not _PACKAGE_TEXT.fullmatch(value):
        raise ValueError("osv-scanner reported an unusable package name or version")
    return value


def _normalized(text: str) -> str:
    return text.lower().replace("_", "-").replace(".", "-")


def _declaring_line(lines: list[str], name: str, version: str) -> int:
    wanted = _normalized(name)
    first_name_match = 0
    for number, line in enumerate(lines, start=1):
        if wanted in _normalized(line):
            if version in line:
                return number
            first_name_match = first_name_match or number
    return first_name_match or 1


def _to_finding(
    path: str,
    line: int,
    name: str,
    version: str,
    group: dict[str, object],
    advisories: dict[str, dict[str, object]],
) -> Finding:
    ids = [_identifier(item) for item in group["ids"]]  # type: ignore[attr-defined]
    aliases = [_identifier(item) for item in group.get("aliases") or ids]  # type: ignore[attr-defined]
    advisory_id = _preferred(aliases or ids)
    members = [advisories[item] for item in ids if item in advisories]

    severity, scored = _severity(group.get("max_severity"))
    summary = next(
        (item["summary"].strip() for item in members if _usable_summary(item.get("summary"))),
        "A published advisory affects this version.",
    )
    impact = f"{summary} {_REACHABILITY}" + ("" if scored else f" {_NO_SCORE}")

    return Finding(
        check_id=CHECK_ID,
        rule_id=advisory_id,
        title=f"{name} {version} is affected by {advisory_id}",
        evidence=(Evidence(path, line, line),),
        severity=severity,
        confidence=Confidence.HIGH,
        impact=impact,
        remediation=_remediation(name, version, members),
        verification=VerificationStatus.UNVERIFIED,
    )


def _identifier(value: object) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError("osv-scanner reported an advisory id with unexpected characters")
    return value


def _preferred(identifiers: list[str]) -> str:
    for prefix in ("CVE-", "GHSA-"):
        for identifier in identifiers:
            if identifier.startswith(prefix):
                return identifier
    return identifiers[0]


def _usable_summary(summary: object) -> bool:
    return isinstance(summary, str) and 0 < len(summary.strip()) <= 300 and "\n" not in summary.strip()


def _severity(score: object) -> tuple[Severity, bool]:
    try:
        value = float(score)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return Severity.MEDIUM, False
    if value >= 9.0:
        return Severity.CRITICAL, True
    if value >= 7.0:
        return Severity.HIGH, True
    if value >= 4.0:
        return Severity.MEDIUM, True
    return Severity.LOW, True


def _remediation(name: str, version: str, members: list[dict[str, object]]) -> str:
    fixed: list[str] = []
    for advisory in members:
        for affected in advisory.get("affected") or []:  # type: ignore[attr-defined]
            if _normalized(str(affected.get("package", {}).get("name"))) != _normalized(name):
                continue
            for version_range in affected.get("ranges") or []:
                if version_range.get("type") != "ECOSYSTEM":
                    continue
                for event in version_range.get("events") or []:
                    candidate = event.get("fixed")
                    if isinstance(candidate, str) and _IDENTIFIER.fullmatch(candidate):
                        if candidate not in fixed:
                            fixed.append(candidate)
    if not fixed:
        return (
            f"No fixed version of {name} is published in the advisory. Check the advisory for "
            "mitigations, or replace or isolate the dependency."
        )
    listed = ", ".join(fixed[:_MAX_FIXED_VERSIONS])
    return (
        f"Upgrade {name} from {version} to a release that contains the fix. Fixed versions "
        f"named by the advisory: {listed}. Run the project's tests after upgrading."
    )


def _arguments(snapshot: Snapshot) -> list[str]:
    # An empty configuration of our own, so that no osv-scanner.toml among the
    # copied files is consulted.
    config = snapshot.scratch / "osv-scanner-empty.toml"
    config.write_bytes(b"")
    return [
        "scan",
        "source",
        "--recursive",
        "--no-ignore",
        "--no-resolve",
        "--format",
        "json",
        "--verbosity",
        "error",
        "--config",
        str(config),
        FILES_DIRNAME,
    ]


OSV_SCANNER = ToolCheck(
    check_id=CHECK_ID,
    tool="osv-scanner",
    applies_to=lambda files: bool(files),
    arguments=_arguments,
    parse=parse_report,
    parse_with_snapshot=True,
    success_exit_codes=frozenset({0, 1}),
    not_applicable_exit_codes=frozenset({128}),
    network_use=(
        "queries api.osv.dev with the names and versions of the dependencies it finds"
    ),
    run_in_container=True,
    version_arguments=("--version",),
    rule_set="OSV advisory database, as published at scan time",
)
