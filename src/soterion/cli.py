"""Command line entry point: scope-check (metadata only) and scan (read-only analysis)."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from soterion import __version__
from soterion.findings import CheckStatus, ScanStatus
from soterion.runner import find_tool
from soterion.checks import DEFAULT_CHECKS
from soterion.scan import ScanReport, ToolCheck, ToolLocator, run_scan
from soterion.scope import Scope, ScopeError, SkippedPath, load_scope, resolve_files

EXIT_NO_FINDINGS = 0
EXIT_FINDINGS = 1
EXIT_SCOPE_REJECTED = 2
EXIT_INCOMPLETE = 3


def display(text: str) -> str:
    """Make repository- or scanner-controlled text safe to print to a terminal."""
    return "".join(char if char.isprintable() else "?" for char in text)


def main(
    argv: Sequence[str] | None = None,
    *,
    checks: Sequence[ToolCheck] = DEFAULT_CHECKS,
    locate: ToolLocator = find_tool,
) -> int:
    parser = argparse.ArgumentParser(
        prog="soterion",
        description="Read-only security review of repositories you own or are authorized to review.",
    )
    parser.add_argument("--version", action="version", version=f"soterion {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    scope_check = commands.add_parser(
        "scope-check",
        help="validate a scope manifest and count the files it allows (reads no file contents)",
    )
    scan = commands.add_parser(
        "scan", help="run the available checks on a private copy of the in-scope files (read-only)"
    )
    for command in (scope_check, scan):
        command.add_argument("manifest", type=Path, help="path to the scope manifest (TOML)")
    scan.add_argument(
        "--tools-dir",
        type=Path,
        action="append",
        metavar="DIR",
        help="absolute directory holding scanner executables; repeatable. "
        "When given, PATH is not searched.",
    )
    args = parser.parse_args(argv)

    tools_dirs: list[Path] | None = getattr(args, "tools_dir", None)
    if tools_dirs:
        if not all(directory.is_absolute() for directory in tools_dirs):
            parser.error("--tools-dir must be an absolute path")

        def locate(name: str, *, forbidden_roots: Sequence[Path] = ()) -> Path | None:
            return find_tool(name, forbidden_roots=forbidden_roots, directories=tools_dirs)

    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")

    try:
        scope = load_scope(args.manifest)
        if args.command == "scope-check":
            return _scope_check(scope)
        return _scan(scope, checks, locate)
    except ScopeError as error:
        print("Scope rejected; nothing was analyzed:", file=sys.stderr)
        for problem in error.problems:
            print(f"  - {display(problem)}", file=sys.stderr)
        return EXIT_SCOPE_REJECTED


def _print_scope(scope: Scope) -> None:
    print(f"Repository: {display(str(scope.repo_root))}")
    print(f"Authorization basis (self-declared, not verified): {scope.authorization_basis}")
    print(f"Allowed actions: {', '.join(sorted(scope.allowed_actions))}")


def _print_skipped(skipped: Sequence[SkippedPath]) -> None:
    print(f"{len(skipped)} paths skipped")
    for item in skipped:
        print(f"  - {display(item.path)} ({item.reason})")


def _scope_check(scope: Scope) -> int:
    resolution = resolve_files(scope)
    _print_scope(scope)
    print(f"{len(resolution.files)} files in scope")
    _print_skipped(resolution.skipped)
    return EXIT_NO_FINDINGS


def _scan(scope: Scope, checks: Sequence[ToolCheck], locate: ToolLocator) -> int:
    report = run_scan(scope, checks, locate=locate)
    _print_scope(scope)
    print(f"{report.file_count} files examined")
    _print_skipped(report.skipped)

    print(f"{len(report.checks)} checks")
    for check in report.checks:
        suffix = f" - {display(check.detail)}" if check.detail else ""
        print(f"  - {display(check.check_id)}: {check.status.value}{suffix}")

    print(f"{len(report.findings)} findings")
    for finding in report.findings:
        first = finding.evidence[0]
        print(
            f"  - {finding.severity.value} severity, {finding.confidence.value} confidence, "
            f"{finding.verification.value}: {display(finding.title)} "
            f"[{display(finding.rule_id)}] at {display(first.path)}:{first.start_line}"
        )

    print(_result_line(report))
    return {
        ScanStatus.NO_FINDINGS: EXIT_NO_FINDINGS,
        ScanStatus.FINDINGS: EXIT_FINDINGS,
        ScanStatus.INCOMPLETE: EXIT_INCOMPLETE,
    }[report.summary.status]


def _result_line(report: ScanReport) -> str:
    summary = report.summary
    if summary.status is ScanStatus.NO_FINDINGS:
        return (
            "Result: no findings from the checks listed above. "
            "This is not proof that the code is free of vulnerabilities."
        )
    if summary.status is ScanStatus.FINDINGS:
        return (
            f"Result: {summary.finding_count} finding(s). Each is a scanner report and may be "
            "a false positive; review the evidence before acting."
        )
    reasons = []
    if not any(check.status is CheckStatus.COMPLETED for check in report.checks):
        reasons.append("no check completed")
    if summary.incomplete_checks:
        reasons.append(f"checks that did not complete: {', '.join(summary.incomplete_checks)}")
    if summary.skipped_path_count:
        reasons.append(f"{summary.skipped_path_count} in-scope path(s) were not examined")
    return (
        f"Result: scan incomplete ({display('; '.join(reasons))}). "
        f"{summary.finding_count} finding(s) so far. Do not treat this as a clean result."
    )


if __name__ == "__main__":
    raise SystemExit(main())
