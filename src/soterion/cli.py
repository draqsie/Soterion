"""Command line entry point: scope-check (metadata only) and scan (read-only analysis)."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from soterion import __version__
from soterion.checks import DEFAULT_CHECKS
from soterion.findings import ScanStatus
from soterion.report import (
    ReportError,
    build_report,
    prepare_output_dir,
    result_statement,
    write_json_report,
)
from soterion.runner import find_tool
from soterion.scan import ToolCheck, ToolLocator, run_scan
from soterion.scope import Scope, ScopeError, SkippedPath, load_scope, resolve_files

EXIT_NO_FINDINGS = 0
EXIT_FINDINGS = 1
EXIT_REJECTED = 2  # the scope or the output directory was refused; nothing was analyzed
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
    scan.add_argument(
        "--output-dir",
        type=Path,
        metavar="DIR",
        help="absolute directory, outside the analyzed repository, to write the report to. "
        "Without it, no file is written.",
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
        return _scan(scope, checks, locate, args.output_dir)
    except ScopeError as error:
        print("Scope rejected; nothing was analyzed:", file=sys.stderr)
        for problem in error.problems:
            print(f"  - {display(problem)}", file=sys.stderr)
        return EXIT_REJECTED


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


def _scan(
    scope: Scope, checks: Sequence[ToolCheck], locate: ToolLocator, output_dir: Path | None
) -> int:
    report_dir = None
    if output_dir is not None:
        # Refused before anything runs, so a scan is never done and then lost.
        try:
            report_dir = prepare_output_dir(output_dir, scope.repo_root)
        except ReportError as error:
            print(f"Output directory rejected; nothing was analyzed: {error}", file=sys.stderr)
            return EXIT_REJECTED

    report = run_scan(scope, checks, locate=locate)
    _print_scope(scope)
    print(f"{report.file_count} files examined")
    _print_skipped(report.skipped)

    print(f"{len(report.checks)} checks")
    for check in report.checks:
        suffix = f" - {display(check.detail)}" if check.detail else ""
        print(f"  - {display(check.check_id)}: {check.status.value}{suffix}")

    descriptions = {check.check_id: check.network_use for check in checks}
    if not report.network_used:
        print("Network access used: none")
    for check_id in report.network_used:
        print(f"Network access used by {display(check_id)}: {display(descriptions[check_id])}")

    print(f"{len(report.findings)} findings")
    for finding in report.findings:
        first = finding.evidence[0]
        print(
            f"  - {finding.severity.value} severity, {finding.confidence.value} confidence, "
            f"{finding.verification.value}: {display(finding.title)} "
            f"[{display(finding.rule_id)}] at {display(first.path)}:{first.start_line}"
        )

    if report.redactions:
        print(f"{report.redactions} value(s) masked in scanner text")
    if not report.secrets_located:
        print(
            "Warning: no secret-detection check completed, so scanner text could only be "
            "masked by shape. Treat this output and any report as possibly containing secrets."
        )
    print(f"Result: {result_statement(report)}")

    exit_code = {
        ScanStatus.NO_FINDINGS: EXIT_NO_FINDINGS,
        ScanStatus.FINDINGS: EXIT_FINDINGS,
        ScanStatus.INCOMPLETE: EXIT_INCOMPLETE,
    }[report.summary.status]
    if report_dir is not None:
        document = build_report(scope, report, generated_at=datetime.now(UTC))
        try:
            written = write_json_report(document, report_dir)
        except ReportError as error:
            print(f"Report not written: {error}", file=sys.stderr)
            return EXIT_INCOMPLETE
        print(f"Report written to {display(str(written))}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
