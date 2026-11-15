"""Run checks against a snapshot of the scope and turn every outcome into an explicit status.

Scanner output is treated as untrusted input. A check only counts as completed
when its tool was found, started, finished in time, exited with an expected
code, produced parseable output, and every finding it reported points at a
real line of a file that is actually in the snapshot. Anything else is
reported as skipped or failed; it is never folded into "no findings".
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from soterion.findings import CheckResult, CheckStatus, Finding, ScanSummary, summarize
from soterion.runner import ToolOutcome, find_tool, run_tool
from soterion.scope import Scope, SkippedPath, resolve_files
from soterion.staging import Snapshot, staged_snapshot


class ToolLocator(Protocol):
    def __call__(self, name: str, *, forbidden_roots: Sequence[Path] = ()) -> Path | None: ...


@dataclass(frozen=True)
class ParsedOutput:
    """What a parser understood from a tool's output.

    ``problem`` is set when the tool ran but did not fully do its job (for
    example, it could not parse some files); it fails the check.
    ``limitation`` describes a narrow, known gap that does not fail the check
    but must stay visible next to its result. ``examined_files`` lists the
    repository-relative files the tool says it examined, when it reports that;
    any in-scope file missing from it fails the check.
    """

    findings: Sequence[Finding]
    problem: str = ""
    examined_files: frozenset[str] | None = None
    limitation: str = ""


def _no_extra_environment(snapshot: Snapshot) -> Mapping[str, str]:
    return {}


@dataclass(frozen=True)
class ToolCheck:
    """One external scanner: how to invoke it and how to read what it prints."""

    check_id: str
    tool: str
    applies_to: Callable[[tuple[str, ...]], bool]
    arguments: Callable[[Snapshot], Sequence[str]]
    # Called with the tool's standard output, and also with the snapshot when
    # parse_with_snapshot is set (for tools that do not report line numbers).
    parse: Callable[..., Sequence[Finding] | ParsedOutput]
    success_exit_codes: frozenset[int] = frozenset({0})
    # Exit codes by which the tool itself says there was nothing for it to check.
    not_applicable_exit_codes: frozenset[int] = frozenset()
    parse_with_snapshot: bool = False
    timeout_seconds: float = 600
    max_output_bytes: int = 50 * 1024 * 1024
    # Extra environment for the tool. It may point the tool at snapshot.scratch.
    environment: Callable[[Snapshot], Mapping[str, str]] = _no_extra_environment
    # Non-empty when the tool contacts the network; says what for. Such a check
    # only runs when the scope manifest names it under [network] allowed_checks.
    network_use: str = ""
    # Run from the snapshot's container instead of the copied files, for tools
    # that read suppression or configuration files from the directory they scan.
    run_in_container: bool = False


@dataclass(frozen=True)
class ScanReport:
    checks: tuple[CheckResult, ...]
    findings: tuple[Finding, ...]
    skipped: tuple[SkippedPath, ...]
    file_count: int
    summary: ScanSummary
    network_used: tuple[str, ...] = ()  # ids of the checks that were run with network access


def run_scan(
    scope: Scope, checks: Sequence[ToolCheck], *, locate: ToolLocator = find_tool
) -> ScanReport:
    if not scope.permits("analyze"):
        raise PermissionError("the scope does not permit the 'analyze' action")
    check_ids = [check.check_id for check in checks]
    if len(set(check_ids)) != len(check_ids):
        raise ValueError("check ids must be unique")

    resolution = resolve_files(scope)
    results: list[CheckResult] = []
    findings: list[Finding] = []
    with staged_snapshot(scope, resolution) as snapshot:
        for check in checks:
            result, accepted = _run_check(check, scope, snapshot, locate)
            results.append(result)
            findings.extend(accepted)
        skipped = resolution.skipped + snapshot.skipped
        file_count = len(snapshot.files)

    return ScanReport(
        checks=tuple(results),
        findings=tuple(findings),
        skipped=skipped,
        file_count=file_count,
        summary=summarize(results, findings, skipped_path_count=len(skipped)),
        network_used=tuple(
            check.check_id
            for check, result in zip(checks, results, strict=True)
            if check.network_use and result.status in (CheckStatus.COMPLETED, CheckStatus.FAILED)
        ),
    )


def _run_check(
    check: ToolCheck, scope: Scope, snapshot: Snapshot, locate: ToolLocator
) -> tuple[CheckResult, tuple[Finding, ...]]:
    def outcome(status: CheckStatus, detail: str = "") -> CheckResult:
        return CheckResult(check.check_id, status, detail)

    if not check.applies_to(snapshot.files):
        return outcome(CheckStatus.NOT_APPLICABLE, "no relevant files in scope"), ()

    if check.network_use and check.check_id not in scope.network_checks:
        detail = (
            f"needs network access ({check.network_use}); to allow it, add "
            f'"{check.check_id}" to allowed_checks under [network] in the scope manifest'
        )
        return outcome(CheckStatus.SKIPPED, detail), ()

    executable = locate(
        check.tool, forbidden_roots=(scope.repo_root, snapshot.container, snapshot.scratch)
    )
    if executable is None:
        return outcome(CheckStatus.SKIPPED, f"{check.tool} was not found on PATH"), ()

    run = run_tool(
        [str(executable), *(str(argument) for argument in check.arguments(snapshot))],
        cwd=snapshot.container if check.run_in_container else snapshot.root,
        timeout_seconds=check.timeout_seconds,
        max_output_bytes=check.max_output_bytes,
        env=check.environment(snapshot),
    )
    if run.outcome is ToolOutcome.START_FAILED:
        return outcome(CheckStatus.FAILED, f"{check.tool} could not be started"), ()
    if run.outcome is ToolOutcome.TIMED_OUT:
        detail = f"{check.tool} timed out after {check.timeout_seconds:g} seconds"
        return outcome(CheckStatus.FAILED, detail), ()
    if run.outcome is ToolOutcome.OUTPUT_TOO_LARGE:
        detail = f"{check.tool} printed more than {check.max_output_bytes} bytes"
        return outcome(CheckStatus.FAILED, detail), ()
    if run.exit_code in check.not_applicable_exit_codes:
        detail = f"{check.tool} found nothing in scope that it can check"
        return outcome(CheckStatus.NOT_APPLICABLE, detail), ()
    if run.exit_code not in check.success_exit_codes:
        detail = f"{check.tool} exited with unexpected code {run.exit_code}"
        return outcome(CheckStatus.FAILED, detail), ()

    try:
        if check.parse_with_snapshot:
            parsed = check.parse(run.stdout, snapshot)
        else:
            parsed = check.parse(run.stdout)
        output = parsed if isinstance(parsed, ParsedOutput) else ParsedOutput(parsed)
        reported = tuple(output.findings)
    except Exception:  # noqa: BLE001 - output is untrusted; any parsing error fails the check
        return outcome(CheckStatus.FAILED, f"{check.tool} output could not be parsed"), ()

    accepted = _attributable(reported, check, snapshot)
    problems: list[str] = []
    rejected = len(reported) - len(accepted)
    if rejected:
        problems.append(
            f"{rejected} reported finding(s) were rejected because they do not point at "
            "an existing line of an in-scope file"
        )
    if output.problem:
        problems.append(output.problem)
    if output.examined_files is not None:
        unexamined = len(set(snapshot.files) - output.examined_files)
        if unexamined:
            problems.append(f"{unexamined} in-scope file(s) were not examined by {check.tool}")
    if problems:
        if output.limitation:
            problems.append(output.limitation)
        return outcome(CheckStatus.FAILED, "; ".join(problems)), accepted
    return outcome(CheckStatus.COMPLETED, output.limitation), accepted


def _attributable(
    reported: Sequence[object], check: ToolCheck, snapshot: Snapshot
) -> tuple[Finding, ...]:
    """Keep only findings from this check whose evidence exists in the snapshot."""
    in_scope = frozenset(snapshot.files)
    line_counts: dict[str, int] = {}

    def line_count(path: str) -> int:
        if path not in line_counts:
            data = (snapshot.root / path).read_bytes()
            line_counts[path] = data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)
        return max(line_counts[path], 1)

    accepted: list[Finding] = []
    for item in reported:
        if not isinstance(item, Finding) or item.check_id != check.check_id:
            continue
        if all(
            evidence.path in in_scope and evidence.end_line <= line_count(evidence.path)
            for evidence in item.evidence
        ):
            accepted.append(item)
    return tuple(accepted)
