"""Run checks against a snapshot of the scope and turn every outcome into an explicit status.

Scanner output is treated as untrusted input. A check only counts as completed
when its tool was found, started, finished in time, exited with an expected
code, produced parseable output, and every finding it reported points at a
real line of a file that is actually in the snapshot. Anything else is
reported as skipped or failed; it is never folded into "no findings".
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from soterion.findings import CheckResult, CheckStatus, Finding, ScanSummary, summarize
from soterion.runner import ToolOutcome, find_tool, run_tool
from soterion.scope import Scope, SkippedPath, resolve_files
from soterion.staging import Snapshot, staged_snapshot


class ToolLocator(Protocol):
    def __call__(self, name: str, *, forbidden_roots: Sequence[Path] = ()) -> Path | None: ...


@dataclass(frozen=True)
class ToolCheck:
    """One external scanner: how to invoke it and how to read what it prints."""

    check_id: str
    tool: str
    applies_to: Callable[[tuple[str, ...]], bool]
    arguments: Callable[[Snapshot], Sequence[str]]
    parse: Callable[[bytes], Sequence[Finding]]
    success_exit_codes: frozenset[int] = frozenset({0})
    timeout_seconds: float = 600
    max_output_bytes: int = 50 * 1024 * 1024
    environment: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ScanReport:
    checks: tuple[CheckResult, ...]
    findings: tuple[Finding, ...]
    skipped: tuple[SkippedPath, ...]
    file_count: int
    summary: ScanSummary


# Scanner adapters are registered here. None ship yet, so a scan with the
# default set reports "incomplete" rather than an empty, clean-looking result.
DEFAULT_CHECKS: tuple[ToolCheck, ...] = ()


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
    )


def _run_check(
    check: ToolCheck, scope: Scope, snapshot: Snapshot, locate: ToolLocator
) -> tuple[CheckResult, tuple[Finding, ...]]:
    def outcome(status: CheckStatus, detail: str = "") -> CheckResult:
        return CheckResult(check.check_id, status, detail)

    if not check.applies_to(snapshot.files):
        return outcome(CheckStatus.NOT_APPLICABLE, "no relevant files in scope"), ()

    executable = locate(check.tool, forbidden_roots=(scope.repo_root, snapshot.root))
    if executable is None:
        return outcome(CheckStatus.SKIPPED, f"{check.tool} was not found on PATH"), ()

    run = run_tool(
        [str(executable), *(str(argument) for argument in check.arguments(snapshot))],
        cwd=snapshot.root,
        timeout_seconds=check.timeout_seconds,
        max_output_bytes=check.max_output_bytes,
        env=check.environment,
    )
    if run.outcome is ToolOutcome.START_FAILED:
        return outcome(CheckStatus.FAILED, f"{check.tool} could not be started"), ()
    if run.outcome is ToolOutcome.TIMED_OUT:
        detail = f"{check.tool} timed out after {check.timeout_seconds:g} seconds"
        return outcome(CheckStatus.FAILED, detail), ()
    if run.outcome is ToolOutcome.OUTPUT_TOO_LARGE:
        detail = f"{check.tool} printed more than {check.max_output_bytes} bytes"
        return outcome(CheckStatus.FAILED, detail), ()
    if run.exit_code not in check.success_exit_codes:
        detail = f"{check.tool} exited with unexpected code {run.exit_code}"
        return outcome(CheckStatus.FAILED, detail), ()

    try:
        reported = tuple(check.parse(run.stdout))
    except Exception:  # noqa: BLE001 - output is untrusted; any parsing error fails the check
        return outcome(CheckStatus.FAILED, f"{check.tool} output could not be parsed"), ()

    accepted = _attributable(reported, check, snapshot)
    rejected = len(reported) - len(accepted)
    if rejected:
        detail = (
            f"{rejected} reported finding(s) were rejected because they do not point at "
            "an existing line of an in-scope file"
        )
        return outcome(CheckStatus.FAILED, detail), accepted
    return outcome(CheckStatus.COMPLETED), accepted


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
