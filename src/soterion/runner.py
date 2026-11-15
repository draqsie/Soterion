"""Locate and run external scanners with a small, explicit attack surface.

* The executable is always an absolute path, never looked up in the current
  directory or inside the analyzed repository, and never a batch file.
* No shell. Arguments are passed as a list.
* The child gets a minimal environment, so tokens and keys in the caller's
  environment never reach a scanner.
* Standard input is closed, standard error is discarded (it may quote source
  lines), and standard output is bounded in size and time.
"""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

_PASSTHROUGH_ENV = frozenset(
    {"SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "TEMP", "TMP", "TMPDIR", "PATHEXT", "LANG", "LC_ALL"}
)
_POLL_SECONDS = 0.1
_KILL_WAIT_SECONDS = 10


class ToolOutcome(StrEnum):
    EXITED = "exited"
    START_FAILED = "start_failed"
    TIMED_OUT = "timed_out"
    OUTPUT_TOO_LARGE = "output_too_large"


@dataclass(frozen=True)
class ToolRun:
    outcome: ToolOutcome
    exit_code: int | None = None
    stdout: bytes = b""


def find_tool(
    name: str,
    *,
    forbidden_roots: Sequence[Path] = (),
    directories: Sequence[Path] | None = None,
) -> Path | None:
    """Find ``name`` in the absolute entries of PATH, ignoring the current directory.

    When ``directories`` is given, only those are searched and PATH is ignored.
    Executables located under any of ``forbidden_roots`` (the analyzed repository
    and its snapshot) are ignored so analyzed content can never be run as a tool.
    """
    if not name or name in (".", "..") or Path(name).name != name:
        raise ValueError("tool name must be a bare file name")
    filename = f"{name}.exe" if os.name == "nt" else name
    forbidden = [Path(root).resolve() for root in forbidden_roots]
    if directories is None:
        entries = os.environ.get("PATH", "").split(os.pathsep)
    else:
        entries = [str(directory) for directory in directories]

    for entry in entries:
        entry = entry.strip('"')
        if not entry or entry.startswith(("\\\\", "//")) or not Path(entry).is_absolute():
            continue
        try:
            candidate = (Path(entry) / filename).resolve(strict=True)
        except OSError:
            continue
        if not candidate.is_file():
            continue
        if os.name != "nt" and not os.access(candidate, os.X_OK):
            continue
        if any(candidate.is_relative_to(root) for root in forbidden):
            continue
        return candidate
    return None


def run_tool(
    argv: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    max_output_bytes: int,
    env: Mapping[str, str] | None = None,
) -> ToolRun:
    """Run a tool to completion and return its bounded standard output.

    Never raises for tool misbehavior: a tool that cannot start, runs too long
    or prints too much is reported through ``ToolRun.outcome``.
    """
    if not argv or not Path(argv[0]).is_absolute():
        raise ValueError("the tool executable must be given as an absolute path")

    with tempfile.TemporaryFile() as output:
        try:
            process = subprocess.Popen(
                list(argv),
                cwd=cwd,
                env=_child_environment(env),
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.DEVNULL,
                shell=False,
                **_isolation_options(),
            )
        except OSError:
            return ToolRun(ToolOutcome.START_FAILED)

        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                process.wait(timeout=_POLL_SECONDS)
                break
            except subprocess.TimeoutExpired:
                pass
            if os.fstat(output.fileno()).st_size > max_output_bytes:
                _kill_tree(process)
                return ToolRun(ToolOutcome.OUTPUT_TOO_LARGE)
            if time.monotonic() >= deadline:
                _kill_tree(process)
                return ToolRun(ToolOutcome.TIMED_OUT)

        if os.fstat(output.fileno()).st_size > max_output_bytes:
            return ToolRun(ToolOutcome.OUTPUT_TOO_LARGE)
        output.seek(0)
        return ToolRun(ToolOutcome.EXITED, process.returncode, output.read())


def _child_environment(extra: Mapping[str, str] | None) -> dict[str, str]:
    environment = {
        name: value for name, value in os.environ.items() if name.upper() in _PASSTHROUGH_ENV
    }
    environment["PATH"] = _system_path()
    environment.update(extra or {})
    return environment


def _system_path() -> str:
    if os.name == "nt":
        return str(_system_root() / "System32")
    return "/usr/bin:/bin"


def _system_root() -> Path:
    return Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))


def _isolation_options() -> dict[str, object]:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NO_WINDOW}
    return {"start_new_session": True}


def _kill_tree(process: subprocess.Popen[bytes]) -> None:
    """Stop the tool and, as far as the platform allows, everything it started."""
    if os.name == "nt":
        taskkill = _system_root() / "System32" / "taskkill.exe"
        try:
            subprocess.run(
                [str(taskkill), "/T", "/F", "/PID", str(process.pid)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=_KILL_WAIT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=_KILL_WAIT_SECONDS)
    except subprocess.TimeoutExpired:
        pass
