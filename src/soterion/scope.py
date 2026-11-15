"""Scope manifest: the only source of what Soterion may read and which actions it may take.

The manifest is supplied explicitly by the operator and must live outside the
target repository, so that repository content (which is untrusted input) can
never define or widen its own scope. Nothing here reads file contents or
follows links; files are selected by name and metadata only.
"""

from __future__ import annotations

import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = 1
ACTIONS = frozenset({"analyze", "propose-fix"})
AUTHORIZATION_BASES = ("owner", "authorized")

DEFAULT_MAX_FILE_SIZE_BYTES = 1024 * 1024
DEFAULT_MAX_FILES = 20_000
DEFAULT_MAX_TOTAL_BYTES = 1024 * 1024 * 1024

_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_PATTERNS = 200
_MAX_PATTERN_LENGTH = 300
_LIMIT_CEILINGS = {
    "max_file_size_bytes": 100 * 1024 * 1024,
    "max_files": 1_000_000,
    "max_total_bytes": 20 * 1024 * 1024 * 1024,
}

_SECTION_KEYS: dict[str, frozenset[str]] = {
    "target": frozenset({"repo_path"}),
    "authorization": frozenset({"basis", "attestation", "reference"}),
    "scope": frozenset({"include", "exclude"}),
    "actions": frozenset({"allowed"}),
    "limits": frozenset({"max_file_size_bytes", "max_files", "max_total_bytes"}),
    "network": frozenset({"allowed_checks"}),
}
_OPTIONAL_SECTIONS = frozenset({"limits", "network"})
_CHECK_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")


class ScopeError(ValueError):
    """The scope is missing, invalid, or cannot be honored. Carries every problem found."""

    def __init__(self, problems: list[str]) -> None:
        self.problems: tuple[str, ...] = tuple(problems)
        super().__init__("; ".join(self.problems))


@dataclass(frozen=True)
class Scope:
    repo_root: Path
    include: tuple[str, ...]
    exclude: tuple[str, ...]
    allowed_actions: frozenset[str]
    authorization_basis: str
    max_file_size_bytes: int
    max_files: int
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    # Ids of the checks that may contact the network. Empty unless the manifest says so.
    network_checks: frozenset[str] = frozenset()

    def permits(self, action: str) -> bool:
        return action in self.allowed_actions


@dataclass(frozen=True)
class SkippedPath:
    """A path that was in scope by name but was deliberately not included."""

    path: str
    reason: str  # "link" | "too_large" | "unreadable"


@dataclass(frozen=True)
class ScopeResolution:
    files: tuple[str, ...]
    skipped: tuple[SkippedPath, ...]


def load_scope(manifest_path: str | os.PathLike[str]) -> Scope:
    """Parse and validate a scope manifest. Raises ScopeError listing every problem."""
    manifest = Path(manifest_path)
    data = _read_manifest(manifest)
    problems: list[str] = []

    for name in sorted(data.keys() - _SECTION_KEYS.keys() - {"schema_version"}):
        problems.append(f"unknown section or key {name!r}")

    version = data.get("schema_version")
    if type(version) is not int or version != SCHEMA_VERSION:
        problems.append(f"schema_version: must be {SCHEMA_VERSION}")

    sections = {name: _section(data, name, problems) for name in _SECTION_KEYS}

    repo_root = _check_repo_path(sections["target"], manifest, problems)
    basis = _check_authorization(sections["authorization"], problems)
    include = _check_patterns(sections["scope"], "include", problems, required="scope" in data)
    exclude = _check_patterns(sections["scope"], "exclude", problems, required=False)
    allowed = _check_actions(sections["actions"], problems, present="actions" in data)
    max_file_size = _check_limit(
        sections["limits"], "max_file_size_bytes", DEFAULT_MAX_FILE_SIZE_BYTES, problems
    )
    max_files = _check_limit(sections["limits"], "max_files", DEFAULT_MAX_FILES, problems)
    network_checks = _check_network(sections["network"], problems)
    max_total = _check_limit(
        sections["limits"], "max_total_bytes", DEFAULT_MAX_TOTAL_BYTES, problems
    )

    if problems or repo_root is None:
        raise ScopeError(problems)
    return Scope(
        repo_root=repo_root,
        include=include,
        exclude=exclude,
        allowed_actions=allowed,
        authorization_basis=basis,
        max_file_size_bytes=max_file_size,
        max_files=max_files,
        max_total_bytes=max_total,
        network_checks=network_checks,
    )


def resolve_files(scope: Scope) -> ScopeResolution:
    """List the files the scope allows, without following links or reading contents.

    Links, oversized files and unreadable paths are reported in ``skipped`` so a
    later report can show that coverage was partial instead of implying it was full.
    """
    root = scope.repo_root
    files: list[str] = []
    skipped: list[SkippedPath] = []
    total_bytes = 0

    def on_walk_error(error: OSError) -> None:
        skipped.append(SkippedPath(_relative(root, Path(error.filename or root)), "unreadable"))

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=on_walk_error):
        current = Path(dirpath)
        descend: list[str] = []
        for name in sorted(dirnames):
            if _is_git_metadata(name):
                continue
            full = current / name
            if _is_link(full):
                relative = _relative(root, full)
                if not _matches(relative, scope.exclude, case_sensitive=False):
                    skipped.append(SkippedPath(relative, "link"))
                continue
            descend.append(name)
        dirnames[:] = descend

        for name in sorted(filenames):
            if _is_git_metadata(name):
                continue
            full = current / name
            relative = _relative(root, full)
            if not _matches(relative, scope.include, case_sensitive=True):
                continue
            if _matches(relative, scope.exclude, case_sensitive=False):
                continue
            try:
                info = os.lstat(full)
            except OSError:
                skipped.append(SkippedPath(relative, "unreadable"))
                continue
            if _is_link(full) or not stat.S_ISREG(info.st_mode):
                skipped.append(SkippedPath(relative, "link"))
                continue
            if info.st_size > scope.max_file_size_bytes:
                skipped.append(SkippedPath(relative, "too_large"))
                continue
            files.append(relative)
            if len(files) > scope.max_files:
                raise ScopeError(
                    [
                        f"limits.max_files: more than {scope.max_files} files are in scope; "
                        "narrow scope.include or raise the limit explicitly"
                    ]
                )
            total_bytes += info.st_size
            if total_bytes > scope.max_total_bytes:
                raise ScopeError(
                    [
                        f"limits.max_total_bytes: files in scope exceed {scope.max_total_bytes} "
                        "bytes in total; narrow scope.include or raise the limit explicitly"
                    ]
                )

    return ScopeResolution(files=tuple(sorted(files)), skipped=tuple(sorted(skipped, key=_skip_key)))


def _skip_key(item: SkippedPath) -> tuple[str, str]:
    return (item.path, item.reason)


def _read_manifest(manifest: Path) -> dict[str, Any]:
    try:
        if manifest.stat().st_size > _MAX_MANIFEST_BYTES:
            raise ScopeError([f"manifest is larger than {_MAX_MANIFEST_BYTES} bytes"])
        raw = manifest.read_bytes()
    except OSError:
        raise ScopeError([f"manifest cannot be read: {manifest}"]) from None
    try:
        return tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ScopeError([f"manifest is not valid UTF-8 TOML: {exc}"]) from None


def _section(data: dict[str, Any], name: str, problems: list[str]) -> dict[str, Any]:
    if name not in data:
        if name not in _OPTIONAL_SECTIONS:
            problems.append(f"{name}: section is required")
        return {}
    section = data[name]
    if not isinstance(section, dict):
        problems.append(f"{name}: must be a table")
        return {}
    for key in sorted(section.keys() - _SECTION_KEYS[name]):
        problems.append(f"{name}: unknown key {key!r}")
    return section


def _check_repo_path(target: dict[str, Any], manifest: Path, problems: list[str]) -> Path | None:
    if not target:
        return None
    raw = target.get("repo_path")
    key = "target.repo_path"
    if not isinstance(raw, str) or not raw.strip():
        problems.append(f"{key}: is required and must be a path string")
        return None
    if _is_unc(raw):
        # Checked before touching the filesystem: resolving a UNC path contacts a remote host.
        problems.append(f"{key}: UNC, network and device paths are not allowed; use a local disk")
        return None
    if "://" in raw or not Path(raw).is_absolute():
        problems.append(f"{key}: must be an absolute path on the local filesystem, not a URL")
        return None
    try:
        resolved = Path(raw).resolve(strict=True)
    except OSError:
        problems.append(f"{key}: does not exist or cannot be accessed")
        return None
    if _is_unc(str(resolved)):
        problems.append(f"{key}: resolves to a UNC or network location; use a local disk")
        return None
    if not resolved.is_dir():
        problems.append(f"{key}: is not a directory")
        return None
    try:
        manifest_inside = manifest.resolve().is_relative_to(resolved)
    except OSError:
        manifest_inside = True
    if manifest_inside:
        problems.append(
            f"{key}: the manifest is stored inside the target repository; keep it outside "
            "so repository content cannot define its own scope"
        )
        return None
    return resolved


def _is_unc(path: str) -> bool:
    return path.startswith(("\\\\", "//"))


def _check_authorization(section: dict[str, Any], problems: list[str]) -> str:
    if not section:
        return ""
    basis = section.get("basis")
    if basis not in AUTHORIZATION_BASES:
        problems.append(f"authorization.basis: must be one of {', '.join(AUTHORIZATION_BASES)}")
    if section.get("attestation") is not True:
        problems.append(
            "authorization.attestation: must be the boolean true, declaring that you own "
            "this repository or are explicitly authorized to review it"
        )
    reference = section.get("reference")
    if reference is not None and (not isinstance(reference, str) or not reference.strip()):
        problems.append("authorization.reference: must be a non-empty string when present")
    elif basis == "authorized" and reference is None:
        problems.append("authorization.reference: is required when basis is 'authorized'")
    return basis if isinstance(basis, str) else ""


def _check_patterns(
    section: dict[str, Any], name: str, problems: list[str], *, required: bool
) -> tuple[str, ...]:
    key = f"scope.{name}"
    if name not in section:
        if required:
            problems.append(f"{key}: is required; list the file patterns that may be read")
        return ()
    patterns = section[name]
    if not isinstance(patterns, list) or (required and not patterns):
        problems.append(f"{key}: must be a non-empty list of glob patterns")
        return ()
    if len(patterns) > _MAX_PATTERNS:
        problems.append(f"{key}: at most {_MAX_PATTERNS} patterns are allowed")
        return ()
    valid = True
    for pattern in patterns:
        reason = _pattern_problem(pattern)
        if reason:
            problems.append(f"{key}: pattern {str(pattern)[:80]!r} {reason}")
            valid = False
    return tuple(patterns) if valid else ()


def _pattern_problem(pattern: object) -> str:
    if not isinstance(pattern, str) or not pattern:
        return "must be a non-empty string"
    if len(pattern) > _MAX_PATTERN_LENGTH:
        return "is too long"
    if "\\" in pattern:
        return "must use forward slashes"
    if pattern.startswith("/") or ":" in pattern:
        return "must be relative to the repository root"
    if ".." in pattern.split("/"):
        return "must not contain '..'"
    try:
        PurePosixPath("probe").full_match(pattern)
    except ValueError:
        return "is not a valid glob pattern"
    return ""


def _check_actions(section: dict[str, Any], problems: list[str], *, present: bool) -> frozenset[str]:
    if not present:
        return frozenset()
    allowed = section.get("allowed")
    if not isinstance(allowed, list) or not all(isinstance(item, str) for item in allowed):
        problems.append("actions.allowed: must be a list of action names")
        return frozenset()
    for action in sorted(set(allowed) - ACTIONS):
        problems.append(
            f"actions.allowed: unknown action {action[:40]!r}; known: {', '.join(sorted(ACTIONS))}"
        )
    if "analyze" not in allowed:
        problems.append("actions.allowed: must contain 'analyze'; every other action builds on it")
    return frozenset(allowed) & ACTIONS


def _check_network(section: dict[str, Any], problems: list[str]) -> frozenset[str]:
    if "allowed_checks" not in section:
        return frozenset()
    allowed = section["allowed_checks"]
    valid = isinstance(allowed, list) and all(
        isinstance(item, str) and _CHECK_ID.fullmatch(item) for item in allowed
    )
    if not valid:
        problems.append(
            "network.allowed_checks: must be a list of check ids (lowercase letters, "
            "digits and hyphens) naming the checks that may use the network"
        )
        return frozenset()
    return frozenset(allowed)


def _check_limit(section: dict[str, Any], name: str, default: int, problems: list[str]) -> int:
    if name not in section:
        return default
    value = section[name]
    ceiling = _LIMIT_CEILINGS[name]
    if type(value) is not int or not 1 <= value <= ceiling:
        problems.append(f"limits.{name}: must be an integer between 1 and {ceiling}")
        return default
    return value


def _relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def _is_git_metadata(name: str) -> bool:
    return name.lower() == ".git"


def _is_link(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def _matches(relative: str, patterns: tuple[str, ...], *, case_sensitive: bool) -> bool:
    candidate = PurePosixPath(relative)
    return any(candidate.full_match(pattern, case_sensitive=case_sensitive) for pattern in patterns)
