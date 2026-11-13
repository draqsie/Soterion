"""Private snapshot of the in-scope files.

Scanners never run against the repository itself. They run against a copy that
contains only the files the scope allows, so they cannot reach ``.git``, links,
out-of-scope files or anything that changed after the scope was resolved.

Each file is re-checked while it is copied: it must still be a regular file
reached without passing through any link, and still within the size limit.
Anything that fails is reported as skipped, never copied.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from soterion.scope import Scope, ScopeResolution, SkippedPath


@dataclass(frozen=True)
class Snapshot:
    root: Path
    files: tuple[str, ...]
    skipped: tuple[SkippedPath, ...]


@contextmanager
def staged_snapshot(scope: Scope, resolution: ScopeResolution) -> Iterator[Snapshot]:
    """Copy the resolved files into a temporary directory that is removed on exit."""
    root = Path(tempfile.mkdtemp(prefix="soterion-")).resolve()
    try:
        files: list[str] = []
        skipped: list[SkippedPath] = []
        for relative in resolution.files:
            reason = _copy_file(scope, relative, root)
            if reason is None:
                files.append(relative)
            else:
                skipped.append(SkippedPath(relative, reason))
        yield Snapshot(root=root, files=tuple(files), skipped=tuple(skipped))
    finally:
        shutil.rmtree(root)


def _copy_file(scope: Scope, relative: str, staging_root: Path) -> str | None:
    """Copy one file; return None on success or the reason it was skipped."""
    source = scope.repo_root / relative
    try:
        # repo_root is already resolved, so any difference means a link on the way.
        if source.resolve(strict=True) != source:
            return "link"
        listed = os.lstat(source)
        if not stat.S_ISREG(listed.st_mode):
            return "link"
        with open(source, "rb") as handle:
            opened = os.fstat(handle.fileno())
            same_file = (opened.st_dev, opened.st_ino) == (listed.st_dev, listed.st_ino)
            if not same_file or not stat.S_ISREG(opened.st_mode):
                return "link"
            data = handle.read(scope.max_file_size_bytes + 1)
    except OSError:
        return "unreadable"
    if len(data) > scope.max_file_size_bytes:
        return "too_large"
    destination = staging_root / relative
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    except OSError:
        return "unreadable"
    return None
