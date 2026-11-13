"""Shared fixtures: a throwaway repository and a scope manifest stored outside it."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from soterion.findings import Confidence, Evidence, Finding, Severity, VerificationStatus
from soterion.scan import ToolCheck

_BASE_SECTIONS = {
    "head": "schema_version = 1\n",
    "target": '[target]\nrepo_path = "{repo}"\n',
    "authorization": '[authorization]\nbasis = "owner"\nattestation = true\n',
    "scope": '[scope]\ninclude = ["**/*.py"]\n',
    "actions": '[actions]\nallowed = ["analyze"]\n',
}


class RepoTestCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name).resolve()
        self.repo = self.tmp / "repo"
        self.repo.mkdir()

    def add_file(self, relative: str, content: str = "x = 1\n", *, root: Path | None = None) -> Path:
        path = (root or self.repo) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("utf-8"))
        return path

    def write_manifest(self, **sections: str) -> Path:
        """Write a valid manifest; pass a section name to replace it ('' removes it)."""
        parts = {**_BASE_SECTIONS, **sections}
        text = "".join(parts.values()).replace("{repo}", self.repo.as_posix())
        path = self.tmp / "manifests" / "scope.toml"
        path.parent.mkdir(exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path


def write_tool(directory: Path, name: str, source: str) -> Path:
    """Write a stand-in scanner: a Python script the tests run through the real runner."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.py"
    path.write_text(source, encoding="utf-8")
    return path


def emitting(items: list[dict[str, object]], exit_code: int = 0) -> str:
    """Source of a stand-in scanner that reports ``items`` as JSON and exits."""
    return f"import json, sys\nprint(json.dumps({items!r}))\nsys.exit({exit_code})\n"


def locate_python(name: str, *, forbidden_roots: Sequence[Path] = ()) -> Path | None:
    """Stand-in for find_tool: 'fake-scanner' is the Python interpreter, nothing else exists."""
    return Path(sys.executable) if name == "fake-scanner" else None


def parse_items(check_id: str) -> Callable[[bytes], list[Finding]]:
    def parse(raw: bytes) -> list[Finding]:
        return [
            Finding(
                check_id=str(item.get("check", check_id)),
                rule_id=str(item["rule"]),
                title=f"Problem reported by {item['rule']}",
                evidence=(Evidence(str(item["path"]), int(item["line"]), int(item["line"])),),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                impact="Stand-in impact.",
                remediation="Stand-in remediation.",
                verification=VerificationStatus.UNVERIFIED,
            )
            for item in json.loads(raw)
        ]

    return parse


def fake_check(script: Path, *, check_id: str = "fake", **overrides: Any) -> ToolCheck:
    options: dict[str, Any] = {
        "check_id": check_id,
        "tool": "fake-scanner",
        "applies_to": lambda files: True,
        "arguments": lambda snapshot: ["-I", str(script)],
        "parse": parse_items(check_id),
    }
    options.update(overrides)
    return ToolCheck(**options)


def make_symlink(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError) as exc:
        raise unittest.SkipTest(f"cannot create symlinks here: {exc}") from exc


def make_junction(link: Path, target: Path) -> None:
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        check=True,
        capture_output=True,
    )
