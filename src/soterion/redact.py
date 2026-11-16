"""Mask secrets and personal data in text before it leaves the scan.

Text that originates from a scanner or from the analyzed repository can quote
source code: a rule message may repeat the string it matched, an error may show
the line it could not parse. Everything of that kind passes through one
``Redactor`` before a scan result is returned, so nothing downstream (terminal
output, reports) ever holds the unmasked text.

Two things are masked:

* Exact values. A secret scanner reports where each secret is; the bytes at
  those locations are read from the private snapshot, kept in memory only for
  the duration of the scan, and masked wherever they appear in any text.
* A short list of well-known shapes (private key blocks, a few provider token
  formats, e-mail addresses), as a second net for values no scanner located.

This is not a guarantee that no secret can appear. A value that no scanner
located and that matches none of the shapes is not masked.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from soterion.findings import CheckResult, Finding

MASK = "[REDACTED]"

_MIN_VALUE_LENGTH = 6
_LONG_WORD_LENGTH = 16
_EDGE_CHARACTERS = " \t\r\n\"'`,;"
_WORD_SEPARATORS = re.compile(r"[\s\"'`=:,;]+")
_SHAPES = (
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
        re.DOTALL,
    ),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"),
)


@dataclass(frozen=True)
class SensitiveSpan:
    """Where a secret is: a file in the snapshot, a 1-based line, byte offsets in that line."""

    path: str
    line: int
    start: int = 0
    end: int | None = None


def collect_sensitive_values(root: Path, spans: Iterable[SensitiveSpan]) -> frozenset[str]:
    """Read the text each span points at. Spans that point nowhere are ignored."""
    lines_by_path: dict[str, list[bytes]] = {}
    values: set[str] = set()
    resolved_root = root.resolve()
    for span in spans:
        if span.path not in lines_by_path:
            lines_by_path[span.path] = _read_lines(resolved_root, span.path)
        lines = lines_by_path[span.path]
        if not 1 <= span.line <= len(lines) or span.start < 0:
            continue
        raw = lines[span.line - 1][span.start : span.end]
        values.update(_candidate_values(raw.decode("utf-8", errors="ignore")))
    return frozenset(values)


def _candidate_values(text: str) -> set[str]:
    """Secret values a located piece of text may contain.

    A scanner may point at the value itself or at a whole ``name = "value"``
    match. The whole text is kept, and so is its last word, where the value
    sits in such a match. Other words are kept only when they are long, so that
    the name of a setting is not masked everywhere it is mentioned.
    """
    whole = text.strip(_EDGE_CHARACTERS)
    words = [word for word in _WORD_SEPARATORS.split(whole) if word]
    candidates = {whole}
    if words:
        candidates.add(words[-1])
    candidates.update(word for word in words if len(word) >= _LONG_WORD_LENGTH)
    return {candidate for candidate in candidates if len(candidate) >= _MIN_VALUE_LENGTH}


def _read_lines(root: Path, relative: str) -> list[bytes]:
    try:
        path = (root / relative).resolve()
        if not path.is_relative_to(root):
            return []
        return [line.rstrip(b"\r") for line in path.read_bytes().split(b"\n")]
    except OSError:
        return []


class Redactor:
    """Masks known values and well-known secret shapes; counts what it masked."""

    def __init__(self, values: Iterable[str]) -> None:
        usable = {value for value in values if len(value) >= _MIN_VALUE_LENGTH}
        self._values = sorted(usable, key=len, reverse=True)
        self.count = 0

    def text(self, text: str) -> str:
        for value in self._values:
            occurrences = text.count(value)
            if occurrences:
                text = text.replace(value, MASK)
                self.count += occurrences
        for shape in _SHAPES:
            text, replaced = shape.subn(MASK, text)
            self.count += replaced
        return text

    def finding(self, finding: Finding) -> Finding:
        return dataclasses.replace(
            finding,
            title=self.text(finding.title),
            impact=self.text(finding.impact),
            remediation=self.text(finding.remediation),
        )

    def check(self, check: CheckResult) -> CheckResult:
        return dataclasses.replace(check, detail=self.text(check.detail))
