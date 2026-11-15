"""Source-code analysis with Semgrep (developed against semgrep 1.185.0, OSS engine).

What was measured against the real binary, and how this adapter responds:

* Rules come from the Semgrep registry, so the tool needs the network. The
  check therefore only runs when the scope manifest allows it. Usage metrics
  and the version check are switched off. The rules are downloaded by the
  user's own Semgrep under the license the registry states for them; Soterion
  does not bundle or redistribute any rule.
* Semgrep needs a home directory and keeps settings (including a login token)
  there. It is given an empty, throwaway home inside the snapshot's scratch
  directory, so it neither reads the user's Semgrep login nor writes outside
  the temporary workspace.
* ``.semgrepignore`` files anywhere in the scanned tree and ``nosemgrep``
  comments let the analyzed content hide findings. Both are disabled
  (``--x-ignore-semgrepignore-files``, ``--disable-nosem``).
* A file Semgrep cannot fully parse is reported only as a warning and the exit
  code stays 0. Any reported error makes this check incomplete, and the list of
  files Semgrep says it scanned is compared with the snapshot, so a file that
  was silently left out also makes it incomplete.
* One kind of warning is different: a rule that parses a fragment of a file as
  another language (the shell text of a workflow step, say) cannot read a
  fragment such as ``${{ ... }}``. The file parsed and the other rules ran, and
  this happens on ordinary, valid workflows. It is reported as a limitation of
  a completed check, with the number of skipped rule evaluations and the files.
* Rule messages can quote matched source text. They are kept as the finding's
  impact; the tool's error messages, which quote source lines, are not.

Semgrep matches patterns; a finding is a lead to review, not a confirmed
vulnerability, and no finding is marked as verified.
"""

from __future__ import annotations

import json
import re

from soterion.findings import Confidence, Evidence, Finding, Severity, VerificationStatus
from soterion.scan import ParsedOutput, ToolCheck
from soterion.staging import FILES_DIRNAME, Snapshot, snapshot_relative

CHECK_ID = "semgrep"
RULESET = "p/default"

_SEVERITIES = {
    "CRITICAL": Severity.CRITICAL,
    "ERROR": Severity.HIGH,
    "HIGH": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "LOW": Severity.LOW,
    "EXPERIMENT": Severity.INFO,
    "INVENTORY": Severity.INFO,
}
_CONFIDENCES = {"HIGH": Confidence.HIGH, "MEDIUM": Confidence.MEDIUM, "LOW": Confidence.LOW}
_ERROR_KIND = re.compile(r"[A-Za-z][A-Za-z0-9_ ]{0,39}")
_SNIPPET_WARNING = re.compile(
    r"When parsing a snippet as [A-Za-z0-9+#]{1,20} for metavariable-pattern "
    r"in rule '([A-Za-z0-9_.-]{1,200})'"
)
_DEFAULT_IMPACT = "The code matches a pattern that is frequently associated with a security weakness."
_REMEDIATION = "Review the flagged code, then fix it or record why it is safe in this context."


def parse_report(raw: bytes) -> ParsedOutput:
    """Convert Semgrep's JSON output. Raises ValueError if it is not what Semgrep prints."""
    try:
        document = json.loads(raw)
    except ValueError:
        raise ValueError("semgrep output is not valid JSON") from None
    try:
        results, errors = document["results"], document["errors"]
        scanned = document["paths"]["scanned"]
    except (KeyError, TypeError):
        raise ValueError("semgrep output lacks results, errors or scanned paths") from None
    if not all(isinstance(part, list) for part in (results, errors, scanned)):
        raise ValueError("semgrep output has an unexpected shape")
    if not all(isinstance(path, str) for path in scanned):
        raise ValueError("semgrep output lists a non-text scanned path")

    skipped_rules, other_errors = _split_errors(errors)
    return ParsedOutput(
        findings=[_to_finding(result) for result in results],
        problem=_describe_errors(other_errors),
        examined_files=frozenset(snapshot_relative(path) for path in scanned),
        limitation=_describe_skipped_rules(skipped_rules),
    )


def _to_finding(result: object) -> Finding:
    try:
        rule = result["check_id"]  # type: ignore[index]
        reported_path = result["path"]  # type: ignore[index]
        start_line = result["start"]["line"]  # type: ignore[index]
        end_line = result["end"]["line"]  # type: ignore[index]
        extra = result["extra"]  # type: ignore[index]
        reported_severity = extra["severity"]
    except (KeyError, TypeError):
        raise ValueError("semgrep result lacks a required field") from None
    if not isinstance(rule, str) or not isinstance(reported_path, str):
        raise ValueError("semgrep result has a non-text rule or path")
    severity = _SEVERITIES.get(str(reported_severity).upper())
    if severity is None:
        raise ValueError("semgrep result has an unknown severity")

    metadata = extra.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    message = extra.get("message")
    impact = message.strip() if isinstance(message, str) else ""
    return Finding(
        check_id=CHECK_ID,
        rule_id=rule,
        title=rule.rsplit(".", 1)[-1],
        evidence=(Evidence(snapshot_relative(reported_path), start_line, end_line),),
        severity=severity,
        confidence=_CONFIDENCES.get(str(metadata.get("confidence")).upper(), Confidence.LOW),
        impact=impact or _DEFAULT_IMPACT,
        remediation=_remediation(metadata.get("shortlink")),
        verification=VerificationStatus.UNVERIFIED,
    )


def _remediation(link: object) -> str:
    usable = (
        isinstance(link, str)
        and link.startswith("https://")
        and len(link) <= 200
        and link.isprintable()
        and " " not in link
    )
    return f"{_REMEDIATION} Rule guidance: {link}" if usable else _REMEDIATION


def _split_errors(errors: list[object]) -> tuple[set[tuple[str, str, object]], list[object]]:
    """Separate "a rule could not read an embedded snippet" from every other error.

    Some rules parse a fragment of a file as another language, for example the
    shell text of a workflow step. When that fragment is not valid in that
    language (``${{ ... }}`` is not shell), Semgrep warns that this one rule
    could not be evaluated there; the file itself parsed and other rules ran.
    Such a warning is recognized only by its exact wording, at warning level,
    for a file inside the snapshot. Anything else stays an error, so a change
    in Semgrep's wording makes the check stricter, not more lenient.
    """
    skipped: set[tuple[str, str, object]] = set()
    others: list[object] = []
    for error in errors:
        snippet = None
        if isinstance(error, dict) and error.get("level") == "warn":
            kind = error.get("type")
            message, path = error.get("message"), error.get("path")
            if (
                isinstance(kind, list)
                and kind[:1] == ["PartialParsing"]
                and isinstance(message, str)
                and isinstance(path, str)
            ):
                snippet = _SNIPPET_WARNING.search(message)
        if snippet is None:
            others.append(error)
            continue
        try:
            relative = snapshot_relative(path)
        except ValueError:
            others.append(error)
            continue
        skipped.add((relative, snippet.group(1), _first_line(error.get("spans"))))
    return skipped, others


def _first_line(spans: object) -> object:
    try:
        return spans[0]["start"]["line"]  # type: ignore[index]
    except (IndexError, KeyError, TypeError):
        return None


def _describe_skipped_rules(skipped: set[tuple[str, str, object]]) -> str:
    """Count skipped rule evaluations and name the files; never quote the snippet."""
    if not skipped:
        return ""
    paths = sorted({path for path, _, _ in skipped})
    shown = ", ".join(paths[:3]) + (f" and {len(paths) - 3} more" if len(paths) > 3 else "")
    return (
        f"{len(skipped)} rule evaluation(s) were skipped because an embedded snippet could "
        f"not be parsed as the language the rule expects, in: {shown}"
    )


def _describe_errors(errors: list[object]) -> str:
    """Summarize tool errors by kind and count only; their messages quote source lines."""
    if not errors:
        return ""
    kinds: set[str] = set()
    paths: set[str] = set()
    for error in errors:
        kind: object = None
        if isinstance(error, dict):
            kind = error.get("type")
            if isinstance(kind, list) and kind:
                kind = kind[0]
            if isinstance(error.get("path"), str):
                paths.add(error["path"])
        kinds.add(kind if isinstance(kind, str) and _ERROR_KIND.fullmatch(kind) else "unknown")
    return (
        f"semgrep reported {len(errors)} error(s) of kind {', '.join(sorted(kinds))}, "
        f"affecting {len(paths)} file(s) that were not fully analyzed"
    )


def _arguments(snapshot: Snapshot) -> list[str]:
    return [
        "scan",
        "--config",
        RULESET,
        "--json",
        "--quiet",
        "--metrics=off",
        "--disable-version-check",
        "--disable-nosem",
        "--no-git-ignore",
        "--x-ignore-semgrepignore-files",
        "--no-exclude-binary-files",
        "--max-target-bytes",
        "0",
        FILES_DIRNAME,
    ]


def _environment(snapshot: Snapshot) -> dict[str, str]:
    home = snapshot.scratch / "semgrep-home"
    home.mkdir(exist_ok=True)
    return {"USERPROFILE": str(home), "HOME": str(home), "SEMGREP_SEND_METRICS": "off"}


SEMGREP = ToolCheck(
    check_id=CHECK_ID,
    tool="semgrep",
    applies_to=lambda files: bool(files),
    arguments=_arguments,
    parse=parse_report,
    timeout_seconds=900,
    environment=_environment,
    network_use=f"downloads the {RULESET} rule set from semgrep.dev; usage metrics are disabled",
    run_in_container=True,
)
