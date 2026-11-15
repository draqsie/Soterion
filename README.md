# Soterion

Soterion helps you review repositories **you own or are explicitly authorized
to review**: it looks for security issues in source code, dependencies and
security-relevant configuration, explains findings with file-and-line evidence,
and (later) prepares low-risk fixes on a separate branch for human review.

It does not scan live systems, does not run the code it analyzes, and does not
claim to find every vulnerability. A report always states which checks ran and
which did not.

## Status: Phase 1b (in progress)

One check ships: hardcoded-secret detection. Source-code analysis and
dependency checks are not implemented yet, so a clean result currently means
only "no secret pattern matched".

| Piece | State |
|---|---|
| Scope manifest and validation | implemented |
| Finding / check-result data model | implemented |
| Private snapshot of in-scope files | implemented |
| Hardened runner for external scanners | implemented |
| Check orchestration and `scan` command | implemented |
| Secret detection (gitleaks) | implemented |
| Dependency vulnerabilities (OSV-Scanner) | not implemented |
| Source-code analysis (Semgrep) | not implemented |
| Reports, standards mapping, fixes | not implemented |

## Checks

| Check | Tool | Developed against | Network | What a finding means |
|---|---|---|---|---|
| `gitleaks` | [gitleaks](https://github.com/gitleaks/gitleaks) | 8.30.1 | none | A string matches a known credential pattern. Soterion does not test whether the credential is live, so every finding is `unverified`. |

Soterion does not bundle or download scanners. Install the tool yourself,
verify its published checksum, and either put it on `PATH` or pass its
directory with `--tools-dir`. A check whose tool is missing is reported as
`skipped` and the scan as incomplete.

Suppressions inside the analyzed repository are not honored. For gitleaks that
means `.gitleaksignore`, `.gitleaks.toml` and `gitleaks:allow` comments have no
effect: repository content is untrusted and must not be able to hide findings.
Secret values are redacted by the tool and are never copied into a finding;
only the rule, file and line are kept.

## How a scan runs

1. The scope manifest is validated and the in-scope files are listed by name
   and metadata only.
2. Those files are copied into a private temporary directory. Each file is
   re-checked while it is copied; links and files that changed are skipped.
3. Each scanner runs against that copy, never in the repository. It is started
   without a shell, from an absolute path outside the repository, with a
   minimal environment (no tokens or keys from your shell), closed standard
   input, a time limit and an output limit.
4. Scanner output is treated as untrusted. A finding is kept only if it points
   at an existing line of a file that is in the copy.
5. The copy is deleted.

Every check ends in exactly one state: `completed`, `failed`, `skipped` (tool
not installed) or `not_applicable`. The overall result is `incomplete` if any
check failed or was skipped, if no check completed, or if any in-scope path
could not be examined.

| Exit code | Meaning |
|---|---|
| 0 | every check completed, no findings (not proof of absence) |
| 1 | findings reported; each may be a false positive |
| 2 | scope rejected, nothing was read |
| 3 | scan incomplete; do not treat as clean |

## Scope manifest

Nothing is analyzed without a manifest that names the repository, the file
patterns that may be read, and the allowed actions. See
[examples/scope.example.toml](examples/scope.example.toml).

Rules enforced in code:

- The manifest must be stored **outside** the target repository. Repository
  content is untrusted input and cannot define its own scope or permissions.
- The repository must be an absolute path on a local disk. URLs and network
  shares are rejected.
- Unknown keys are errors, so a typo cannot silently widen the scope.
- Symbolic links and junctions are never followed, and `.git` is never read.
- Links, oversized files and unreadable paths are reported as skipped.
- The authorization section is your own declaration. Soterion cannot verify it.

## Usage

Requires Python 3.13 or newer. There are no runtime dependencies.

```bash
python -m pip install -e .
```

```bash
soterion scope-check /path/outside/the/repo/my.scope.toml
```

```bash
soterion scan /path/outside/the/repo/my.scope.toml --tools-dir /absolute/path/to/scanners
```

`scope-check` exits `0` when the scope is valid and `2` when it is rejected.

`--tools-dir` may be repeated. When it is given, `PATH` is not searched. Tools
are never looked up in the current directory or inside the analyzed
repository, and on Windows only `.exe` files are accepted.

## Known limitations

- Hard links are not detected.
- On Windows, a scanner's child processes are stopped on timeout but are not
  confined to a job object.
- Scanner standard error is discarded, so a failed check reports only its exit
  code.
- A local user who can modify the repository while a scan is running is outside
  the threat model.

## Tests

```bash
PYTHONPATH=src python -m unittest discover -s tests -t .
```

Tests that run a real scanner are skipped unless `SOTERION_TEST_TOOLS_DIR`
names the directory that contains it:

```bash
SOTERION_TEST_TOOLS_DIR=/absolute/path/to/scanners PYTHONPATH=src python -m unittest discover -s tests -t .
```

Test fixtures build token-shaped strings at run time; no secret-like literal is
stored in this repository.

## License

Not chosen yet.
