# Soterion

Soterion helps you review repositories **you own or are explicitly authorized
to review**: it looks for security issues in source code, dependencies and
security-relevant configuration, explains findings with file-and-line evidence,
and (later) prepares low-risk fixes on a separate branch for human review.

It does not scan live systems, does not run the code it analyzes, and does not
claim to find every vulnerability. A report always states which checks ran and
which did not.

## Status

Three checks ship: hardcoded-secret detection, source-code pattern analysis and
known vulnerabilities in dependencies. Reports, standards mapping and fix
proposals are not implemented yet; see [ROADMAP.md](ROADMAP.md).

| Piece | State |
|---|---|
| Scope manifest and validation | implemented |
| Finding / check-result data model | implemented |
| Private snapshot of in-scope files | implemented |
| Hardened runner for external scanners | implemented |
| Check orchestration and `scan` command | implemented |
| Secret detection (gitleaks) | implemented |
| Dependency vulnerabilities (OSV-Scanner) | implemented |
| Source-code analysis (Semgrep) | implemented |
| Configuration review (Dockerfile, GitHub Actions) | implemented, through the same Semgrep rule set |
| Reports, standards mapping, fixes | not implemented |

## Checks

| Check | Tool | Developed against | Network | What a finding means |
|---|---|---|---|---|
| `gitleaks` | [gitleaks](https://github.com/gitleaks/gitleaks) | 8.30.1 | none | A string matches a known credential pattern. Soterion does not test whether the credential is live, so every finding is `unverified`. |
| `semgrep` | [Semgrep](https://github.com/semgrep/semgrep) (OSS engine) | 1.185.0 | downloads the `p/default` rule set from semgrep.dev | Code matches a rule pattern. It is a lead to review, not a confirmed vulnerability; every finding is `unverified`. |
| `osv-scanner` | [OSV-Scanner](https://github.com/google/osv-scanner) | 2.7.1 | queries api.osv.dev with the names and versions of the dependencies it finds | The declared version of a dependency falls in a published advisory's affected range. Whether the vulnerable code is reachable is not analyzed; every finding is `unverified`. |

### Configuration review

Dockerfiles and GitHub Actions workflows are reviewed by the `semgrep` check;
there is no separate check for them. The `p/default` rule set already contains
Semgrep's Dockerfile and GitHub Actions rules: in our fixtures, adding the
dedicated `p/dockerfile` and `p/github-actions` rule sets produced exactly the
same findings, so they are not requested separately.

What that covered in the fixtures (Semgrep 1.185.0):

| Fixture content | Reported |
|---|---|
| Dockerfile with no `USER` instruction | yes |
| Workflow step that puts pull-request text into a shell command | yes |
| `pull_request_target` workflow that checks out the pull request's code | yes |
| Third-party action pinned to a branch or tag instead of a commit | yes |
| `FROM image:latest` | no |
| `ADD` from a remote URL | no |
| Unpinned `apt-get install` | no |
| Explicit `USER root` | no |

This is a narrow set of checks, not a Dockerfile or workflow linter, and the
table describes those fixtures only.

### Network use

A check that contacts the network does not run unless the scope manifest names
it:

```toml
[network]
allowed_checks = ["semgrep", "osv-scanner"]
```

Without that, the check is reported as `skipped` and the scan as incomplete.
`scan` prints which checks used the network and what for. This is enforced by
which checks are started and with which options, not by a network sandbox.

For Semgrep, usage metrics and the version check are disabled, and it runs with
an empty throwaway home directory, so it does not use a Semgrep login stored on
your machine. Its rules are downloaded by your own Semgrep installation under
the license the registry states for them (at the time of writing, "Semgrep
Rules License v1.0"); Soterion does not bundle or redistribute rules. Check
that license for your use. Because the rule set is fetched at scan time, two
scans on different days can produce different findings.

For OSV-Scanner, transitive dependency resolution is switched off because it
would contact a second service. Only what a manifest or lockfile states is
checked: a `requirements.txt` that pins direct dependencies says nothing about
their own dependencies, so prefer a full lockfile. The supported manifest
formats are OSV-Scanner's; when it finds none, the check is `not_applicable`.
The advisory database changes over time, so results can differ between scans.

Soterion does not bundle or download scanners. Install the tool yourself,
verify its published checksum, and either put it on `PATH` or pass its
directory with `--tools-dir`. A check whose tool is missing is reported as
`skipped` and the scan as incomplete.

### Suppressions and coverage

Suppressions inside the analyzed repository are not honored, because repository
content is untrusted and must not be able to hide findings. That covers
`.gitleaksignore`, `.gitleaks.toml` and `gitleaks:allow` comments for gitleaks,
`.semgrepignore` files and `nosemgrep` comments for Semgrep, and
`osv-scanner.toml` files for OSV-Scanner.

Secret values are redacted by gitleaks and are never copied into a finding;
only the rule, file and line are kept.

Semgrep reports a file it cannot fully parse only as a warning. Soterion turns
any such error into a `failed` check and also compares the files Semgrep says
it scanned with the files in scope. Exclude a file that cannot be parsed in the
scope manifest if you accept that it is not analyzed.

One kind of Semgrep warning is treated differently. Some rules parse a fragment
of a file as another language, for example the shell text of a workflow step.
A fragment such as `${{ github.event.pull_request.title }}` is not valid shell,
so those rules cannot be evaluated on that line, while the file itself parses
and the other rules run. This happens on ordinary workflows, so it does not
fail the check. It is shown as a limitation next to `completed`, with the
number of skipped rule evaluations and the files, and the result line says
that limitations exist. The warning is recognized by its exact wording; any
other warning or error still fails the check.

OSV-Scanner names the manifest and the package but no line. Soterion looks the
package up in the manifest: the first line that mentions both its name and
version, else the first that mentions its name, else line 1.

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
- A Semgrep finding's description comes from the rule's message, which can
  quote the matched code. Reports with redaction are not implemented yet.
- Proxy settings are not passed to scanners, so a check that needs the network
  fails behind a proxy that requires them.
- A local user who can modify the repository while a scan is running is outside
  the threat model.

## Tests

```bash
PYTHONPATH=src python -m unittest discover -s tests -t .
```

Tests that run a real scanner are skipped unless `SOTERION_TEST_TOOLS_DIR`
names the directories that contain them (separated like `PATH`). Tests that
also need the network additionally require `SOTERION_TEST_NETWORK=1`:

```bash
SOTERION_TEST_TOOLS_DIR=/absolute/path/to/scanners SOTERION_TEST_NETWORK=1 PYTHONPATH=src python -m unittest discover -s tests -t .
```

Test fixtures build token-shaped strings at run time; no secret-like literal is
stored in this repository.

## License

Not chosen yet.
