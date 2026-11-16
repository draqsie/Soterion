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
known vulnerabilities in dependencies. Results can be written as a JSON report.
Markdown and SARIF reports, standards mapping and fix proposals are not
implemented yet; see [ROADMAP.md](ROADMAP.md).

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
| Masking of secrets in scanner text | implemented |
| JSON report | implemented |
| Markdown and SARIF reports, standards mapping, fixes | not implemented |

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
| 2 | scope or output directory rejected, nothing was analyzed |
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

## Reports

```bash
soterion scan /path/outside/the/repo/my.scope.toml --output-dir /absolute/path/for/reports
```

With `--output-dir`, the scan also writes `soterion-report.json` there. Without
it, no file is written. The directory must be an absolute path outside the
analyzed repository; a path that leads into the repository through a link is
refused too, and it is refused before any check runs.

The report (`schema_version` 1) contains:

- `result`: `no_findings`, `findings` or `incomplete`, a `complete` flag, and a
  sentence that says what the result does and does not mean;
- `scope`: the patterns, limits and permissions that applied. The repository is
  identified by its directory name only, not its full path, and the
  authorization is recorded as self-declared and not verified;
- `checks`: every check with its state, tool version, rule set and network use;
- `skipped_paths`: in-scope paths that no check examined;
- `findings`: ordered by severity, each with its evidence, ratings and
  verification status, and `same_location_as`, which links findings from
  different checks on the same lines instead of merging them;
- `masking`: how many values were masked and whether located secrets were
  available for masking.

## Masking

Text that comes from a scanner or the repository can quote source code, and
with it a secret. Before a scan returns anything, that text passes through one
masking step, so the terminal output and the report are built from masked text
only.

- **Exact values.** gitleaks reports where each secret is. The bytes at those
  locations are read from the private copy, kept in memory for the duration of
  the scan, and replaced by `[REDACTED]` wherever they appear, including in the
  findings and error details of other checks.
- **Well-known shapes.** Private key blocks, a few provider token formats and
  e-mail addresses are masked wherever they appear, located or not.

Limits you should know:

- A secret that no check located and that matches none of the shapes is not
  masked.
- If gitleaks is missing, fails or times out, there are no located values. The
  scan output then carries a warning and the report sets
  `masking.secrets_located` to `false`. Treat such output as possibly
  containing secrets.
- File paths are not masked.
- The name of a setting next to a secret (`client_secret = "..."`) is kept; a
  word of 16 or more characters on the same line as a located secret is masked
  as a precaution.

## Known limitations

- Hard links are not detected.
- On Windows, a scanner's child processes are stopped on timeout but are not
  confined to a job object.
- Scanner standard error is discarded, so a failed check reports only its exit
  code.
- Masking has the limits described under "Masking"; it is not a guarantee
  that no secret appears in output.
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

Tests that use the network depend on semgrep.dev and api.osv.dev being
reachable. When one is not, the affected check is reported as failed and its
tests fail; run them again before concluding that something is broken. A
computer that goes to sleep during a run makes scanners time out the same way.

## License

Not chosen yet.
