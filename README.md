# Soterion

Soterion helps you review repositories **you own or are explicitly authorized
to review**: it looks for security issues in source code, dependencies and
security-relevant configuration, explains findings with file-and-line evidence,
and (later) prepares low-risk fixes on a separate branch for human review.

It does not scan live systems, does not run the code it analyzes, and does not
claim to find every vulnerability. A report always states which checks ran and
which did not.

## Status: Phase 1a

The scanning pipeline exists, but **no scanner adapter ships yet**. `scan`
therefore always ends with "scan incomplete" for now. That is deliberate: an
empty run must not look like a clean result.

| Piece | State |
|---|---|
| Scope manifest and validation | implemented |
| Finding / check-result data model | implemented |
| Private snapshot of in-scope files | implemented |
| Hardened runner for external scanners | implemented |
| Check orchestration and `scan` command | implemented |
| Scanner adapters (SAST, dependencies, secrets) | not implemented |
| Reports, standards mapping, fixes | not implemented |

## How a scan runs

1. The scope manifest is validated and the in-scope files are listed by name
   and metadata only.
2. Those files are copied into a private temporary directory. Each file is
   re-checked while it is copied; links and files that changed are skipped.
3. Each scanner runs inside that copy, never in the repository. It is started
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
soterion scan /path/outside/the/repo/my.scope.toml
```

`scope-check` exits `0` when the scope is valid and `2` when it is rejected.

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

## License

Not chosen yet.
