# Roadmap

Where Soterion is, what is left before a first release, and how each step is
judged complete. Steps are done in order; each one ends with its tests passing
and its limits written down in the README.

Scope of the first release is unchanged: source code, dependencies and
security-relevant configuration of a repository the operator owns or is
authorized to review. No dynamic testing, no scanning of live targets, no
automatic merge or deploy.

## Rules that every step keeps

1. Nothing is read or done outside the scope manifest.
2. Repository content and scanner output are untrusted input; decisions are
   made by code, not by a model.
3. Analysis is read-only. Fixes go to a separate branch and are never merged
   automatically.
4. Secrets and personal data are not written to logs or reports.
5. A check that did not run, or did not cover the scope, is never reported as
   clean.
6. Every finding states its evidence, severity, confidence and verification
   status, and is presented as a lead that may be a false positive.
7. Each security rule has a test that fails when the rule is removed. The
   known exceptions are options that only change which hosts a scanner
   contacts (`--metrics=off`, `--no-resolve`); they are documented but cannot
   be observed without capturing network traffic.

## Done

| Step | Result |
|---|---|
| 0. Foundations | Scope manifest, file selection without following links, finding and check-result model, `scope-check` |
| 1a. Scan pipeline | Private snapshot, hardened tool runner, check orchestration, `scan` with distinct exit codes |
| 1b. Secret detection | gitleaks adapter; repository suppressions not honored; secret values never stored |
| 1c. Source-code analysis | Semgrep adapter; per-check network permission; parse errors and uncovered files make the check incomplete |
| 1d. Dependency vulnerabilities | OSV-Scanner adapter; manifest line as evidence; repository `osv-scanner.toml` cannot hide a vulnerability; "not applicable" when no manifest is in scope |
| 1e. Configuration review | Dockerfile and GitHub Actions findings through Semgrep's `p/default` rules; measured coverage documented; a rule skipped on an embedded snippet is a visible limitation instead of a failed check |
| 2a. Masking and JSON report | One masking step for all scanner and repository text, using the secret locations gitleaks reports plus well-known shapes; versioned JSON report with scope, checks, tool versions and linked same-location findings; `--output-dir` refused when it is or leads into the repository |

## To do

### 2b. Markdown report

The same content as the JSON report, for people.

Complete when:
- an incomplete scan is unmistakable at the top of the document;
- text from scanners cannot change the document's structure (no injected
  headings, links, HTML or tables);
- it is built from the same masked data as the JSON report.

### 2c. SARIF report

SARIF 2.1.0, for tools that display code-scanning results.

Complete when:
- the file validates against the published 2.1.0 schema;
- checks that failed or were skipped are reported as tool execution
  notifications, so an incomplete scan does not look like a clean one;
- severity, confidence and verification status survive the conversion.

### 3. Standards mapping

Relate findings to OWASP ASVS 5, OWASP WSTG and NIST SSDF without inventing
requirements.

- Mapping data comes from the official publications, is stored as a versioned
  data file with its source and retrieval date, and is not written from memory.
- Findings are linked through the CWE identifiers their rules declare; a
  finding with no defensible mapping says "no mapping".
- The report explains what each standard is used for here. WSTG is largely a
  dynamic-testing guide, so only its source- and configuration-review parts
  apply to this release.
- A process section states which SSDF practices running Soterion supports and
  which it does not address.

Complete when:
- every identifier shown in a report exists in the vendored source data, and a
  test fails if one does not;
- unmapped findings are visible as such;
- the report shows the standard versions used.

### 4. Fix proposals (deterministic)

Low-risk fixes prepared for human review. Starts with dependency version bumps
to the fixed version an advisory names.

- Requires the `propose-fix` action in the scope manifest.
- Work happens in a separate git worktree on a `soterion/fix-*` branch. The
  checked-out branch and the default branch are never written.
- A policy gate implemented in code: only in-scope files, a diff size limit, no
  changes to CI workflows, hooks or dependency sources.
- After a fix, the originating check is re-run on the changed tree, plus the
  project's own tests when the operator configures a command for them.
- Output is a local branch and a pull-request description file. Nothing is
  pushed.

Complete when:
- the default branch is byte-identical before and after;
- a fix whose finding is still reported afterwards is labelled "not verified"
  and is not presented as successful;
- a fix that touches a path outside the policy is refused, with a test;
- absence of project tests is reported as "partially verified", not as passed.

### 5. Model-assisted explanations and patches (optional)

Off by default. A model may explain a finding and propose a patch; it decides
nothing.

- The model has no tools. Its only output is a structured object validated
  against a schema.
- Repository content is passed as data and marked as untrusted. Redaction runs
  before any content is sent, and sending content requires network permission
  for this feature in the scope manifest.
- A proposed patch goes through the same policy gate and re-verification as a
  deterministic fix.

Complete when:
- a fixture repository containing prompt-injection text cannot widen the
  scope, change permissions, or get a patch past the policy gate;
- output that does not match the schema is rejected;
- the report distinguishes model-written text from scanner output.

### 6. GitHub pull requests

Only on explicit request, and only after steps 4 and 5 are stable.

- Creates a pull request from a `soterion/fix-*` branch, as a draft, with the
  verification status at the top.
- Uses the narrowest token scope that works. The token is never logged and
  never passed to a scanner.
- Never enables auto-merge and never pushes to the default branch.

Complete when:
- an unverified fix cannot be opened as anything other than a draft marked
  "not verified";
- tests cover the refusal to push to the default branch.

### 7. Release readiness

- Choose a license (decision for the maintainer).
- Continuous integration on Linux and Windows for every supported Python
  version, including the symbolic-link tests that cannot run on an
  unprivileged Windows account.
- Documented, pinned scanner versions with checksums, and a compatibility test
  per scanner version.
- `SECURITY.md` with a reporting channel, the threat model as a document, and
  contributor guidance.
- Hardening carried over from earlier steps: confine scanner processes with a
  job object on Windows, detect hard links, pass proxy settings to checks that
  are allowed to use the network.
- Run Soterion on itself in CI and keep the result clean.

Complete when:
- a new user can install, write a manifest and get a report by following the
  README alone;
- every limitation listed in the README is still accurate;
- the first tagged release is built from a commit whose CI is green.

## Open decisions

| Decision | Current behavior |
|---|---|
| License | Not chosen |
| Checks the operator deliberately leaves off | Reported as skipped, so the scan is incomplete. An explicit "disabled by operator" state would let such a scan end cleanly while still listing what did not run. |
| Semgrep rule set | `p/default`, fetched at scan time, so results can change between scans. Pinning or vendoring rules depends on their license. |
| Evidence snippets | Not stored. The masking step now exists, but a snippet is the most likely place for an unlocated secret, so adding them needs its own decision. |
| Scanner text when no secret was located | Shown, with a warning in the output and `masking.secrets_located: false` in the report. The stricter alternative is to withhold scanner messages entirely unless the secret check completed. |
| Dockerfile coverage | Limited to what Semgrep's default rules flag (see the README table). A dedicated Dockerfile linter would be a new check and a new tool to install. |
| Rule evaluations skipped on embedded snippets | Reported as a limitation of a completed check, so an ordinary workflow does not make every scan incomplete. The stricter alternative is to fail the check. |
| Transitive dependencies | Not resolved, because resolution contacts a second service. Could become a separate, separately permitted check. |
