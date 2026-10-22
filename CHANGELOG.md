# Changelog

All notable changes to Argus are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may
include breaking changes, noted explicitly).

## [Unreleased]

## [0.9.1] - 2026-10-22

0.9.0 was tagged and its container image published, but the PyPI upload was
rejected (see below), so 0.9.1 is the first PyPI release with the 0.9.0
security hardening. It contains every 0.9.0 change plus these fixes.

### Fixed
- Packages declare core metadata 2.4 instead of 2.5, and releases upload with
  `pypa/gh-action-pypi-publish` v1.14.3. The upload tooling pinned for 0.9.0
  could not read metadata 2.5 and rejected the distributions.
- The curl-pipe-shell rule no longer fires on text that only names the
  pattern (for example "avoid `curl | bash`" in documentation or a rule's own
  explanation); a real download-and-execute always has an argument between
  the command and the pipe.
- The scan cache now includes a fingerprint of the installed Argus code, so
  changing a rule in a source checkout no longer returns stale cached findings.

## [0.9.0] - 2026-10-22

This release is a security hardening release. Argus runs on untrusted code (pull
requests from forks, cloned repositories), and a full review found ways a
hostile repository could execute code, read outside the scan root, hang a
scan, hide its own findings, or make a CI gate pass. All of them are fixed.
Upgrading is recommended for every user.

### Breaking changes
- **Repository config is untrusted by default.** `Config()` now defaults to
  `trust_project_config=False`. A cloned remote's `.argus.yml`,
  `.argus/rules`, `.argus/exceptions.yml` and inline `argus-ignore` comments
  are ignored unless you pass `--trust-remote-config`. Library code that builds
  `Config()` directly must set `trust_project_config=True` to honour them.
- **Scanner crashes fail the gate.** When a `fail_on` threshold is set, a
  scanner error now fails the run (a crashed scanner reports nothing, which a
  gate must not read as a pass). Opt out with `--no-fail-on-error` or
  `fail_on_error: false`. `policy check` always fails on scanner errors.
- **Configuration mistakes exit 2.** Wrong types in `.argus.yml` (for example
  `exclude_paths: "dist/*"`), unknown `--scanners` names, a selection that
  leaves no scanner, an unknown profile, an invalid severity, invalid policies,
  a malformed `exceptions.yml`, and `policy check` with no policies configured
  now exit 2 instead of being coerced or ignored.
- **Dashboard requests are restricted.** Only loopback Host headers are
  accepted (add names with `ARGUS_DASHBOARD_ALLOWED_HOSTS`); `/api/scans`
  requires `Content-Type: application/json`; the upload form requires its CSRF
  token; binding to a non-loopback address requires `ARGUS_DASHBOARD_TOKEN`.
- **`argus push` refuses `http://`** except for loopback hosts.
- **The MCP server only scans inside its working directory** (or
  `ARGUS_MCP_ROOTS`).
- **A DAST URL in the scanned project's own `.argus.yml` is ignored.** Use
  `--live-target` or `ARGUS_DAST_URL`.
- **`argus fix` runs your git commit hooks** and commits with your own git
  identity. It refuses to run when `HEAD` is not the base branch.
- **`watch` state directory names changed**, so the first cycle after
  upgrading records a fresh baseline.

### Security
- Scanning a repository can no longer execute code through its `.git/config`
  (`core.fsmonitor`, `gpg.program`, `diff.external`, textconv); every git call
  runs with hardened config overrides, timeouts and bounded output.
- GitHub Action inputs are passed to the shell through the environment instead
  of being interpolated, closing a command-injection path for workflows that
  forward untrusted event data. On pull requests the Action now reads Argus
  config from the base branch (`pr-config-from-base`).
- Regular expressions that a crafted file could drive into minutes of
  backtracking were rewritten to linear forms, and every line-based search is
  bounded.
- Secret values are masked everywhere they appear in a snippet, including
  second tokens on the same line and CI/CD and container findings.
- Dashboard: DNS-rebinding and cross-site request protection, security headers,
  optional token authentication, request size limits, owner-only database
  permissions, and clamped report timestamps.
- DAST and live posture probes verify the connected peer address, refuse
  redirects into private networks, and cap response size.
- Markdown reports, PR review comments and fix PR bodies escape untrusted text,
  links, HTML and @mentions.
- Every prompt sent to a model fences and caps the scanned snippet;
  AI-proposed patches are never marked verified.
- Remote clones are bounded, skip Git LFS downloads, and never leak temporary
  directories on timeout.

### Added
- `--config-from-ref REF` on `scan`, `review`, `policy check` and
  `baseline create`: read Argus config from a git ref (the base branch) and
  treat the checked-out tree as untrusted.
- `fix --no-verify` to skip commit hooks explicitly.
- `ai.max_findings` (default 25): only the highest-risk findings are sent to a
  model; the rest get offline reasoning.
- `ARGUS_AI_TIMEOUT`, `ARGUS_AI_MAX_RETRIES`, `ARGUS_GIT_TIMEOUT`,
  `ARGUS_MCP_SCAN_TIMEOUT`, `ARGUS_DASHBOARD_MAX_SCANS`,
  `ARGUS_WATCH_KEEP_SNAPSHOTS` and `ARGUS_DAST_URL`.
- New informational findings when part of an analysis could not run:
  `<scanner>.analysis-skipped`, `secrets.history-scan-failed`,
  `secrets.history-scan-incomplete`, `agent.step-failed`, `fim.file-created`,
  `fim.unreadable`, `host.ssh-config-unreadable`, `host.check-failed`.
- Python 3.13 support, CodeQL and dependency review in CI, signed build
  provenance and SBOM attestations for releases and the container image.
- Governance: `GOVERNANCE.md`, `MAINTAINERS.md`, `SUPPORT.md`, a complete
  security policy, the full Contributor Covenant, and DCO sign-off.
- **Versioned plugin API**: `argus.plugin_api` is the public import surface for
  scanners, reporters and AI providers, versioned by `PLUGIN_API_VERSION` (1).
  Plugin base classes carry `api_version`; a plugin built for a different
  version is skipped with a logged warning instead of being loaded. See
  "Stability and versioning" in `docs/plugins.md`.

### Changed
- `ScannerContext` is now a dataclass. Construction and attribute access are
  unchanged.
- The CLI is split into one module per command group under
  `argus.cli.commands`; commands, options, help text and exit codes are
  unchanged. `argus.cli.main:app` remains the entry point.
- All git calls go through one hardened runner, `argus.core.gitexec`. The fix
  and review workflow, the dependency diff and `--config-from-ref` now get the
  same config pins, timeouts and output caps as the git-based scanners. Git
  never prompts for credentials (`GIT_TERMINAL_PROMPT=0`).
- The default Anthropic model is `claude-sonnet-5-5` (override with
  `ARGUS_AI_MODEL`, `ai.model` or `--ai-model`); model calls default to a 60 s
  timeout and 2 retries; the default `max_tokens` is 4096.
- `argus watch` re-reads the target every cycle, keeps running after a failed
  cycle, and prunes old snapshots. The host agent keeps monitoring when a step
  or push fails, and reports the failure.
- The `ci` profile disables the scan cache.
- `--diff` keeps every finding (with a warning) when the diff cannot be
  computed, and works when scanning a subdirectory.
- PR review comments use repository-relative paths and the summary is capped
  at 50 entries.
- The malware scanner reports findings in test files at lower severity
  instead of skipping them, and never skips `conftest.py` or `setup.py`.
- The container image is pinned by digest and installed from the hash-locked
  dependency set.

### Fixed
- `sbom` and `inventory` JSON on stdout is no longer wrapped or stripped.
- `argus watch` saw only the first cycle's files.
- The host agent never detected listening ports on Linux and crashed on
  unreadable `sshd_config`; file integrity monitoring missed new files,
  directory contents and unreadable files.
- Packages beyond a fixed count were silently dropped from OSV lookups.
- Deeply nested files or malformed manifests could zero out a whole scanner or
  crash the scan.
- The auth map ranked risks in the wrong order; PostgreSQL was detected from
  "jpg" and "upgrade"; the reachability risk boost and the AWS credential
  attack chain never fired.
- JUnit and SARIF output stay valid for any path or text; GitLab report ids are
  unique.
- The fix applier keeps original line endings, skips non-UTF-8 files, and
  restores the working tree and branch on failure.
- `argus dependencies`, `argus supply-chain` and `argus sbom` exit 2 with a
  message for an unknown or option-like `--diff` ref instead of a traceback.
- `ScanEngine.scan` no longer modifies the `Project` passed in, so its
  `exclude_paths` no longer carry over to a later scan of the same object.

## [0.8.1] - 2026-09-07

### Added
- **`malware` scanner**: backdoors, webshells, obfuscated exec, reverse shells,
  cryptominers, credential exfiltration, suspicious npm install scripts.
- **`lang-sast`**: Go, C#, Kotlin, Swift, shell, and PowerShell rules.

### Fixed
- **Deep profile**: `ast-python-interproc` renamed to `ast-python-xfile` (cross-file taint).
- **Authz precision**: skip test files and public auth routes; detect router-level
  `Depends()`; reduce false positives on token-in-URL heuristics.

## [0.8.0] - 2026-09-07

Platform expansion: supply chain, policy engine, SBOM, infrastructure scanning,
and the `argus.commands` entry point for add-on CLI commands.

### Added
- **Supply chain**: malicious package intel, typosquat detection, npm behavior
  metadata, `argus supply-chain` command.
- **SBOM**: CycloneDX and SPDX output, SBOM diff via `argus sbom --diff`.
- **Policy engine**: `argus policy check` with YAML policies.
- **Dependency diff**: `argus dependencies --diff` for pull-request review.
- **Infrastructure scanning**: `cicd`, `container`, and `cloud` scanners;
  focused CLI commands `argus cicd`, `argus container`, `argus cloud`.
- **Additional scanners**: authz, API security (OpenAPI), provenance, dependency-diff.
- **Reachability**: npm import reachability and Python symbol-level tier.
- **Docs**: infrastructure scanning guide.
- **Plugin CLI commands**: third-party packages can add `argus` subcommands
  through the `argus.commands` entry point.

### Fixed
- `os.system` with a constant command (`"df -h"`, `"find ."`) no longer reported
  as command injection.
- `--config` pointing at a missing file is now an error (exit 2) instead of
  silently falling back to defaults and disabling `fail_on` gating.
- JavaScript `eval`/`Function` sink no longer matches names that merely end in
  those words (`retrieval`, `myFunction`); `toString()` is no longer treated as
  a sanitizer.
- OSV advisories that carry only a CVSS v3 vector are scored from the vector
  instead of defaulting to Medium.
- Secret verification treats HTTP 403 as unknown rather than invalid, so a live
  but rate-limited or forbidden credential is never downgraded.

## [0.7.0] - 2026-07-14

The largest release so far: AI-era security coverage, deeper code analysis,
signal-quality features, and frictionless distribution. It also folds in the
JavaScript/TypeScript AST scanner and the web dashboard, which were built but
never released.

### Added
- **AST data-flow (taint) scanner for JavaScript/TypeScript** via tree-sitter:
  follows untrusted input through multiple hops into sinks, and treats
  parameterized queries and sanitized values as safe.
- **Web dashboard** (optional extra `[dashboard]`): a FastAPI and SQLModel app
  with scan history and risk trends, started with `argus dashboard`.
- **LLM / AI-application security scanner** (`llm`), mapped to the OWASP Top 10
  for LLM Apps: insecure handling of model output (taint pass into
  `eval`/`exec`/shell/SQL/HTML sinks), prompt injection, secrets in prompts,
  over-privileged agent tools, `trust_remote_code=True`, unsafe `torch.load`
  pickle loading, and HTTP model downloads. Runs only on files that use an
  LLM/agent stack. See `docs/llm-security.md`.
- **Secret verification** (opt-in, `--verify-secrets`): read-only calls confirm
  whether a detected credential is actually **live** (GitHub, Stripe, Slack,
  OpenAI, Google), escalating confirmed ones to Critical and clearing format
  false positives. Local targets only, never in CI templates; the secret is
  never stored in a finding, cache, or report.
- **Live-target posture checks** (`--live-target <url>`, and `argus scan <url>`):
  safe, read-only, non-intrusive runtime checks, security headers, cookie
  flags, HTTP-vs-HTTPS transport, version disclosure, and a short allowlist of
  exposed sensitive paths (`/.env`, `/.git/config`, …). A pre-DAST layer, not a
  crawler or fuzzer.
- **Cross-file / inter-procedural taint** (`ast-python-xfile`, needs the `[ast]`
  extra): follows untrusted input one hop across a function, and file,
  boundary into a sink (e.g. a route in `routes.py` passing request data to a
  helper in `db.py` that builds a query). Deliberately high-precision: depth-1
  and requires a direct source at the call site, so a name collision alone never
  fires.
- **Go SAST rules**: SQL injection via `fmt.Sprintf`, command injection via a
  shell, weak hashes (MD5/SHA-1), and SSRF from a dynamic URL.
- **Community rules in YAML** (`scanner_options.patterns.rules`, and the
  convention dir `.argus/rules/*.yml`): add SAST rules with only regex + a few
  fields, no Python. Invalid rules are skipped, not fatal. Example in
  `examples/custom-rules/`.
- **GitLab SAST reporter** (`-f gitlab`): emits a GitLab Secure SAST report so
  findings show in the merge-request security widget and Vulnerability Report.
- **Expanded auto-fix**: deterministic rewrites for `trust_remote_code=True` and
  `torch.load(...)` (adds `weights_only=True`), and an explicit **AI-proposed fix
  tier**, model-drafted patches are verified when possible and labeled
  `human-review-required`; only deterministic fixes are ever auto-applied.
- Argus now ships its own `.argus.yml` and scans itself clean in CI (dogfooding).

### Fixed
- `exclude_paths` now honors real glob patterns (`examples/**`, `*.min.js`, a
  specific file path) as documented; previously only bare directory names were
  matched, so file and subtree globs were silently ignored.

#### Distribution
- **Official GitHub Action** (`action.yml`): one-block CI setup with SARIF
  upload to GitHub Code Scanning and automatic diff-aware baseline scanning on
  pull requests.
- **pre-commit hooks** (`.pre-commit-hooks.yaml`): `argus-secrets` (fast,
  secrets-only, made for every commit) and `argus` (full static scan).
- **Official Docker image** published to `ghcr.io/argus-codesecurity/argus`
  (linux/amd64 + linux/arm64) on every release.
- **Reachability analysis (experimental, `--reachability`)**: dependency
  findings for Python projects gain an *imported / not imported* verdict, so a
  CVE in a package your code never imports is visibly lower-priority. First
  tier of the reachability roadmap; Python only for now.
- **Per-file scan caching**: file-local scanners cache findings by file
  content hash, so warm scans re-analyze only changed files. On by default;
  `--no-cache` / `cache: false` disables. Determinism is preserved, cached
  and uncached scans produce byte-identical reports (enforced by tests).
- **Concurrent scanners**: independent scanners now run in a thread pool
  (`parallel: false` to disable), with deterministic result ordering.
- **Benchmark harness** (`benchmarks/`): reproducible finding inventories on
  Juice Shop, DVWA, WebGoat, and (locally) NIST SARD, with commits recorded.
- Published scan-time numbers in `docs/performance.md`.
- Bitbucket Pipelines and expanded GitLab CI documentation.

## [0.6.1] - 2026-07-05

### Fixed
- Rich markup no longer eats bracketed text in CLI tables (e.g. `[ast]`).

## [0.6.0] - 2026-07-05

### Added
- **AST data-flow (taint) scanner for Python** via tree-sitter (optional extra
  `[ast]`), closing SQL-injection and path-traversal detection gaps.

### Changed
- OSV client hardened: batches all packages in one request, caches responses on
  disk, retries transient failures.
- Top-level `--version` / `-V` flag.

## [0.5.0] - 2026-07-04

### Added
- Baseline / diff-aware scanning: report only findings not present in a
  previous JSON report, matched by content-based fingerprint.
- Multi-ecosystem SCA via lockfiles: PyPI (`poetry.lock`, `Pipfile.lock`), npm
  (`package-lock.json`, `yarn.lock`), Go (`go.mod`), Rust (`Cargo.lock`), Ruby
  (`Gemfile.lock`), PHP (`composer.lock`), transitive dependencies included.
- Remote-config hardening: `.argus.yml` inside a cloned remote repo is ignored
  unless `--trust-remote-config` is passed.

## [0.2.0] - 2026-07-04

### Added
- Live vulnerability data from [OSV.dev](https://osv.dev) in the dependency
  scanner, with a bundled offline advisory seed as fallback.

## [0.1.1] - 2026-07-04

### Fixed
- False positives found by scanning real-world repositories.

## [0.1.0] - 2026-07-04

Initial release: five-stage pipeline (resolve, analyze, scan, enrich,
report); secrets, dependency, SAST-pattern, and IaC scanners; AI enrichment
with heuristic (offline), Anthropic, OpenAI, and Ollama providers; Attack
Simulation Mode; deterministic verified auto-fix with branch + pull-request
creation (`argus fix`); JSON, SARIF, Markdown, HTML, and CSV reporters; plugin
entry-point system for scanners, reporters, and providers.

[Unreleased]: https://github.com/Argus-CodeSecurity/Argus-appsec/compare/v0.9.1...HEAD
[0.9.1]: https://github.com/Argus-CodeSecurity/Argus-appsec/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/Argus-CodeSecurity/Argus-appsec/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/Argus-CodeSecurity/Argus-appsec/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/Argus-CodeSecurity/Argus-appsec/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/Argus-CodeSecurity/Argus-appsec/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/Argus-CodeSecurity/Argus-appsec/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/Argus-CodeSecurity/Argus-appsec/compare/v0.5.1...v0.6.0
[0.2.0]: https://github.com/Argus-CodeSecurity/Argus-appsec/releases/tag/v0.2.0
[0.1.0]: https://github.com/Argus-CodeSecurity/Argus-appsec/releases/tag/v0.1.0
