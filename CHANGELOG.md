# Changelog

All notable changes to Argus are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may
include breaking changes, noted explicitly).

## [Unreleased]

## [0.8.0], 2026-09-07

Platform expansion: supply chain, policy engine, SBOM, infrastructure scanning,
and plugin CLI commands for commercial add-ons.

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
- **Docs**: repository split, project layout, infrastructure scanning, publishing checklist.

### Changed
- Version **0.8.0** is the minimum core release for `argus-k8s` plugin commands.

## [0.7.0], 2026-07-14

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

## [0.6.1]

### Fixed
- Rich markup no longer eats bracketed text in CLI tables (e.g. `[ast]`).

## [0.6.0]

### Added
- **AST data-flow (taint) scanner for Python** via tree-sitter (optional extra
  `[ast]`), closing SQL-injection and path-traversal detection gaps.

### Changed
- OSV client hardened: batches all packages in one request, caches responses on
  disk, retries transient failures.
- Top-level `--version` / `-V` flag.

## [0.5.0]

### Added
- Baseline / diff-aware scanning: report only findings not present in a
  previous JSON report, matched by content-based fingerprint.
- Multi-ecosystem SCA via lockfiles: PyPI (`poetry.lock`, `Pipfile.lock`), npm
  (`package-lock.json`, `yarn.lock`), Go (`go.mod`), Rust (`Cargo.lock`), Ruby
  (`Gemfile.lock`), PHP (`composer.lock`), transitive dependencies included.
- Remote-config hardening: `.argus.yml` inside a cloned remote repo is ignored
  unless `--trust-remote-config` is passed.

## [0.2.0]

### Added
- Live vulnerability data from [OSV.dev](https://osv.dev) in the dependency
  scanner, with a bundled offline advisory seed as fallback.

## [0.1.1]

### Fixed
- False positives found by scanning real-world repositories.

## [0.1.0]

Initial release: five-stage pipeline (resolve → analyze → scan → enrich →
report); secrets, dependency, SAST-pattern, and IaC scanners; AI enrichment
with heuristic (offline), Anthropic, OpenAI, and Ollama providers; Attack
Simulation Mode; deterministic verified auto-fix with branch + pull-request
creation (`argus fix`); JSON, SARIF, Markdown, HTML, and CSV reporters; plugin
entry-point system for scanners, reporters, and providers.
