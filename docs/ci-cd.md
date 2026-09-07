# CI/CD integration

Argus is built to run in a pipeline: it emits SARIF for code-scanning platforms
and can fail a build on a severity threshold.

## GitHub Actions

### The official Action (recommended)

The fastest path is the official Action, one block of YAML:

```yaml
name: Security
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write   # required for the SARIF upload

jobs:
  argus:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0     # full history enables diff-aware PR scanning
      - uses: Argus-CodeSecurity/Argus-appsec@v0.8.1
        with:
          fail-on: high      # block merges on newly introduced High+ findings
```

That is the whole setup. Findings appear as PR annotations and in the Security
tab. On pull requests the Action is **diff-aware by default**: it scans the base
branch to build a baseline and gates only on findings the PR *introduces*, the
property that keeps a first adoption from drowning in pre-existing alerts.

All inputs are optional; the useful ones:

| Input | Default | Purpose |
|-------|---------|---------|
| `path` | `.` | Directory to scan |
| `fail-on` | *(never fail)* | Severity gate: `critical`/`high`/`medium`/`low` |
| `scanners` / `exclude-scanners` | all | Choose scanners |
| `min-severity` |, | Report floor |
| `config` |, | Path to an `.argus.yml` |
| `diff-aware` | `true` | Baseline PRs against the base branch |
| `upload-sarif` | `true` | Upload to Code Scanning |
| `argus-version` | latest | Pin the argus-appsec version |
| `extra-args` |, | Anything else `argus scan` accepts |

### Hand-rolled workflow

If you need more control, a ready-to-copy workflow lives at
[`.github/workflows/argus-scan.yml`](../.github/workflows/argus-scan.yml). It runs
Argus, writes SARIF, and uploads it to GitHub Code Scanning so findings appear as
PR annotations and in the Security tab.

To **block merges** instead of only annotating, add a gate:

```yaml
      - name: Run Argus (gate on High+)
        run: argus scan . --fail-on high --quiet -f sarif -o argus.sarif
```

`--fail-on high` makes the step exit non-zero when any High or Critical finding is
present.

## Diff-aware scanning with a baseline

Adopting a scanner on an existing codebase usually means drowning in pre-existing
findings. Argus supports **two** diff-aware modes:

### Git-native diff (`--diff`)

Report only findings on lines/files changed in a git range, plus dependency
findings on changed lockfiles:

```bash
argus scan . --diff origin/main...HEAD --fail-on high
argus dependencies . --diff origin/main...HEAD
argus sbom . --diff origin/main...HEAD -o sbom-diff.json
argus supply-chain . --diff origin/main...HEAD --fail-on high
```

This also enables the `dependency-diff` scanner (version changes + npm behavior
anomalies) automatically.

### Baseline fingerprint diff (`--baseline`)

```bash
# 1. Scan the base branch and save the report as a baseline (outside the tree).
argus scan /path/to/base-checkout -f json -o /tmp/baseline.json --quiet

# 2. Scan the PR, suppressing anything already in the baseline, and gate on new High+.
argus scan . --baseline /tmp/baseline.json --fail-on high --quiet
```

Findings are matched by a **content-based fingerprint** (the whitespace-normalized
offending code, not the line number), so a finding is still recognized as
pre-existing after unrelated edits shift it up or down the file. The shipped
[`argus-scan.yml`](../.github/workflows/argus-scan.yml) workflow does this
automatically on pull requests.

## Reproducibility

Argus walks files in a deterministic, sorted order, so finding IDs and report
ordering are stable across machines and runs, safe to diff report-to-report.

## Untrusted targets

When scanning a **remote** repository (a git URL), Argus ignores any `.argus.yml`
inside that repo by default, so a scanned project cannot weaken its own scan. Pass
`--trust-remote-config` to opt in when you control the repository.

## GitLab CI

```yaml
argus:
  image: python:3.12-slim
  script:
    - pip install argus-appsec
    - argus scan . -f sarif -o gl-argus.sarif --fail-on high
  artifacts:
    when: always
    paths:
      - gl-argus.sarif
```

## Bitbucket Pipelines

```yaml
# bitbucket-pipelines.yml
pipelines:
  default:
    - step:
        name: Argus security scan
        image: python:3.12-slim
        script:
          - pip install argus-appsec
          - argus scan . -f sarif -o argus.sarif --fail-on high --no-ai --quiet
        artifacts:
          - argus.sarif
```

## Docker

An official image is published to GHCR on every release, useful where `pip`
is unavailable in CI or you want a pinned, reproducible scanner:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/argus-codesecurity/argus scan /work --fail-on high
```

The image runs as a non-root user and includes git, so remote repository
targets (`argus scan https://github.com/org/repo`) work too.

## Pre-commit hook

Argus ships hooks for the [pre-commit](https://pre-commit.com) framework, so
catching a secret **before it enters git history** takes three lines:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Argus-CodeSecurity/Argus-appsec
    rev: v0.7.0
    hooks:
      - id: argus-secrets        # fast, secrets-only, made for every commit
      # - id: argus              # full static scan, heavier; consider pre-push
```

`argus-secrets` runs only the secrets scanner with AI enrichment disabled, so
it stays fast enough for every commit. The full `argus` hook is better suited
to `stages: [pre-push]` or CI.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed; no finding met the `--fail-on` threshold (or none was set). |
| 1 | Scan completed but a finding met the `--fail-on` threshold. |
| 2 | The target could not be resolved (bad path/URL, clone failed). |

## Keeping scans fast in CI

- Restrict scanners to what you need: `-s secrets,dependencies,patterns`.
- Disable AI enrichment for speed with `--no-ai` (findings still carry their
  built-in reasoning and taxonomy).
- Use `exclude_paths` in `.argus.yml` to skip vendored or generated code.

## Scan your own CI/CD pipelines

Use the focused command to gate risky workflow changes without a full scan:

```yaml
- name: CI/CD security
  run: argus cicd . --fail-on high --quiet
```

For Docker, Compose, and Kubernetes manifests: `argus container . --fail-on high`.

For Terraform and CloudFormation: `argus cloud . --fail-on high`.

Details: [infrastructure-scanning.md](infrastructure-scanning.md).
