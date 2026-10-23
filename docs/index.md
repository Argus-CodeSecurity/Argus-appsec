# Nephilex

**Find vulnerabilities, see how untrusted input reaches them, and apply fixes
that Nephilex re-checks before it commits them.**

Nephilex is an open-source (Apache-2.0) application security scanner for the
command line. One `nephilex scan` covers source code, dependencies, secrets,
infrastructure as code, CI workflows, containers and LLM/agent configuration,
and produces one prioritized list. It runs offline by default and needs no API
key; the dependency scanner sends package names and versions to
[OSV](https://osv.dev) to look up advisories.

[![PyPI](https://img.shields.io/pypi/v/nephilex?color=6366f1&label=pypi)](https://pypi.org/project/nephilex/)
[![Python](https://img.shields.io/pypi/pyversions/nephilex)](https://pypi.org/project/nephilex/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](https://github.com/nephilex/nephilex/blob/main/LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Nephilex/nephilex/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Nephilex/nephilex)

## Try it

Python 3.10 or newer. The `[ast]` extra installs the tree-sitter parsers the
data-flow (taint) scanners need; without it those scanners are skipped.

=== "pipx"

    ```bash
    pipx install "nephilex[ast]"
    ```

=== "pip"

    ```bash
    python -m pip install "nephilex[ast]"
    ```

Scan the deliberately vulnerable demo app from the repository:

```bash
git clone --depth 1 https://github.com/nephilex/nephilex.git
nephilex scan nephilex/examples/vulnerable-app --no-ai
```

Real output from Nephilex 0.11.0 on 2026-10-23 (trimmed: the progress lines and
12 of the 20 table rows are left out):

```text
┌────────────────────────────────────────────── Nephilex scan ──────────────────────────────────────────────┐
│ vulnerable-app                                                                                            │
│ Aggregate risk: 99.7/100   Findings: 20                                                                   │
│ Critical: 2 | High: 8 | Medium: 9 | Low: 1 | Info: 0                                                      │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌──────────┬──────┬───────────────────────────────────┬──────────────────┬──────────────────────────────────┐
│ Sev      │ Risk │ Title                             │ Location         │ Rule                             │
├──────────┼──────┼───────────────────────────────────┼──────────────────┼──────────────────────────────────┤
│ Critical │ 97.0 │ Vulnerable dependency: pyyaml     │ requirements.txt │ dependencies.GHSA-8q59-q68h-6hv4 │
│          │      │ 5.3.1 (CVE-2020-14343)            │                  │                                  │
│ Critical │ 97.0 │ Hardcoded credential: aws access  │ app.py:19        │ secrets.aws-access-key-id        │
│          │      │ key id                            │                  │                                  │
│ High     │ 72.8 │ Vulnerable dependency: flask      │ requirements.txt │ dependencies.GHSA-m2qf-hxjv-5gpq │
│          │      │ 2.0.1 (CVE-2023-30861)            │                  │                                  │
│ High     │ 72.8 │ OS command injection (tainted     │ app.py:37        │ ast-python.ast-command-injection │
│          │      │ value reaches a shell command)    │                  │                                  │
│ High     │ 72.8 │ SQL injection (tainted value      │ app.py:29        │ ast-python.ast-sql-injection     │
│          │      │ reaches a database query)         │                  │                                  │
│ High     │ 70.5 │ Unsafe yaml.load without          │ app.py:45        │ patterns.python-yaml-load        │
│          │      │ SafeLoader                        │                  │                                  │
│ High     │ 66.5 │ Possible hardcoded secret in      │ app.py:20        │ secrets.high-entropy-string      │
│          │      │ 'API_TOKEN'                       │                  │                                  │
│ High     │ 66.5 │ Attack chain: injection foothold  │ app.py:19        │ chains.secret-plus-injection     │
│          │      │ beside an exposed credential      │                  │                                  │
```

`--no-ai` turns off finding enrichment so the output above is reproducible.
Without it Nephilex uses its offline `heuristic` provider, which also needs no
key. Dependency findings come from live OSV data, so their list changes as new
advisories are published.

<div class="grid cards" markdown>

-   **[Quickstart](quickstart.md)**

    Five minutes from install to an HTML report, a SARIF file, a CI gate and
    editor setup, with the expected output of every step.

-   **[Example finding](example-finding.md)**

    One finding from the demo app followed end to end: the code, the report,
    the proposed patch, how it is verified and what the re-scan shows.

-   **[Trust and limits](trust.md)**

    How accuracy is measured, what is static and what is live, a capability
    matrix per scanner, and where established tools are stronger.

-   **[Benchmarks](benchmarks.md)**

    Precision and recall on a labeled corpus and on public datasets, scored
    next to Bandit and Semgrep, with the methodology and its caveats.

</div>

!!! note "Status: early alpha (0.x)"
    The architecture and full pipeline are in place: a working CLI, built-in
    scanners (secrets, dependencies, SAST, IaC, CI/CD, containers, cloud, supply
    chain, LLM and agent configuration), a multi-provider AI layer, cross-file
    taint analysis, and nine report formats. Detection accuracy is still being
    benchmarked. Treat findings as a strong signal to review, not gospel.

## What Nephilex does

- **Maps the project first.** Detects languages and frameworks and records an
  architecture summary (APIs, auth, datastores, cloud, containers, CI/CD,
  dependency manifests) that the scanners and the risk score use.
- **Runs layered analysis in one pass.** Secrets, dependency CVEs (OSV data,
  with optional import-level reachability), pattern SAST, tree-sitter taint
  analysis for Python and JavaScript/TypeScript, IaC misconfiguration, and an
  LLM/agent scanner mapped to the
  [OWASP Top 10 for LLM Apps](https://genai.owasp.org/llm-top-10/).
- **Explains each finding.** Why it is a vulnerability, how an attacker would
  use it, business impact, likelihood, severity, and a CWE/OWASP mapping.
- **Fixes what it can verify.** For a small set of rules Nephilex has a
  deterministic one-line rewrite. It applies a rewrite only when the rule no
  longer matches the changed line and, for Python, JSON and YAML, the file
  still parses. `nephilex fix` commits the changes to a new branch and opens a
  pull request only when you pass `--open-pr`. Nothing is auto-merged.
- **Keeps your code on your machine.** The default AI provider is offline.
  Ollama runs locally. Cloud models are opt-in.

## What Nephilex does not do

Security engineers trust tools that state their limits:

!!! warning "Static analysis first, not DAST"
    Nephilex reads code and configuration. With `--live-target` it also makes a
    few read-only GET requests to a URL you are authorized to test: whether the
    site uses HTTPS, security headers, cookie flags, version disclosure, a
    short list of exposed paths (such as `/.env` and `/.git/config`), wildcard
    CORS, and whether a harmless marker sent in the URL's existing query
    parameters is reflected. It does not crawl, fuzz endpoints, or test
    authenticated flows.

- **Taint depth varies by language.** Data-flow analysis covers Python and
  JavaScript/TypeScript and needs the `[ast]` extra. Cross-file analysis is
  Python only and follows one call hop. Other languages get pattern rules,
  not data-flow analysis.
- **Fix verification is a local re-check, not a test run.** "Verified" means
  the rule no longer fires on the rewritten line and the file still parses. It
  does not run your tests or prove the new code is correct; see the
  [example finding](example-finding.md) for what that means in practice.
- **Not a full enterprise ASPM.** No ticketing and no SSO. Policies
  (`nephilex policy check`, see [Policy](policy.md)) gate a scan in CI; they
  are not organization-wide governance. It is a scanner and a fixer, not a
  platform.
- **Dependency coverage follows OSV.** A vulnerability absent from OSV is
  absent from Nephilex. Without network access the scanner falls back to a
  small bundled advisory list and says so. Reachability lowers noise but is
  heuristic, not a proof.
- **Not a replacement for a human review or a pen test.** A clean scan means
  "nothing these checks caught," not "secure."

The full list, scanner by scanner, is in [Trust and limits](trust.md).

## Explore the CLI

```bash
nephilex scanners     # list scanners
nephilex reporters    # list report formats (json, sarif, html, markdown, csv, gitlab, junit, vex, badge)
nephilex providers    # list AI providers and whether each is usable right now
nephilex init         # write a starter .nephilex.yml
```

## Where to next

- [Understanding scan results](understanding-results.md): risk scores,
  severities, pass/fail gates, and what "secure" means.
- [Scanners & coverage](scanners.md): what each domain detects and does not.
- [Triage & baselines](triage.md): keep the tool low-noise on real repos.
- [CI/CD integration](ci-cd.md): the GitHub Action and diff-aware gating.
- [How Nephilex compares](comparison.md): Semgrep, Trivy, Snyk and others.
- [Security & threat model](security.md): a scanner is also an attack surface.
