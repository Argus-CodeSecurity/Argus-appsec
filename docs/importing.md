# Importing SARIF from other scanners

Most teams already run scanners they trust: Semgrep, CodeQL, gitleaks, Trivy,
Bandit. Nearly all of them write SARIF 2.1.0. `argus import` reads that output
and turns every result into an ordinary Argus finding, so the rest of Argus
works on it unchanged: baselines, the allowlist and exceptions, policy, the
severity gate, every report format, enrichment and patch generation.

You keep your scanners. Argus adds triage, gating and reporting on top.

## Quick start

```bash
# Import one or more SARIF files for the project in the current directory
argus import semgrep.sarif codeql.sarif

# Gate CI on the imported results
argus import semgrep.sarif --fail-on high

# Write any report format
argus import trivy.sarif -f html -o report.html
argus import *.sarif -f json -f sarif -o reports/

# Merge imported results into a full Argus scan
argus scan . --import-sarif semgrep.sarif --import-sarif gitleaks.sarif
```

`argus import` takes the same reporting and gating options as `argus scan`:
`-f/--format`, `-o/--output`, `--baseline`, `--diff`, `--fail-on`,
`--min-severity`, `--config`, `--no-ai`, `--patches`, `--audience` and `-q`.
`--project PATH` (default: the current directory) is the project root the
SARIF paths are relative to.

## Producing SARIF, per tool

Run each tool from the project root so the paths it writes are relative to it.

### Semgrep

```bash
semgrep scan --config auto --sarif --output semgrep.sarif
argus import semgrep.sarif
```

Results suppressed in the source with `nosemgrep` are marked as suppressed in
the SARIF and are not imported.

### CodeQL

```bash
codeql database create codeql-db --language=python --source-root .
codeql database analyze codeql-db codeql/python-queries \
  --format=sarif-latest --output=codeql.sarif
argus import codeql.sarif
```

In GitHub Actions, `github/codeql-action/analyze` writes its SARIF to the
directory given by its `output` input (default `../results`); pass that file
to `argus import`. CodeQL's `%SRCROOT%` usually names the runner's checkout
path. Argus reads paths relative to it as relative to `--project` and prints
a warning saying so.

### gitleaks

```bash
gitleaks detect --source . --report-format sarif --report-path gitleaks.sarif
# gitleaks 8.19 and later also accept:
gitleaks dir . --report-format sarif --report-path gitleaks.sarif
argus import gitleaks.sarif
```

gitleaks puts the raw secret in the SARIF snippet. Argus masks it before the
finding is stored (see [Secrets in imported files](#secrets-in-imported-files)),
but the SARIF file itself still holds the secret: treat it as sensitive, or
run gitleaks with `--redact`.

### Trivy

```bash
trivy fs --format sarif --output trivy.sarif .
argus import trivy.sarif

# Container images: paths are inside the image, not the project
trivy image --format sarif --output trivy-image.sarif myapp:1.4.2
argus import trivy-image.sarif
```

Trivy declares its base as `file:///`; Argus treats a base that is the
filesystem root as the project root.

### Bandit

```bash
bandit -r . -f sarif -o bandit.sarif
argus import bandit.sarif
```

Recent Bandit releases include the SARIF formatter; older ones need the
`bandit-sarif-formatter` package.

### Anything else

Any tool that writes SARIF 2.1.0 works the same way. Argus reads the fields
the specification defines and the common extensions listed below; a field it
does not understand is ignored.

## What is preserved

| Argus finding | Taken from |
|---------------|------------|
| `scanner` | `sarif:<tool>`, from `tool.driver.name` (`sarif:codeql`, `sarif:semgrep-oss`, ...) |
| `rule_id` | `<tool>.<ruleId>`, for example `codeql.py/sql-injection` |
| `title` | the rule's `shortDescription`, else its readable `name`, else the first line of the message |
| `description` | the result `message` (`text`, `markdown`, or `id` with `arguments`) |
| `why_vulnerable` | the rule's `fullDescription` |
| `remediation` | the rule's `help` text, with `helpUri` as a reference (http and https only) |
| `location` | the first `physicalLocation`: path, start and end line and column |
| `snippet` | the source line(s) from the project file when readable, else `region.snippet`, then `contextRegion.snippet`; always redacted |
| `cwe` | `properties.tags` (`external/cwe/cwe-079`, `CWE-79: ...`), `properties.cwe`, `rule.relationships` and `result.taxa` into a `CWE` taxonomy |
| `owasp` | tags such as `OWASP-A03:2021 - Injection` |
| `tags` | `sarif`, the tool name, and the rule's other tags |
| `metadata.sarif` | tool name and version, original rule id, `fingerprints` and `partialFingerprints`, logical locations, the source file, and which field set the severity |
| `metadata.cve` | a CVE or GHSA id in the rule id (Trivy) |

Rules are looked up by `ruleIndex`, `rule.index` with `rule.toolComponent`
(CodeQL keeps its rules in `tool.extensions`), then by id. A result without a
file location keeps its logical location (for example
`(com.example.Billing.charge)`), or the tool name, as a placeholder path.

### Severity

The first of these that is present and valid wins:

1. `properties["security-severity"]` on the result, then on the rule (CodeQL,
   Trivy, Semgrep). GitHub's buckets: 9.0 and above is critical, 7.0 high, 4.0
   medium, 0.1 low, 0.0 info.
2. A named `severity` or `issue_severity` property (`critical`, `high`,
   `medium`, `low`, `info`; Bandit).
3. `properties["problem.severity"]`: `error` is high, `warning` medium,
   `recommendation` low (CodeQL).
4. The result `level`, then the rule's `defaultConfiguration.level`: `error` is
   high, `warning` medium, `note` low, `none` info.
5. Otherwise medium (SARIF's default level is `warning`), except for secret
   findings, which default to high: a committed credential is never "a
   warning", and gitleaks writes no level at all.

### Confidence

Argus has not verified an imported result, so confidence is one step below
what the tool claims (`precision`, `confidence` or `issue_confidence`):
`very-high` is high, `high` medium, `medium` and `low` low. A tool that says
nothing gets low. Confidence affects the risk score and ordering, not the
`--fail-on` gate.

### Skipped results

Results are not imported when they are not a problem (`kind` of `pass`,
`notApplicable` or `informational`), are `baselineState: absent`, or carry an
accepted suppression (a `suppressions` entry with status `accepted` or no
status). `argus import` prints how many were skipped and why.

## Paths and safety

An imported file is untrusted input: it may come from a CI artifact or a pull
request. Argus therefore:

- refuses files over 50 MB, JSON nested deeper than 64 levels, `NaN` or
  `Infinity` constants, SARIF versions other than 2.1.0, and more than 100,000
  results (a usage error, exit 2);
- ignores any field of the wrong type instead of trusting it;
- percent-decodes URIs, accepts `/` and `\` separators and `file://` URIs
  (including `file:///C:/...`), and resolves `uriBaseId` through
  `originalUriBaseIds`;
- **drops, with a warning, any location that resolves outside the project
  root**: `../` traversal (also percent-encoded), absolute paths elsewhere,
  other hosts, UNC paths and schemes other than `file`, `http` and `https`;
- never opens a file outside the root. When it reads a project file to fill a
  snippet, it resolves symlinks first and skips the file if it leads outside,
  is not a regular file, is binary or is over the project size limit;
- strips terminal control sequences from all text.

A `uriBaseId` that points somewhere else (usually the checkout path on the CI
machine) is read as the project root; the relative part is still checked
against it.

## Secrets in imported files

Every snippet and message is run through the same redaction Argus's secrets
scanner uses before the finding is stored. For a secret finding (from a
secret scanner such as gitleaks, a credential CWE, or a rule or tag naming a
secret, token, password or key) Argus also:

- masks the exact column span the tool reported, even when the value matches
  no known pattern;
- masks the whole snippet when nothing else could be located, as for
  gitleaks, which stores only the value;
- removes the masked values from the title, message and help text.

The raw value is never kept in the finding, its metadata or any report.

## De-duplication

When the same issue is reported twice, the report shows it once. Two findings
are the same issue when they come from different scanners, are in the same
file, and either

- both have a line, the lines are at most 2 apart, and they share a CWE; or
- they name the same advisory (CVE or GHSA id), as Argus's dependency scanner
  and Trivy do for one vulnerable package.

Which finding is kept:

- with `argus scan --import-sarif`, Argus's own finding is kept, because it
  carries Argus's reasoning, remediation and fix support;
- between two imported findings, the one with the higher severity (then
  confidence) is kept, the first file given on a tie.

The kept finding lists the others in `metadata.also_reported_by` and takes the
highest severity among them (noted in `metadata.severity_raised_by`), so
importing a file can never make a `--fail-on` gate pass that the tool on its
own would fail. Attack-chain findings are never merged with. Identical
results (the same file imported twice, or duplicate results in one file) are
collapsed.

## Baselines, diffs and identity

Each imported finding gets a stable id, `sarif:<tool>:<rule>:<hash>`. The hash
covers the tool, rule and path, plus the result's `fingerprints` and
`partialFingerprints` when the tool provides them, else the line and snippet.

Baselines match on the same fingerprint as Argus's own findings: rule id,
path and the whitespace-normalized snippet. Because Argus reads the snippet
from the project file, a finding keeps its identity when unrelated edits move
it, as long as the file is available. Record and compare a baseline the usual
way:

```bash
argus import semgrep.sarif -f json -o baseline.json
# later, in CI: report and gate only on new results
argus import semgrep.sarif --baseline baseline.json --fail-on high
```

`--diff origin/main...HEAD` keeps only results on changed lines, as for
`argus scan`.

## Using the rest of Argus

Imported findings go through the same post-processing as Argus's own, in
the same order, so every setting below behaves exactly as it does for
`argus scan`:

- **Allowlist and exceptions**: `allow:` entries in `.argus.yml` and
  `.argus/exceptions.yml` apply to imported findings. Match a rule by its
  original id (`rule: py/sql-injection`) or the prefixed one.
- **Inline suppressions**: `argus-ignore` comments apply on trusted projects,
  as for a scan.
- **`exclude_paths`** from config also drops imported findings in those paths.
- **Project context**: `.argus/context.yml` lowers findings under
  `internal_paths`, raises those under `data_classification` and adjusts
  likelihood by `exposure`, recording each change in `metadata.context`. See
  [Project context](context.md).
- **Audit log**: an allowlist entry, exception, inline comment or baseline
  that hides an imported finding is recorded in `.argus/audit.log` on trusted
  local projects. See [Audit log](audit-log.md).
- **Attack chains** are built from the imported findings as from scanner
  findings.
- **Policy**: write a JSON report and check it:
  `argus import *.sarif -f json -o results.json` then
  `argus policy check --report results.json`.
- **Enrichment and fixes**: imported findings go through the configured AI
  provider (offline heuristics by default; `--no-ai` turns it off) and,
  with `--patches`, patch generation.

## Exit codes

The same as `argus scan`: 0 when the gate passes, 1 when a finding is at or
above `--fail-on` (or `fail_on` in config), 2 for usage errors, including an
unreadable or rejected SARIF file, a missing `--project` directory and an
unknown severity. A result dropped for an unsafe path is a warning, not an
error.

## Limitations

- Only SARIF 2.1.0. Other formats (Semgrep JSON, Trivy JSON) are not read.
- Only the first location of a result is used. `codeFlows`,
  `relatedLocations` and `stacks` are not imported, and SARIF `fixes` are not
  turned into Argus patches.
- An absolute path outside the project root is dropped, not re-mapped. Use
  relative paths or `originalUriBaseIds` (most tools do by default), or run
  `argus import` from a checkout at the same path the tool used.
- If the project file is not available and the SARIF has no snippet, the
  baseline fingerprint falls back to the line number, so such a finding is
  reported again after it moves.
- `argus-ignore: <rule>` cannot name rule ids that contain `/` (CodeQL);
  use an `allow:` entry or a rule-less `argus-ignore` instead.
- Markdown in messages is kept as text, not rendered.
