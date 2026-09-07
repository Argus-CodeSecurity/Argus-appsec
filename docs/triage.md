# Triage & baselines

A scanner lives or dies on noise. The first run should show signal, and a team
should be able to accept known issues and get alerted only on new ones. Argus
gives you a few honest, working controls for that today.

For how to read risk scores, severities, and pass/fail gates, see
[Understanding scan results](understanding-results.md).

## Start with signal, not noise

Show only what matters first, then widen:

```bash
# Only high and critical, the sensible first look
argus scan ./app --min-severity high

# Widen once you trust it
argus scan ./app --min-severity low
```

## Gate a pipeline

Fail the build only at or above a severity you choose. Empty means never fail.

```bash
argus scan ./app --fail-on high
```

Exit codes are stable and documented for scripting; see
[CI/CD integration](ci-cd.md) for the full contract and machine-readable output.

## Baseline: alert only on new findings

Record the current state, then on later runs report only findings that are new
relative to that baseline. This is how you adopt Argus on a large existing
codebase without drowning in day-one debt.

```bash
# 1. Capture the current findings as a baseline
argus scan ./app -f json -o baseline.json

# 2. On later runs, ignore anything already in the baseline
argus scan ./app --baseline baseline.json
```

Findings are matched by a stable fingerprint, so unrelated line moves do not
resurface an accepted issue.

!!! warning "Baselines and untrusted repositories"
    A baseline can suppress findings. When you scan a repository you do not
    control, do not let it supply its own baseline; a hostile repo could hide its
    own issues. Keep the baseline file under your control, outside the scanned
    tree.

## Exclude paths

Skip vendored code, fixtures, or generated bundles from `.argus.yml`:

```yaml
exclude_paths:
  - "examples/**"
  - "**/*.min.js"
  - "third_party/**"
```

Globs match the path and the bare filename, so both a subtree and a single file
work. Built-in noise directories (`node_modules`, `.venv`, `dist`, and similar)
are skipped automatically.

## Suppress a specific finding inline

Accept one finding on one line with a documented reason, using an `argus-ignore`
comment on the offending line. The reason is **required**, so every suppression
explains itself:

```python
subprocess.run(cmd, shell=True)  # argus-ignore: python-shell-true reason="fixed internal command, no user input"
```

- Scope by rule id (full `patterns.python-shell-true`, short `python-shell-true`,
  or the last segment). Omit the rule id to suppress every finding on the line.
- `//` comments work too, for JavaScript/TypeScript.
- **Expiring suppressions.** Add `until=YYYY-MM-DD` and the suppression lapses on
  that date, so accepted risk resurfaces instead of hiding forever:

```python
eval(payload)  # argus-ignore: ast-code-injection reason="tracked in JIRA-123" until=2026-12-31
```

## Allowlist file (accepted risk in one place)

When you would rather keep suppressions outside the source, list them under
`allow:` in `.argus.yml`. Each entry needs a `reason`, scopes by `rule` and/or
`path` (glob), and may `expire`:

```yaml
allow:
  - rule: python-shell-true
    path: "scripts/**"
    reason: "deploy scripts run fixed internal commands"
  - rule: secrets.high-entropy-string
    path: "tests/**"
    reason: "test fixtures, not real credentials"
    until: 2026-12-31   # optional; the entry stops suppressing on this date
```

An entry with neither a `rule` nor a `path` is ignored (it would hide the whole
scan), and an expired `until` lets the finding resurface, same as inline
suppressions.

## Machine-readable everything

For agents and CI, prefer structured output and keep logs on stderr:

```bash
argus scan ./app -f sarif -o results.sarif   # GitHub Code Scanning
argus scan ./app -f json                      # pipe to jq, dashboards, or an agent
```
