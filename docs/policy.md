# Policy engine

Argus includes a deterministic **policy engine** that evaluates scan findings
against rules declared in `.argus.yml`. Policies never depend on LLM output.

## Declaring policies

```yaml
policies:
  - id: block-critical
    when:
      severity: critical
    action: block

  - id: block-secrets
    when:
      scanner: secrets
    action: block

  - id: warn-typosquat
    when:
      rule: supply-chain.typosquat
    action: warn

  - id: block-malicious-package
    when:
      rule: supply-chain.known-malicious
    action: block
```

## Match fields

| Field | Matches |
|-------|---------|
| `severity` | Finding severity at or above the threshold |
| `scanner` | Exact scanner name (`secrets`, `dependencies`, `supply-chain`, …) |
| `rule` | Rule id (full, suffix, or last segment) |
| `tag` | Finding tag |
| `cwe` | CWE identifier |

## Actions

| Action | Meaning |
|--------|---------|
| `block` | Policy check fails (exit code 1) |
| `warn` | Reported but does not fail the check |

## Usage

```bash
# Evaluate policies after a scan
argus policy check .

# Evaluate an existing JSON report
argus policy check --report results.json

# In CI (after scan)
argus scan . -f json -o results.json --quiet
argus policy check --report results.json
```

Policies complement `--fail-on`, which gates on raw severity. Use policies when
you need scanner-specific or rule-specific gates (e.g. block all secrets and
malicious packages, warn on typosquats).

## Version control

Keep `.argus.yml` policies in git. Changes to policy should be reviewed like
code changes - they define your security gate.
