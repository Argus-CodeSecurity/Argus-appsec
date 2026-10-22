# Project context

A scanner sees code, not your architecture. It cannot know that
`myapp.security.escape_html` is your reviewed HTML encoder, that `scripts/`
only runs from an operator's laptop, or that `billing/` holds card data.
`.argus/context.yml` tells it, so findings reflect your project instead of a
generic one:

- **sanitizers**: functions that neutralise taint, per language and optionally
  per CWE. The AST taint tiers (`ast-python`, `ast-js`) stop reporting flows
  that pass through them.
- **trusted_sources**: values that are not attacker-controlled, such as an
  internal configuration reader. Flows that start there are not reported.
- **internal_paths**: code that is not reachable from outside. Findings there
  are lowered one severity level and tagged `internal`. They are never hidden.
- **exposure**: per-path notes that raise or lower likelihood.
- **data_classification**: paths or models that hold sensitive data. Findings
  there are raised one severity level.

Every finding the context changes says so in `metadata["context"]`, and every
flow it clears is listed in the scan summary, so a reviewer can see exactly
what the file did. See [Reviewing what the context changed](#reviewing-what-the-context-changed).

## Trust rules

The context file is project configuration and follows the same rules as
`.argus.yml` (see [Which configuration is trusted](configuration.md#which-configuration-is-trusted)).
A sanitizer entry switches checks off, so the file must never come from the
code it is meant to review.

| Situation | `.argus/context.yml` |
|---|---|
| Local path (`argus scan .`) | Honoured |
| Cloned remote (`argus scan https://...`) | Ignored unless `--trust-remote-config` |
| `--config-from-ref REF` | Read from that git ref; the working tree's copy is ignored |
| `argus agent`, `argus mcp` | Ignored |

In CI on pull requests, use `--config-from-ref origin/<base-branch>` (the
GitHub Action does this by default). A pull request that adds or edits
`.argus/context.yml` then has no effect on its own scan: the version already
reviewed and merged on the base branch decides. Changes to the context file
take effect after they are merged, like any other gate setting.

Treat changes to `.argus/context.yml` like changes to the gate itself: put the
file under `CODEOWNERS` for your security reviewers.

## Schema

All sections are optional. Unknown keys, wrong types, unknown languages, CWE
ids that do not look like `CWE-79`, and names that are not dotted identifiers
are configuration errors: the run stops with exit status 2 instead of scanning
with a setting that does not say what you meant.

```yaml
version: 1                      # optional; 1 is the only version

sanitizers:
  python:                       # python | javascript | typescript (alias of javascript)
    - myapp.db.quote_identifier # a bare name clears taint for every sink
    - name: myapp.security.escape_html
      cwe: [CWE-79]             # only for sinks of these CWEs
      note: wraps markupsafe.escape
  javascript:
    - name: lib.html.htmlSafe
      cwe: CWE-79               # a single CWE may be a string

trusted_sources:
  python:
    - os.environ                # deploy-time configuration, not user input
    - name: myapp.settings.get
      note: reads the service's own config file
  javascript:
    - process.env

internal_paths:
  - scripts/**
  - path: migrations/*.py
    note: run by operators during deploys

exposure:
  - path: api/**
    level: public_api           # public_api | public_web | internal_service | offline
  - path: worker/**
    level: internal_service
    note: consumes an internal queue only

data_classification:
  - path: billing/**
    classes: [financial, pii]   # pii | secrets | credentials | financial | health
  - model: myapp.models.Customer
    classes: [pii]
```

Limits: at most 1000 entries per section, names up to 200 characters, notes up
to 500 characters, and the file itself up to 1 MB.

### sanitizers

A call matches a configured sanitizer when the dotted name at the call site is
a trailing part of the configured name. For `myapp.security.escape_html`:

| Call | Matches |
|---|---|
| `escape_html(x)` | yes |
| `security.escape_html(x)` | yes |
| `myapp.security.escape_html(x)` | yes |
| `other.escape_html(x)` | no |
| `self.escape_html(x)` | no |

Imports are not resolved, so a different function with the same short name
also matches a bare call. Prefer distinctive names, and configure the name the
way your code calls it.

With `cwe`, the sanitizer only clears taint for sinks of those CWEs. The value
stays tainted for every other sink, through any number of assignments:

```python
from myapp.security import safe_path


def download():
    p = safe_path(request.args["file"])  # sanitizer for CWE-22 only
    q = p
    send_file(q)  # not reported: path traversal is handled
    os.system("gzip " + q)  # still reported: command injection
```

The CWEs the taint tiers check are CWE-89 (SQL injection), CWE-78 (command
injection), CWE-22 (path traversal), CWE-95 (code injection) and, for
JavaScript, CWE-79 (cross-site scripting).

JavaScript example:

```yaml
sanitizers:
  javascript:
    - name: lib.html.htmlSafe
      cwe: [CWE-79]
```

```javascript
const name = html.htmlSafe(req.query.name);
el.innerHTML = name;                              // not reported
db.query("SELECT * FROM t WHERE n = '" + name + "'");  // still reported (CWE-89)
```

### trusted_sources

Each entry is a dotted name. A call to it (matched like a sanitizer) yields a
clean value whatever its arguments, and the name itself no longer counts as an
input source where Argus treats it as one by default (`os.environ` and
`sys.argv` in Python, `process.env` and `process.argv` in JavaScript):

```python
table = os.environ.get("REPORT_TABLE")  # with trusted_sources: [os.environ]
cursor.execute("SELECT * FROM " + table)  # not reported
```

Only list values an attacker cannot influence in your deployment. Environment
variables are a good fit for a server; they are not for a CLI tool that other
users run with their own environment.

### internal_paths

Path globs, matched against the project-relative path like allowlist paths:
`*` crosses directories, `dir/**` matches everything below `dir/`, and a glob
without `/` also matches the file name anywhere. Each finding under a matching
path is lowered one severity level (High becomes Medium, Info stays Info) and
tagged `internal`.

The finding is never removed. `min_severity` is applied to the severity before
the downgrade, so `--min-severity high` still shows a High finding that the
context lowered to Medium. `--fail-on` uses the lowered severity, which is the
point: an internal-only High no longer fails a `fail_on: high` gate, but it is
still in the report.

### exposure

`public_api` and `public_web` raise likelihood one step (for example Possible
to Likely); `internal_service` and `offline` lower it one step. Likelihood
feeds the risk score and ranking, not the severity gate. The first matching
entry wins.

### data_classification

Each entry needs a `path` glob, a `model` name, or both, and a non-empty list
of `classes`. A finding of severity Low or above under the path, or whose code
snippet mentions the model's short name as a whole word (`Customer`, not
`Customers`), is raised one severity level and tagged `sensitive-data` plus
each class. The first matching entry wins. When a finding is both in sensitive
data and in an internal path, both changes apply and both are recorded.

## Reviewing what the context changed

A finding the context changed carries the original values and one entry per
setting that applied:

```json
"metadata": {
  "context": {
    "source": ".argus/context.yml",
    "original_severity": "high",
    "original_likelihood": "possible",
    "changes": [
      {
        "setting": "internal_paths",
        "match": "scripts/**",
        "effect": "severity high -> medium",
        "why": "run by operators during deploys"
      }
    ]
  }
}
```

Flows cleared by a sanitizer or trusted source are not findings any more, so
they are listed in the report's `project_summary.context.cleared`, with the
rule, path, line and the context entries that occur in the file:

```json
"context": {
  "source": "origin/main:.argus/context.yml",
  "digest": "3f2a9c0d1e4b5a67",
  "internal": 1,
  "exposure": 0,
  "sensitive_data": 0,
  "cleared": [
    {
      "rule": "ast-python.ast-path-traversal",
      "path": "app/download.py",
      "line": 7,
      "entries": ["myapp.security.safe_path"],
      "why": "a sanitizer or trusted source declared in the project context removes the taint on this flow"
    }
  ]
}
```

## Limits

- Sanitizers and trusted sources apply to the intra-file AST taint tiers
  (`ast-python`, `ast-js`). The regex `patterns` tier and the cross-file
  Python tier do not read them. Where an AST tier analysed a file, the regex
  tier's findings for SQL injection, XSS, path traversal and code injection
  are already dropped in favour of the AST result, so the sanitizer still
  takes effect for those classes.
- Matching is by name, not by resolved import or type.
- Editing the context file invalidates the scan cache for the taint tiers, so
  a warm scan picks up the change.
