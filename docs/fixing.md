# Fixing findings and opening pull requests

`nephilex fix` turns Nephilex from an advisor into a fixer. It scans a repository,
applies the fixes it can verify locally to a new branch, commits them, and, on
request, pushes the branch and opens a pull request.

```bash
nephilex fix ./my-app --dry-run      # preview only; writes nothing
nephilex fix ./my-app                # apply fixes to a branch and commit locally
nephilex fix ./my-app --open-pr      # also push and open a pull request
```

## What gets fixed

Only **deterministic, self-verified** rewrites are applied by default. These are
fixes where Nephilex can transform the exact offending line and then re-check that
the detection no longer fires. Current rewrites:

| Rule | Change |
|------|--------|
| `patterns.python-yaml-load` | `yaml.load(...)` to `yaml.safe_load(...)` |
| `patterns.weak-hash-md5-sha1` | MD5 / SHA-1 to SHA-256 |
| `patterns.python-shell-true` | remove `shell=True` from `subprocess` calls |
| `patterns.tls-verify-disabled` | re-enable certificate verification |
| `patterns.flask-debug-true` | `debug=True` to `debug=False` |

Findings without a deterministic rewrite are left for you to fix manually (the
scan report still explains them and, with an AI provider, can suggest a patch).

Each applied change preserves the original line's indentation and surrounding
code, because the rewrite runs against the real file line rather than a stored
snippet.

## Safety model

- **Nothing is written in `--dry-run`.** You see the exact table of changes first.
- **Changes land on a new branch** (`nephilex/security-fixes` by default), never on
  your working branch, so they are trivial to discard.
- **Nothing is pushed or opened** unless you pass `--open-pr`.
- **Only verified fixes** are applied unless you explicitly pass
  `--include-unverified` (review those carefully).

## Opening a pull request

`--open-pr` pushes the branch and opens a PR through the host's API. It needs a
token in the environment:

| Host | Token |
|------|-------|
| GitHub | `GITHUB_TOKEN` |
| GitLab | `GITLAB_TOKEN` |

```bash
export GITHUB_TOKEN=ghp_...
nephilex fix . --open-pr --base main
```

The PR description lists every change with its file, line, rule, and whether it
was verified, plus the diffs in a collapsible section.

## Options

```
nephilex fix [TARGET]
      --dry-run              preview changes without writing
      --open-pr              push the branch and open a pull request
      --branch NAME          branch to create (default: nephilex/security-fixes)
      --base NAME            base branch for the PR (default: repo's default branch)
      --include-unverified   also apply fixes that did not self-verify
      --force-branch         reuse/overwrite the branch if it already exists
  -s, --scanners a,b         only run these scanners
      --min-severity SEV     only consider findings at/above this severity
  -q, --quiet                suppress progress output
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Completed (fixes applied/committed, or nothing to fix). |
| 1 | The workflow stopped with an error (e.g. not a git repo, push failed, no token). |
| 2 | The target could not be resolved. |

## In CI

You can wire `nephilex fix --open-pr` into a scheduled job so Nephilex proposes fix PRs
automatically. Give the job a token with permission to push branches and open pull
requests, and pin `--base` to your default branch.
