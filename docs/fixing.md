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
- **Tests are opt-in.** Nephilex does not run the project's tests unless you
  pass `--verify-with-tests` (see below). Your git commit hooks still run when
  the fixes are committed, unless you pass `--no-verify`.

## Verifying fixes with your tests

"Verified" above means the detection rule no longer matches the rewritten
line. It does not mean the application still works: switching MD5 to SHA-256
changes stored digests, and removing `shell=True` breaks a command passed as a
string. `--verify-with-tests` adds a second check by running the project's own
test command:

```bash
nephilex fix . --verify-with-tests --test-command "python -m pytest -q"
nephilex fix . --test-command "npm test" --test-timeout 900   # --test-command implies it
```

The command can also come from the project's `.nephilex.yml`:

```yaml
autofix:
  test_command: ["python", "-m", "pytest", "-q"]   # or a string: "python -m pytest -q"
  test_timeout: 900                                # seconds per run (default 600)
```

The config keys are read **only when the project config is trusted** (local
targets; see [Which configuration is trusted](configuration.md#which-configuration-is-trusted)).
A cloned repository can never choose a command Nephilex runs. `--test-command`
and `--test-timeout` override the config. Without a command,
`--verify-with-tests` stops with a usage error (exit code 2). It cannot be
combined with `--dry-run`.

### What happens

1. Nephilex creates a temporary git worktree from the scanned commit (HEAD).
   Your working tree is never used to run anything, and the worktree is removed
   at the end, also after an error or a timeout.
2. The test command runs once in that worktree before any fix (the baseline).
   If it fails or times out, the fixes cannot be judged: Nephilex reports that,
   marks every fix "could not verify", commits nothing and exits 1.
3. The fixes are applied in the worktree and the project is scanned again.
   A fix fails if its finding is still reported, or if a new High or Critical
   finding appears in a file it changed. Failed fixes are dropped.
4. The test command runs again with the remaining fixes applied.
5. Only fixes whose tests passed are applied to the fix branch, committed,
   and (with `--open-pr`) pushed. Nephilex checks that the files it commits are
   byte for byte the ones the tests ran against (line endings aside).

Each fix gets a test result next to its rule check: **passed**, **failed** or
**could not verify** (for example, the run after the fixes timed out). The
summary table shows both, with the reason for every fix that was left out.
The commit message, the pull request body (a **Tests** column and a "Test
verification" section) and the `fix.applied` records in the
[audit log](audit-log.md) carry the result too.

All fixes are tested together in one run. When that run fails, every fix in it
is marked failed and the output says the failing fix was not isolated. Re-run
with `--scanners` or `--min-severity`, or fix the findings one rule at a time,
to narrow it down.

The worktree holds only committed files. Dependencies must already be
available (an activated virtual environment, packages on `PATH`) or be
installed by the test command itself. Untracked files such as `node_modules/`,
`.env` or local build output are not copied, and submodules are not
initialized.

### How the command runs

- **No shell.** The command is split into a program and arguments
  (`shlex.split` on POSIX, the Windows command-line rules on Windows) and run
  directly. Pipes, `&&` and variable expansion do not work; put them in a
  script and run the script. A list in `autofix.test_command` is used as is.
- **Program lookup.** A bare name such as `pytest` is searched only in the
  absolute directories on `PATH`, never in the current or the repository
  directory. A path such as `./scripts/test.sh` is resolved inside the worktree.
- **Timeout.** Each run is stopped after `--test-timeout` seconds (default
  600), together with the processes it started.
- **Capped output.** The last 1 MB of combined output is kept; the last lines
  are shown when a run fails. Test output is shown only in your terminal. It is
  never sent to an AI provider and never put in the pull request.
- **Scrubbed environment.** Variables that look like credentials are removed
  before the tests start: names containing `TOKEN`, `SECRET`, `KEY`,
  `PASSWORD`, `CREDENTIAL`, `AUTH` and similar; whole families such as
  `GITHUB_*`, `GITLAB_*`, `AWS_*`, `AZURE_*`, `GOOGLE_*`, `NEPHILEX_*`,
  `ANTHROPIC_*` and `OPENAI_*`; `SSH_AUTH_SOCK`, `KUBECONFIG` and git variables
  that redirect git; and any value that holds a password in a URL, a private
  key or a well-known token format. `PATH`, `HOME`, `SYSTEMROOT`, the temp
  directories and the variables Python and Node read (`VIRTUAL_ENV`,
  `PYTHONPATH`, `NODE_OPTIONS`, ...) are kept. The names removed are listed in
  the summary; their values never are.

### Remaining risk

**Running a project's tests runs that project's code.** Only use
`--verify-with-tests` on repositories you trust as much as you would trust
running their tests yourself. The controls above stop an accident, such as a
test suite reading a token from the environment or writing to your checkout;
they are not a sandbox:

- The tests run as your user, with your file system and network. They can read
  `~/.ssh`, `~/.aws/credentials`, `~/.netrc`, browser profiles, and anything
  else your account can read, and they can reach the network.
- The environment scrub is a deny list. A secret in an innocently named
  variable, in an unrecognised format, gets through.
- On Windows, a process the tests start in the background can outlive a run
  that finished normally; the process tree is only killed on a timeout.

For an untrusted repository, run `nephilex fix` without `--verify-with-tests` and
run its tests yourself in a disposable container or VM.

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
      --verify-with-tests    run the project's tests before and after the fixes
                             in a temporary worktree; commit only passing fixes
      --test-command CMD     test command (implies --verify-with-tests)
      --test-timeout SECONDS time limit per test run (default 600)
  -s, --scanners a,b         only run these scanners
      --min-severity SEV     only consider findings at/above this severity
  -q, --quiet                suppress progress output
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Completed (fixes applied/committed, or nothing to fix). |
| 1 | The workflow stopped with an error (e.g. not a git repo, push failed, no token, or the baseline test run failed with `--verify-with-tests`). |
| 2 | The target could not be resolved, or the options are invalid (e.g. `--verify-with-tests` without a test command). |

With `--verify-with-tests`, fixes that fail their tests are a normal outcome,
not an error: they are left out, the rest are committed, and the exit code is 0.

## In CI

You can wire `nephilex fix --open-pr` into a scheduled job so Nephilex proposes fix PRs
automatically. Give the job a token with permission to push branches and open pull
requests, and pin `--base` to your default branch.
