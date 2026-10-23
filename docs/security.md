# Security & threat model

A security tool is also an attack surface. Nephilex clones untrusted repositories,
parses hostile files with complex parsers, runs git, holds discovered credentials
in memory, optionally sends code to an AI layer, and writes fixes back into a
working tree. Every one of those is a classic scanner vulnerability class, so
Nephilex is engineered to defend itself, and documents where it does and does not.

## Threat model

The full, honest threat model lives in the repository and is kept current with the
code. It states what Nephilex defends against, how, with file references, and what
residual risk remains:

- [THREAT_MODEL.md](https://github.com/nephilex/nephilex/blob/main/THREAT_MODEL.md)

Highlights of what is already defended:

- **Malicious remote clone.** Transport allowlist, a `--` separator before the
  URL, `GIT_ALLOW_PROTOCOL`, no credential prompts, and a timeout. Git is always
  called with argument arrays, never a shell.
- **Symlink escape.** Symlinks whose real target leaves the scan root are skipped
  on read, and the fix engine refuses to write outside the project or through an
  escaping symlink.
- **Parser safety.** Every YAML load is `yaml.safe_load`; oversized files are
  skipped; rule matching skips over-long lines to bound regex cost.
- **Malicious repo config.** A scanned repository's own `.nephilex.yml` is ignored by
  default and is opt-in via `--trust-remote-config`.
- **Secret handling.** Values are redacted to a prefix plus length everywhere;
  live verification is opt-in and read-only.
- **Report safety.** The HTML report escapes every attacker-controlled field.
- **Test verification of fixes.** `nephilex fix --verify-with-tests` runs a
  test command chosen by the operator (a scanned repository's own config can
  set it only when that config is trusted), without a shell, in a temporary
  worktree that is always removed, with a timeout, capped output, and an
  environment from which credential-like variables are removed. See below for
  what this does not protect.

## Running a project's tests

Unlike scanning, `nephilex fix --verify-with-tests` exists to execute the
target's code: it runs the project's test suite to check that a
fix did not break the application. Running a project's tests runs that
project's code, with your user's permissions. The controls listed above keep
the test run out of your working tree and away from tokens in the environment,
and they stop a hung suite, but they are not a sandbox: the tests can read
your files (SSH keys, cloud credential files, `~/.netrc`), reach the network,
and pick up a secret stored in a variable the deny list does not recognise.

Use `--verify-with-tests` only on repositories you trust as much as you would
trust running their tests yourself. It is off by default, it is never turned
on by a repository's own configuration, and its test output is never sent to
an AI provider. For untrusted code, run the tests in a disposable container
or VM instead. Details: [Fixing findings](fixing.md#verifying-fixes-with-your-tests).

## Reporting a vulnerability

Please report privately, not in a public issue:

- [SECURITY.md](https://github.com/nephilex/nephilex/blob/main/SECURITY.md)

Scanner-escape bugs (reading, writing, executing, or leaking outside the scan
boundary) are treated as high severity.

## Your data and the AI layer

The default `heuristic` provider and the `ollama` provider keep your source on
your machine. The `anthropic` and `openai` providers send code to those services;
choose one appropriate to your confidentiality requirements. `nephilex providers`
shows which are local and which are remote.
