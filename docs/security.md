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
