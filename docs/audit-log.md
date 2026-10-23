# Audit log

Every fix Nephilex applies and every suppression that hides or accepts a finding
is recorded in `.nephilex/audit.log`, inside the repository. The file is meant to
be committed: it gives reviewers and auditors one place to answer "who
suppressed this, when, and why" and "what did the automated fixes change".

Records are hash-chained, so `nephilex audit verify` detects a record that was
edited, deleted, inserted or moved. Read [What it proves](#what-it-proves-and-what-it-does-not)
before relying on it as evidence.

## What is recorded

| Action | When |
|---|---|
| `fix.applied` | `nephilex fix` (or `apply_fixes`) wrote a deterministic fix to a file. One record per fix. |
| `fix.pr_opened` | `nephilex fix --open-pr` opened a pull request for the fixes. One record per fix, with the PR URL. |
| `suppression.added` | Nephilex saw a suppression definition for the first time: an allowlist entry, a `.nephilex/exceptions.yml` entry, an inline `nephilex-ignore` comment (when it first hides a finding), or a baseline file. |
| `suppression.matched` | A suppression hid or accepted a finding. `kind` is `allowlist`, `exception`, `inline` or `baseline`. |

Suppression events are recorded **once per content**: a `suppression.matched`
record is keyed by kind, finding fingerprint and reason, and a
`suppression.added` record by kind, selector and reason. Scanning the same
code again adds nothing; changing the reason of a suppression records it
again, because that is a new decision.

Suppression events are written only when the project configuration is
trusted and the target is a local directory, the same rule that decides
whether inline comments and exceptions are honoured at all (see
[Which configuration is trusted](configuration.md#which-configuration-is-trusted)).
Scans of cloned remotes, `--config-from-ref` runs, `nephilex agent` and `nephilex mcp`
never write to the scanned tree.

Baseline filtering (`--baseline` on `nephilex scan`, `nephilex import` and
`nephilex review`) runs in the command after the scan and is recorded under the
same rule: one `suppression.added` per baseline file content and one
`suppression.matched` per finding it hid. Other callers can use the
`nephilex.audit.record_baseline` helper.

### Turning it off

Set `audit_log: false` in `.nephilex.yml`, or `NEPHILEX_AUDIT_LOG=off` in the
environment (also `0`, `false`, `no`). Both also cover the `fix.applied`
and `fix.pr_opened` records of `nephilex fix`.

## Format

JSON Lines, ASCII only, one record per line. Every record has the same keys,
with `null` where a field does not apply:

```json
{"action":"suppression.matched","actor":"Jane Developer <jane@example.com>",
 "details":{"line":12,"selector":"python-shell-true","severity":"high","until":null},
 "fingerprint":"patterns.python-shell-true|tools/run.py|5d41402abc4b",
 "hash":"9c1e...","kind":"inline","path":"tools/run.py",
 "prev_hash":"77ab...","reason":"command is a constant list","rule":"patterns.python-shell-true",
 "seq":42,"ts":"2026-10-22T09:14:03.120Z","v":1}
```

(Shown wrapped; in the file each record is one line.)

| Field | Meaning |
|---|---|
| `v` | Record format version, currently 1. |
| `seq` | Position in the chain, starting at 1. |
| `ts` | UTC time, millisecond precision. |
| `actor` | `user.name <user.email>` from git config, else `GIT_AUTHOR_NAME`/`GIT_AUTHOR_EMAIL`, else the OS user name. |
| `action` | One of the actions above. |
| `kind` | For suppressions: `allowlist`, `exception`, `inline`, `baseline`. |
| `fingerprint` | The finding's stable fingerprint, the same value baselines and exceptions use. |
| `rule`, `path` | Rule id and project-relative path. |
| `reason` | The suppression's reason, or for fixes whether the fix was verified. |
| `details` | Extra context: line, selector, expiry, exception status and owner, branch, commit, PR URL. |
| `prev_hash` | `hash` of the previous record; 64 zeros for the first. |
| `hash` | SHA-256 of the record's canonical form. |

### The hash chain

The canonical form of a record is its JSON with every key except `hash`,
keys sorted, no whitespace (`separators=(",", ":")`), ASCII only. `hash` is
the hex SHA-256 of those bytes. To check a record by hand in Python:

```python
import hashlib, json

rec = json.loads(line)
body = {k: v for k, v in rec.items() if k != "hash"}
canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
assert hashlib.sha256(canon.encode("ascii")).hexdigest() == rec["hash"]
```

Each record's `prev_hash` must equal the previous record's `hash`, and `seq`
must count up by one. Editing any field changes the hash; deleting,
inserting or reordering a record breaks a `prev_hash` link or the `seq`
count at that point.

### What is never written

The log is committed, so it must not leak what the scanner found. Nephilex never
writes code lines or finding snippets to it (fixes record rule, path, line,
fingerprint and verification state only). Every string field is passed
through the same secret masking the secrets scanner uses for report snippets,
and credentials in URLs are removed, so a token pasted into a suppression
reason is masked. Fields are capped at 500 characters.

## Commands

```bash
nephilex audit verify [PATH] [--anchor HASH] [--json]
nephilex audit show   [PATH] [--action A] [--kind K] [--rule R] [--path GLOB]
                          [--actor TEXT] [--fingerprint FP] [--since DATE]
                          [--until DATE] [-n N] [--json]
nephilex audit export [PATH] -f csv|json [-o FILE] [--action A] [--kind K]
                          [--since DATE] [--until DATE]
```

`PATH` is the project directory (default `.`) or the log file itself.

- `verify` exits 0 and prints the record count and head hash when the chain
  is intact, and exits 1 naming the first broken record (line number, `seq`
  and what is wrong) otherwise. Without a log it exits 0, unless `--anchor`
  is given.
- `show` lists records oldest first, filtered; `-n 20` shows the last 20
  matches; `--json` prints JSON Lines.
- `export -f json` writes the matching records together with the chain's
  verification result; `-f csv` writes one row per record, with `details` as
  JSON and cells that a spreadsheet would evaluate as a formula prefixed with
  `'`.

## Concurrency and failure

Writers take an exclusive lock on the log (`flock` on Linux and macOS; on
Windows a byte-range lock placed past the end of the file, so readers are
never blocked), read the current head under the lock, and append all of their
records in one write. Parallel scans and fixes therefore extend one chain
instead of forking it. A writer waits up to 15 seconds for the lock.

The audit log never fails a scan or a fix. If the log cannot be written (the
directory is read-only, `.nephilex` is not a directory, the lock times out, or
the log or `.nephilex` is a symlink, which is refused so a hostile repository
cannot redirect the append), the run continues and the problem is reported
as a warning and in the report's `project_summary.audit.warning`. If the last
line is damaged (for example a crash mid-write), new records are still
appended on a fresh line and `verify` points at the damaged line.

## With `nephilex fix`

`nephilex fix` refuses to run on a working tree with uncommitted changes, with
one exception: `.nephilex/audit.log` itself, because the scan that produced the
findings may just have appended to it. The fix commit includes the log, so
the `fix.applied` records travel with the fixes they describe. If `.nephilex/` is
ignored by git, the log is left out of the commit and a note says so (add
`!.nephilex/audit.log` to `.gitignore` to commit it). If the fix fails and is
rolled back, the log is restored to its state before the run.

`fix.pr_opened` is appended after the branch is pushed, so it is in the
working tree of the fix branch, not in the pull request. Commit it with your
next change.

## What it proves and what it does not

The log is **tamper-evident, not tamper-proof**.

It does show:

- that no record in the middle of the chain was edited, removed, inserted or
  reordered since it was written, provided the chain verifies;
- the order in which fixes and suppressions were recorded, and the reason
  given for each suppression at the time.

It does not show, on its own:

- **that nothing was removed from the end.** Truncating the last records
  leaves a valid, shorter chain;
- **that the log was not rewritten.** Anyone who can write the file can
  recompute every hash and produce a valid chain with different content;
- **who acted.** `actor` comes from git config, which anyone can set; it is
  a claim, not an authenticated identity;
- **when.** Timestamps come from the writer's clock;
- that every suppression was recorded. Runs with the log disabled, untrusted
  runs, and suppressions applied by other tools are not in it.

To close the first two gaps, anchor the chain outside the repository: after
each merge to the main branch, have CI run `nephilex audit verify --json` and
store the `head` value somewhere the repository's writers cannot change (a CI
artifact, a release note, a signed tag, a transparency log). Later,
`nephilex audit verify --anchor <stored head>` fails unless that record is still
in the chain, which catches truncation and wholesale rewrites. Git history
helps too: the log is committed, so `git log -p .nephilex/audit.log` shows every
change to it, and protected branches with signed commits make rewriting it
visible. For identity, rely on your forge's authenticated commit and review
records, and treat `actor` as a convenience.
