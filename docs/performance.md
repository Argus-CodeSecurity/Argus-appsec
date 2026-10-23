# Performance

Adoption in CI lives or dies on scan time, so Nephilex treats speed as a feature
and publishes its numbers. Two mechanisms keep scans fast, both on by default:

- **Per-file result caching.** File-local scanners (secrets, SAST patterns,
  IaC, both AST taint tiers) cache findings per *file content hash*. On the
  next scan, unchanged files reuse their cached findings, including the
  "scanned, clean" result, which is most files, and only changed files are
  re-analyzed. Content-hash keying means a rule/version change or any edit
  invalidates correctly; mtimes are never trusted. Disable with `--no-cache`
  or `cache: false`. The cache lives under `~/.cache/nephilex/scan`
  (`NEPHILEX_CACHE_DIR` overrides the base directory).
- **Concurrent scanners.** Scanners are independent by design and run in a
  thread pool; results are merged in a fixed order. Disable with
  `parallel: false`.

Both preserve Nephilex's determinism guarantee: findings, ids, and report
ordering are identical with caching and parallelism on or off (this is
enforced by tests).

## Measured scan times

Method: `nephilex scan <repo> --no-ai --quiet -f json`, cold = empty cache,
warm = immediate second run. Times include Python interpreter startup and
project analysis. Machine: Intel Core i5-10310U (4c/8t, 1.7 GHz base),
Windows 11, Python 3.11. Measured 2026-07-14 on Nephilex v0.7.0.

| Repository | Files | Cold | Warm |
|---|---|---|---|
| pallets/flask (shallow checkout) | ~236 | 5.3 s | 2.8 s |
| Nephilex itself | ~200 | 4.4 s | 2.9 s |
| examples/vulnerable-app | 3 | 2.7 s | 2.6 s |

The warm floor (~2.5 s) is interpreter startup, project analysis, and the
dependency scanner's OSV lookup (which has its own on-disk cache and is not
file-local). On larger repositories the gap widens: file analysis is the part
that grows with repo size, and it is exactly the part the warm path skips.

## Keeping scans fast

- Restrict scanners to what a context needs: `-s secrets` for a pre-commit
  hook, everything for the nightly run.
- `--no-ai` skips enrichment (findings keep their built-in reasoning).
- Use a baseline (`--baseline`) on PRs, reporting only new findings also
  means less enrichment work.
- `exclude_paths` in `.nephilex.yml` for vendored/generated trees.
