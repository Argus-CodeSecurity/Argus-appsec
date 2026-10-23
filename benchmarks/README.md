# Nephilex benchmarks

Reproducible scans of known-vulnerable reference applications. The goal is the
credibility cornerstone every scanner should have: published numbers, honest
methodology, and a harness anyone can re-run.

```bash
python benchmarks/run_benchmarks.py               # all available corpora
python benchmarks/run_benchmarks.py juice-shop    # just one
```

Corpora are shallow-cloned into `.corpora/` (gitignored); results are written
to `results/<corpus>.json` plus a combined `results/SUMMARY.md`, with the exact
corpus commit recorded so every number is attributable.

## Corpora

| Name | What it exercises |
|---|---|
| `juice-shop` | OWASP Juice Shop, JS/TS SAST + taint tiers, secrets, npm deps |
| `dvwa` | DVWA (PHP), secrets/dependency/IaC layers on an uncovered language |
| `webgoat` | OWASP WebGoat (Java), same, JVM stack |
| `sard-local` | NIST SARD/Juliet cases, set `NEPHILEX_BENCH_SARD_DIR` to the extracted suite (manual license click-through at samate.nist.gov) |

## Held-out benchmark (real fix commits)

`heldout/` scores Nephilex, Bandit and Semgrep on files changed by the fix
commits of reviewed GitHub advisories (pip and npm), as vulnerable/patched
pairs that no Nephilex rule was tuned on:

```bash
python benchmarks/heldout/run.py fetch     # files listed in heldout/manifest.json
python benchmarks/heldout/run.py scan --bandit PATH --semgrep PATH
python benchmarks/heldout/run.py score     # re-score committed results, no tools
```

The selection rule, scoring and results are in `docs/benchmarks.md`
("Held-out benchmark: real fix commits"); outputs go to `results/heldout/`.

## Methodology and honesty notes

- Scans run with `--no-ai --no-cache` so numbers are deterministic and
  comparable across machines.
- What is published today is a **finding inventory** (counts by scanner and
  severity, scan time), which catches per-release regressions. True
  **precision/recall** requires a ground-truth mapping per corpus; the harness
  has a `ground_truth` hook per corpus and contributions of labeled mappings
  are very welcome.
- Numbers that get worse are published anyway, a benchmark that only ever
  improves is marketing, not measurement.
