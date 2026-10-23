# Nephilex benchmark summary

Finding inventories on known-vulnerable corpora (not precision/recall yet, see run_benchmarks.py). Regenerate with `python benchmarks/run_benchmarks.py`.

| Corpus | Commit | Nephilex | Findings | Time (s) | By scanner |
|---|---|---|---|---|---|
| juice-shop | `33518f5a09` | 0.7.0 | 141 | 49.67 | ast-js: 17, dependencies: 42, iac: 3, patterns: 2, secrets: 77 |
| dvwa | `d45ba3c4e7` | 0.7.0 | 4 | 23.58 | dependencies: 3, iac: 1 |
