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

## Labeled LLM and agent corpus (`agent/`)

`agent/corpus/` holds small, realistic LLM-application and agent snippets
(OpenAI and Anthropic SDKs, LangChain, LlamaIndex, MCP servers, Vercel AI SDK,
plain HTTP fetches into prompts) in Python, JavaScript and TypeScript. Each
scenario is a vulnerable case and a safe case that does the same thing
correctly, labeled in `agent/corpus/manifest.json` with the OWASP Top 10 for
LLM Applications 2025 ids a correct report may carry, plus CWEs. The corpus
was written by a separate author who did not read the scanner code.

```bash
python benchmarks/agent/run.py                  # dev and held-out summary
python benchmarks/agent/run.py --details dev    # per-case outcomes, dev split
```

Scenarios are split into **dev** and **held-out** by a fixed rule: a scenario
is held out when the SHA-256 of its id is divisible by 3. The corpus and the
split were committed, with a baseline score, before any rule was written
against them, and rule work looked only at the dev split. A vulnerable case
counts as caught only when a finding from the `llm` or `agent-config` scanner
carries one of its expected OWASP ids; any such finding on a safe case is a
false positive. Results are in `agent/results/`.
