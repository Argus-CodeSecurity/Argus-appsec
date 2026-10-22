# Benchmarks & accuracy

A scanner's most important number is how accurate it is, and the most honest thing
a young scanner can do is publish that number with its methodology, and republish
it when it gets worse. Argus AppSec measures accuracy three ways: a small in-repo
labeled corpus, public labeled datasets scored side by side with Bandit and
Semgrep, and finding inventories on large reference apps.

## Labeled corpus (precision and recall)

A small, fully labeled corpus ships in the repo so the numbers are reproducible on
any machine with one command and no downloads:

```bash
python benchmarks/accuracy.py
```

Every case is a single file that is either **vulnerable** (Argus must raise at
least one actionable finding) or **safe** (Argus must raise none). From that:

- **Recall** = caught vulnerable cases / all vulnerable cases (did we miss a bug?)
- **Precision** = caught / (caught + findings on safe cases) (did we cry wolf?)

Current results:

| Domain | Recall | Precision | Vulnerable cases | False positives |
| --- | --- | --- | --- | --- |
| secrets | 100% | 100% | 1 | 0 |
| sast | 100% | 100% | 3 | 0 |
| taint | 100% | 100% | 1 | 0 |
| iac | 100% | 100% | 1 | 0 |
| llm | 100% | 100% | 6 | 0 |
| **overall** | **100%** | **100%** | **12** | **0** |

!!! warning "Read this number honestly"
    This is a **small sanity-and-regression corpus** (12 vulnerable, 11 safe cases),
    not a claim of 100% real-world accuracy. 100% here means Argus classifies
    every case in this set correctly, and the run **exits non-zero if it does
    not**, so a regression fails CI. On independent public datasets the
    numbers are far lower; see the next section.

The **llm** rows are worth calling out: there is no standard public benchmark for
LLM/AI-application vulnerability classes (prompt injection, insecure model-output
handling, unsafe model loading, secrets in prompts, excessive agency). This
labeled set covers OWASP LLM01/02/05/06/08 with a vulnerable and a safe case each,
so the accuracy claim in Argus's strongest and least-crowded domain is measurable
and reproducible rather than asserted.

This corpus already earned its keep: building it surfaced two real bugs, both now
fixed and covered by regression tests:

- A false **negative**: `subprocess(..., shell=True)` was being dropped by the
  engine whenever the AST taint tier ran, because that tier does not model a
  taint-independent smell. Command-execution findings now survive.
- A false **positive**: a properly parameterized query
  `execute("... %s", (uid,))` was flagged as SQL injection because a tainted value
  in the bound-parameters argument counted. Bound parameters are now recognized as
  the safe form.

## Public labeled datasets (Argus, Bandit, Semgrep)

The in-repo corpus is written by the same people who write the rules, so it
cannot tell you how Argus does on code it was not tuned for. For that, Argus is
scored on two independent, public, labeled Python datasets, next to Bandit and
Semgrep run on the same files and scored by the same code.

### Reproduce

```bash
pip install -e ".[ast]"                    # Argus with the AST tier
pip install bandit semgrep                 # ideally in a separate virtualenv
python benchmarks/public/run.py            # both datasets, all three tools
```

Useful variations:

```bash
python benchmarks/public/run.py --dataset owasp-python --tools argus,bandit,semgrep
python benchmarks/public/run.py --offline  # re-score cached outputs, no network, no tool runs
python benchmarks/public/run.py --bandit /path/to/bandit --semgrep /path/to/semgrep
```

`--bandit` and `--semgrep` (or the `ARGUS_BENCH_BANDIT` and `ARGUS_BENCH_SEMGREP`
environment variables) point at tools installed outside the current environment.
A tool that cannot be found is recorded as `not_run` with the reason; no numbers
are produced for it.

Outputs:

- `benchmarks/results/public/<dataset>.json`: dataset commit and archive hash,
  tool versions, run dates, command lines, the CWE mapping tables used, per-rule
  CWE inventory, and per-category and overall metrics for every tool and mode,
  including the list of false-positive and false-negative case ids.
- `benchmarks/results/public/SUMMARY.md`: generated tables.
- `benchmarks/results/public/findings/<dataset>/<tool>.json`: every finding
  normalized to file, line, rule id and CWEs (no source code), so the scoring
  can be audited or re-run with `--offline` without installing the tools.
- `benchmarks/.corpora/` (git-ignored): the downloaded datasets, the cached
  Semgrep ruleset and each tool's raw JSON output.

### Datasets

| Dataset | Pinned commit | Content | Labels |
| --- | --- | --- | --- |
| [OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython) v0.1 | `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` | 1230 Flask test cases in 14 CWE categories | `expectedresults-0.1.csv`: 452 vulnerable, 778 safe |
| [SecurityEval](https://github.com/s2e-lab/SecurityEval) v2.1 | `6f4fb70f782c6d47b02ea24341e8ef8c1eb04a6a` | 121 short Python samples (`dataset.jsonl`, field `Insecure_code`) | one CWE per sample, 69 CWEs, all vulnerable |

Datasets are downloaded as GitHub archives of the pinned commit. The archive's
SHA-256 is recorded; GitHub does not promise byte-stable archives, so a hash
change is reported as a warning while the commit pin fixes the content.

### Tools and settings

| Tool | Version measured | Configuration |
| --- | --- | --- |
| Argus | 0.9.2 | `argus scan <root> --no-ai --no-cache -f json`: offline heuristic provider, default scanner set; the harness refuses to run if the `ast-python` tier is missing |
| Bandit | 1.9.4 | `bandit -r <root> -f json`: default plugins, all severities and confidences |
| Semgrep | 1.182.1 (Community Edition) | `semgrep scan --config p/python --metrics=off --no-git-ignore --json`: registry ruleset `p/python`, 151 rules, cached locally with its SHA-256 recorded because registry rulesets are not version-pinned |

Semgrep needs `--no-git-ignore` only because the corpora sit in a git-ignored
directory of this repository; without it Semgrep skips every file. All findings
each tool emits count, at every severity; no tool gets a severity or confidence
filter. Runs were made on Windows 11 with Python 3.11 on 2026-10-22.

### Scoring

**OWASP BenchmarkPython** follows the OWASP Benchmark methodology. A test case is
*flagged* when the tool reports at least one finding in that test case's source
file (`testcode/BenchmarkTestNNNNN.py`) whose CWE matches the case's CWE. Findings
in that file with a different CWE are ignored for that case; findings in helpers
and templates are ignored. Flagged vulnerable case = TP, flagged safe case = FP,
unflagged safe = TN, unflagged vulnerable = FN. Per category and overall:
TPR (recall), FPR, precision, F1 and the OWASP score, TPR - FPR. Overall
numbers are given two ways: *pooled* (counts summed over all 1230 cases, which
weights large categories such as weakrand with 326 cases) and *category average*
(unweighted mean of the per-category TPR, FPR and score, as on the official
OWASP scorecard).

**SecurityEval** has no safe samples, so only recall can be measured. Precision,
FPR and F1 are undefined and are not reported. A sample is detected when the
tool reports a finding in its file with a matching CWE; the `any` mode also
reports how many samples got any finding at all, whatever its CWE.

**CWE matching** comes in two modes, both always published:

- `strict`: one of the tool's own reported CWEs equals the labeled CWE.
- `mapped`: the tool's CWEs, plus documented per-rule overrides, intersect an
  equivalence group containing the label. The groups join parent and child
  CWEs (for example 327/328/916 for weak hashing, 22/23/36/73/99 for path
  traversal, 94/95 for code injection, 330/331/338 for weak randomness). They
  are in `benchmarks/public/mapping.py` and apply to every tool equally.

Manual overrides exist only where a tool reports a generic or wrong CWE for a
rule with a single documented purpose. After auditing the per-rule inventory,
the overrides are: Bandit's XML blacklist rules B313 to B320 and B405 to B410
(reported as CWE-20, mapped to CWE-611), B506 `yaml_load` (CWE-20 to CWE-502),
B102 `exec_used` and B307 `eval` (reported as CWE-78, mapped to CWE-95), and
Semgrep's `python.flask.security.injection.tainted-sql-string` (registry
metadata says CWE-704, mapped to CWE-89). No Argus rule needed an override.
Overrides only add CWEs. Note that they cut both ways: Bandit's mapped OWASP
score is *lower* than its strict one, because the overrides credit rules that
also fire on safe cases.

### Results

OWASP Benchmark for Python v0.1, all 1230 cases:

| Tool | Mode | TP | FP | TN | FN | TPR | FPR | Precision | F1 | Score (pooled) | Score (category avg) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Argus | mapped | 78 | 30 | 748 | 374 | 17.3% | 3.9% | 72.2% | 27.9% | +13.4 | +6.3 |
| Argus | strict | 37 | 24 | 754 | 415 | 8.2% | 3.1% | 60.7% | 14.4% | +5.1 | +2.4 |
| Bandit | mapped | 130 | 79 | 699 | 322 | 28.8% | 10.2% | 62.2% | 39.3% | +18.6 | +7.5 |
| Bandit | strict | 101 | 25 | 753 | 351 | 22.4% | 3.2% | 80.2% | 34.9% | +19.1 | +8.2 |
| Semgrep | mapped | 73 | 15 | 763 | 379 | 16.2% | 1.9% | 83.0% | 27.0% | +14.2 | +6.0 |
| Semgrep | strict | 18 | 15 | 763 | 434 | 4.0% | 1.9% | 54.5% | 7.4% | +2.1 | -0.8 |

Per category, mapped mode, as TPR / FPR (score):

| Category | CWE | Cases (vuln/safe) | Argus | Bandit | Semgrep |
| --- | --- | --- | --- | --- | --- |
| cmdi | 78 | 13/7 | 53.8% / 100.0% (-46.2) | 100.0% / 100.0% (+0.0) | 53.8% / 100.0% (-46.2) |
| codeinj | 94 | 20/33 | 20.0% / 18.2% (+1.8) | 95.0% / 90.9% (+4.1) | 0.0% / 0.0% (+0.0) |
| deserialization | 502 | 18/36 | 100.0% / 33.3% (+66.7) | 83.3% / 30.6% (+52.8) | 50.0% / 16.7% (+33.3) |
| hash | 328 | 71/80 | 52.1% / 0.0% (+52.1) | 0.0% / 0.0% (+0.0) | 76.1% / 0.0% (+76.1) |
| ldapi | 90 | 16/13 | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) |
| pathtraver | 22 | 65/103 | 18.5% / 4.9% (+13.6) | 0.0% / 0.0% (+0.0) | 3.1% / 1.9% (+1.1) |
| redirect | 601 | 13/21 | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) |
| securecookie | 614 | 24/15 | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) |
| sqli | 89 | 5/11 | 0.0% / 0.0% (+0.0) | 100.0% / 100.0% (+0.0) | 20.0% / 0.0% (+20.0) |
| trustbound | 501 | 18/19 | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) |
| weakrand | 330 | 99/227 | 0.0% / 0.0% (+0.0) | 72.7% / 0.0% (+72.7) | 0.0% / 0.0% (+0.0) |
| xpathi | 643 | 51/135 | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) |
| xss | 79 | 31/58 | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) |
| xxe | 611 | 8/20 | 0.0% / 0.0% (+0.0) | 75.0% / 100.0% (-25.0) | 0.0% / 0.0% (+0.0) |

SecurityEval v2.1, 121 samples, recall only:

| Tool | Mode | Detected | Recall | CWE-average recall | CWEs with a detection |
| --- | --- | --- | --- | --- | --- |
| Argus | mapped | 12/121 | 9.9% | 7.0% | 9/69 |
| Argus | strict | 8/121 | 6.6% | 3.9% | 6/69 |
| Argus | any | 22/121 | 18.2% | 15.5% | 18/69 |
| Bandit | mapped | 32/121 | 26.5% | 23.3% | 21/69 |
| Bandit | strict | 23/121 | 19.0% | 15.9% | 15/69 |
| Bandit | any | 49/121 | 40.5% | 39.6% | 34/69 |
| Semgrep | mapped | 13/121 | 10.7% | 8.1% | 8/69 |
| Semgrep | strict | 10/121 | 8.3% | 5.7% | 6/69 |
| Semgrep | any | 23/121 | 19.0% | 18.2% | 17/69 |

The per-CWE SecurityEval table is in `benchmarks/results/public/SUMMARY.md`.

### What the numbers say

- **Argus loses to Bandit on both datasets.** On OWASP BenchmarkPython, Bandit's
  score is higher pooled (+18.6 vs +13.4 mapped) and by category average (+7.5
  vs +6.3). On SecurityEval, Bandit's mapped recall is 26.5% against Argus's
  9.9%. Argus and Semgrep `p/python` are close to each other on both.
- **Argus has the best score in two categories:** path traversal (+13.6, against
  +1.1 for Semgrep and 0 for Bandit) and deserialization (+66.7, against +52.8
  for Bandit). Semgrep is best on weak
  hashing (+76.1 vs +52.1 for Argus), Bandit on weak randomness (+72.7; Argus
  has no weak-random rule).
- **Argus detects nothing in 9 of the 14 OWASP categories.** For seven of them
  it has no Python rule today (LDAP, XPath and XML entity injection, reflected
  XSS, open redirect, trust boundary, weak randomness). For the insecure-cookie
  category a rule exists but its pattern does not match Flask's
  `response.set_cookie(..., secure=False)`. For SQL injection the taint rule
  exists but lost the flow in all 5 vulnerable cases. Semgrep `p/python` also
  detects nothing in eight of these nine; Bandit detects weak randomness, XXE and
  (with a 100% false-positive rate) SQL injection.
- **Argus's taint tier loses many flows** it should follow (see the case ids in
  the results file); a single idiom, `if not param: param = ""`, appears in 41 of
  its 80 false negatives in the cmdi, codeinj, pathtraver and sqli categories.
- **Argus's false positives are concentrated** in rules that fire on a sink
  regardless of data flow (`shell=True`, `pickle.loads`, `yaml.load`), which flag
  every safe case in cmdi and a third of the safe deserialization cases.

### Limitations

- **Labeled-dataset bias.** OWASP BenchmarkPython is synthetic: every case is
  generated from templates, uses Flask, and contains deliberate traps (dead
  branches, constant conditions, overwritten values) that reward or punish
  specific analysis features. Category sizes are uneven (326 weakrand cases,
  16 sqli cases), which dominates the pooled numbers; the category average is
  published for that reason. Real applications look different.
- **SecurityEval has no negatives,** so it cannot measure false positives at all,
  and most CWEs have one to six samples. Many samples are snippets whose input
  is a function parameter rather than a web request, which penalizes tools that
  require a proven untrusted source (the Argus taint tier) relative to tools
  that flag sinks unconditionally (Bandit).
- **CWE mapping caveats.** Tools pick different CWEs for the same issue (MD5 is
  CWE-327 in Bandit, Semgrep and Argus, but the benchmark label is CWE-328), so
  `strict` understates every tool and `mapped` depends on the committed groups
  and overrides. Both are published; the mapping tables are embedded in each
  results file.
- **Python only.** These datasets measure the Python SAST and taint tiers. They
  say nothing about Argus's JavaScript/TypeScript tiers, secrets, dependency,
  IaC, container or LLM-application scanners.
- **Default configurations only.** Semgrep was run with the `p/python` registry
  ruleset on the Community Edition engine (no cross-file Pro analysis); another
  ruleset (for example `p/default`) or Semgrep Pro would give different numbers.
  Argus was run without an AI provider (`--no-ai`), so AI triage is not measured.
  No tool was tuned for these datasets.
- **Single run, single machine.** All three tools are deterministic for a fixed
  input, but the runs were made once, on Windows. Argus's default scanner set
  includes a dependency scanner that may query OSV for the dataset's
  `requirements.txt`; those findings fall outside the test cases and do not
  affect the scores.

## Public reference apps (finding inventory)

The larger harness scans real, known-vulnerable applications:

```bash
python benchmarks/run_benchmarks.py            # all available corpora
python benchmarks/run_benchmarks.py juice-shop # just one
```

It publishes a **finding inventory** (counts by scanner and severity, plus scan
time) for OWASP Juice Shop, DVWA, WebGoat, and (with a manual download) NIST
SARD/Juliet. An inventory is not precision/recall, it needs a ground-truth
mapping per corpus, which is tracked as a `ground_truth` hook and where
contributions are welcome, but it shows coverage shape and catches per-release
regressions in what Argus finds and how fast.

## Methodology and honesty notes

- Runs are deterministic and offline (`--no-ai`, caching disabled) so numbers are
  comparable across machines.
- Numbers that get worse are published anyway. A benchmark that only ever improves
  is marketing, not measurement.
- The labeled corpus is intentionally small and unambiguous. Growing it (more
  languages, more classes, adversarial safe cases) directly improves the quality
  signal, and pull requests that add labeled cases are among the most valuable
  contributions to the project.
