# Benchmarks & accuracy

A scanner's most important number is how accurate it is, and the most honest thing
a young scanner can do is publish that number with its methodology, and republish
it when it gets worse. Nephilex measures accuracy three ways: a small in-repo
labeled corpus, public labeled datasets scored side by side with Bandit and
Semgrep, and finding inventories on large reference apps.

## Labeled corpus (precision and recall)

A small, fully labeled corpus ships in the repo so the numbers are reproducible on
any machine with one command and no downloads:

```bash
python benchmarks/accuracy.py
```

Every case is a single file that is either **vulnerable** (Nephilex must raise at
least one actionable finding) or **safe** (Nephilex must raise none). From that:

- **Recall** = caught vulnerable cases / all vulnerable cases (did we miss a bug?)
- **Precision** = caught / (caught + findings on safe cases) (did we cry wolf?)

Current results:

| Domain | Recall | Precision | Vulnerable cases | Safe cases | False positives |
| --- | --- | --- | --- | --- | --- |
| secrets | 100% | 100% | 1 | 1 | 0 |
| sast | 100% | 100% | 6 | 7 | 0 |
| taint | 100% | 100% | 11 | 11 | 0 |
| iac | 100% | 100% | 1 | 1 | 0 |
| llm | 100% | 100% | 17 | 17 | 0 |
| mcp | 100% | 100% | 7 | 7 | 0 |
| **overall** | **100%** | **100%** | **43** | **44** | **0** |

!!! warning "Read this number honestly"
    This is a **small sanity-and-regression corpus** (43 vulnerable, 44 safe cases),
    not a claim of 100% real-world accuracy. 100% here means Nephilex classifies
    every case in this set correctly, and the run **exits non-zero if it does
    not**, so a regression fails CI. On independent public datasets the
    numbers are far lower; see the next section.

The **llm** rows are worth calling out: there is no standard public benchmark for
LLM/AI-application vulnerability classes (prompt injection, insecure model-output
handling, unsafe model loading, secrets in prompts, excessive agency). This
labeled set covers OWASP LLM01/02/05/06/08 with a vulnerable and a safe case each,
so the accuracy claim in Nephilex's strongest and least-crowded domain is measurable
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

## Public labeled datasets (Nephilex, Bandit, Semgrep)

The in-repo corpus is written by the same people who write the rules, so it
cannot tell you how Nephilex does on code it was not tuned for. For that, Nephilex is
scored on two independent, public, labeled Python datasets, next to Bandit and
Semgrep run on the same files and scored by the same code.

### Reproduce

```bash
pip install -e ".[ast]"                    # Nephilex with the AST tier
pip install bandit semgrep                 # ideally in a separate virtualenv
python benchmarks/public/run.py            # both datasets, all three tools
```

Useful variations:

```bash
python benchmarks/public/run.py --dataset owasp-python --tools nephilex,bandit,semgrep
python benchmarks/public/run.py --offline  # re-score cached outputs, no network, no tool runs
python benchmarks/public/run.py --bandit /path/to/bandit --semgrep /path/to/semgrep
```

`--bandit` and `--semgrep` (or the `NEPHILEX_BENCH_BANDIT` and `NEPHILEX_BENCH_SEMGREP`
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
| Nephilex | 0.9.2 plus the accuracy changes described below (the version string is unchanged until the next release) | `nephilex scan <root> --no-ai --no-cache -f json`: offline heuristic provider, default scanner set; the harness refuses to run if the `ast-python` tier is missing |
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
metadata says CWE-704, mapped to CWE-89). No Nephilex rule needed an override.
Overrides only add CWEs. Note that they cut both ways: Bandit's mapped OWASP
score is *lower* than its strict one, because the overrides credit rules that
also fire on safe cases.

### Results

Measured on 2026-10-22 after the changes listed under "What changed since
0.9.2". Bandit, Semgrep, the datasets and the Semgrep ruleset (same SHA-256) are
unchanged from the 0.9.2 run, and their numbers are identical to it.

!!! warning "How these Nephilex numbers were produced"
    Nephilex's Python rules were revised **with OWASP BenchmarkPython visible**:
    the cases Nephilex got wrong in 0.9.2 were read, and general rules were
    written for the idioms behind them. No OWASP case was held out, so the
    OWASP rows below measure Nephilex on code it was developed against, not on
    unseen code. The checks under "Methodology checks" are the evidence on
    generalisation; read them before quoting a number.

OWASP Benchmark for Python v0.1, all 1230 cases:

| Tool | Mode | TP | FP | TN | FN | TPR | FPR | Precision | F1 | Score (pooled) | Score (category avg) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Nephilex | mapped | 447 | 74 | 704 | 5 | 98.9% | 9.5% | 85.8% | 91.9% | +89.4 | +91.3 |
| Nephilex | strict | 356 | 62 | 716 | 96 | 78.8% | 8.0% | 85.2% | 81.8% | +70.8 | +79.6 |
| Nephilex 0.9.2 | mapped | 78 | 30 | 748 | 374 | 17.3% | 3.9% | 72.2% | 27.9% | +13.4 | +6.3 |
| Nephilex 0.9.2 | strict | 37 | 24 | 754 | 415 | 8.2% | 3.1% | 60.7% | 14.4% | +5.1 | +2.4 |
| Bandit | mapped | 130 | 79 | 699 | 322 | 28.8% | 10.2% | 62.2% | 39.3% | +18.6 | +7.5 |
| Bandit | strict | 101 | 25 | 753 | 351 | 22.4% | 3.2% | 80.2% | 34.9% | +19.1 | +8.2 |
| Semgrep | mapped | 73 | 15 | 763 | 379 | 16.2% | 1.9% | 83.0% | 27.0% | +14.2 | +6.0 |
| Semgrep | strict | 18 | 15 | 763 | 434 | 4.0% | 1.9% | 54.5% | 7.4% | +2.1 | -0.8 |

Per category, mapped mode, as TPR / FPR (score):

| Category | CWE | Cases (vuln/safe) | Nephilex | Nephilex 0.9.2 | Bandit | Semgrep |
| --- | --- | --- | --- | --- | --- | --- |
| cmdi | 78 | 13/7 | 100.0% / 14.3% (+85.7) | 53.8% / 100.0% (-46.2) | 100.0% / 100.0% (+0.0) | 53.8% / 100.0% (-46.2) |
| codeinj | 94 | 20/33 | 100.0% / 36.4% (+63.6) | 20.0% / 18.2% (+1.8) | 95.0% / 90.9% (+4.1) | 0.0% / 0.0% (+0.0) |
| deserialization | 502 | 18/36 | 100.0% / 19.4% (+80.6) | 100.0% / 33.3% (+66.7) | 83.3% / 30.6% (+52.8) | 50.0% / 16.7% (+33.3) |
| hash | 328 | 71/80 | 100.0% / 0.0% (+100.0) | 52.1% / 0.0% (+52.1) | 0.0% / 0.0% (+0.0) | 76.1% / 0.0% (+76.1) |
| ldapi | 90 | 16/13 | 100.0% / 0.0% (+100.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) |
| pathtraver | 22 | 65/103 | 92.3% / 15.5% (+76.8) | 18.5% / 4.9% (+13.6) | 0.0% / 0.0% (+0.0) | 3.1% / 1.9% (+1.1) |
| redirect | 601 | 13/21 | 100.0% / 0.0% (+100.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) |
| securecookie | 614 | 24/15 | 100.0% / 0.0% (+100.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) |
| sqli | 89 | 5/11 | 100.0% / 0.0% (+100.0) | 0.0% / 0.0% (+0.0) | 100.0% / 100.0% (+0.0) | 20.0% / 0.0% (+20.0) |
| trustbound | 501 | 18/19 | 100.0% / 0.0% (+100.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) |
| weakrand | 330 | 99/227 | 100.0% / 0.0% (+100.0) | 0.0% / 0.0% (+0.0) | 72.7% / 0.0% (+72.7) | 0.0% / 0.0% (+0.0) |
| xpathi | 643 | 51/135 | 100.0% / 28.1% (+71.9) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) |
| xss | 79 | 31/58 | 100.0% / 0.0% (+100.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) | 0.0% / 0.0% (+0.0) |
| xxe | 611 | 8/20 | 100.0% / 0.0% (+100.0) | 0.0% / 0.0% (+0.0) | 75.0% / 100.0% (-25.0) | 0.0% / 0.0% (+0.0) |

SecurityEval v2.1, 121 samples, recall only:

| Tool | Mode | Detected | Recall | CWE-average recall | CWEs with a detection |
| --- | --- | --- | --- | --- | --- |
| Nephilex | mapped | 32/121 | 26.5% | 18.4% | 17/69 |
| Nephilex | strict | 26/121 | 21.5% | 13.4% | 13/69 |
| Nephilex | any | 51/121 | 42.1% | 34.4% | 30/69 |
| Nephilex 0.9.2 | mapped | 12/121 | 9.9% | 7.0% | 9/69 |
| Nephilex 0.9.2 | strict | 8/121 | 6.6% | 3.9% | 6/69 |
| Nephilex 0.9.2 | any | 22/121 | 18.2% | 15.5% | 18/69 |
| Bandit | mapped | 32/121 | 26.5% | 23.3% | 21/69 |
| Bandit | strict | 23/121 | 19.0% | 15.9% | 15/69 |
| Bandit | any | 49/121 | 40.5% | 39.6% | 34/69 |
| Semgrep | mapped | 13/121 | 10.7% | 8.1% | 8/69 |
| Semgrep | strict | 10/121 | 8.3% | 5.7% | 6/69 |
| Semgrep | any | 23/121 | 19.0% | 18.2% | 17/69 |

The per-CWE SecurityEval table is in `benchmarks/results/public/SUMMARY.md`.

### Methodology checks

**Corpus-specific keying.** No rule refers to a benchmark file name, test id,
helper module or function (`helpers.*`, the benchmark's request wrapper or
HTML-escape helper), variable name, comment, or the expected-results CSV. An
audit before publishing removed three things that were closer to the
benchmark's own "safe" idioms than to general mitigations: the blocklist
guards `'../' in p` (path traversal) and "contains no quote" (XPath), the
`.replace("'", ...)` XPath sanitizer and the "quoted literal only" check
before `eval`. Those blocklists are incomplete in general (an absolute path or
another quoting style gets past them), so the engine no longer trusts them.
That costs 66 OWASP false positives (16 path traversal, 38 XPath, 12 code
injection), which are in the table above. `os.path.exists` and other
existence checks were also dropped as path sinks after the false-positive
check below, which costs 5 path-traversal true positives. One rule that is
correct but was motivated by the benchmark stays and is documented:
`request.path` is not a source in a Flask view whose routes have no
`<converters>`, because routing has already fixed the path.

**Split halves (not a held-out test).** The OWASP score is stable across
halves, but both halves were visible during development, so this shows the
rules are not keyed to individual cases, not that they generalise:

| Split | Cases | Mapped score (pooled) | Mapped score (category avg) | Strict score (pooled) |
| --- | --- | --- | --- | --- |
| even test numbers | 615 | +89.4 | +92.2 | +71.5 |
| odd test numbers | 615 | +89.4 | +89.0 | +70.1 |
| random half A (seed 20261022) | 611 | +88.8 | +92.7 | +70.9 |
| random half B | 619 | +90.0 | +90.2 | +70.7 |

**SecurityEval (a different corpus).** Mapped recall went from 12/121 (9.9%)
in 0.9.2 to 32/121 (26.5%). Five of the 32 come from rules added after reading
SecurityEval's misses (`compile()` as a code sink, a redirect through
`headers["Location"]`, and lxml `resolve_entities=True`, three samples); the
SQL-from-a-parameter rule was written for a SecurityEval sample named in the
task (`CWE-089_author_1.py`). Without the five post-hoc detections the figure
is 27/121 (22.3%). That is the better estimate of how the OWASP-driven work
transfers to code it was not developed on: a large gain over 0.9.2, still
behind Bandit on CWE-average recall (23.3%) and CWE breadth (21 CWEs).

**False positives on code with no known vulnerabilities.** The SAST, taint and
auth scanners (`ast-python`, `ast-python-xfile`, `patterns`, `authz`) were run
on Flask 3.0.3's tutorial and JavaScript example apps, the Flask 3.0.3 and
Werkzeug 3.0.3 sources, and the installed click, requests, jinja2, rich and
typer packages. Findings at severity low or above, 0.9.2 scanners against
these changes:

| Project | 0.9.2 | Now | New findings |
| --- | --- | --- | --- |
| Flask tutorial app (flaskr) | 0 | 0 | |
| Flask JavaScript example | 0 | 0 | |
| Flask 3.0.3 | 3 | 3 | none (the same 3: `PYTHONSTARTUP` read and executed by `flask shell`, SHA-1 in sessions) |
| Werkzeug 3.0.3 | 6 | 7 | `subprocess.call(args)` re-executing `sys.argv` in the reloader |
| click | 1 | 0 | (0.9.2 flagged the editor launch because its `env=` mapping copies `os.environ`; only the command argument is a sink now) |
| requests | 0 | 0 | |
| jinja2 | 1 | 1 | none |
| rich | 0 | 1 | `pty.spawn(sys.argv[1:])` in a demo entry point |
| typer | 0 | 0 | |

The two new findings come from treating `sys.argv`
as an untrusted source, which Nephilex already did in 0.9.2; the new
engine simply follows those flows further. Earlier drafts of this change were
noisier on these projects (`eval`/`exec` of a function parameter in template
engines, `os.path.exists` on environment paths, `x.open()` on test clients,
`http.cookiejar` `set_cookie(cookie)` and `set_cookie(..., **kwargs)`); those
rules were removed or narrowed before publishing.

### What changed since 0.9.2

Each fix below is a general rule meant to hold on real code. Details per rule
are in [Scanners](scanners.md).

- **Flow-sensitive taint.** Branches, `match`, loops and `try` are analyzed
  separately and joined, so `if not p: p = ""` keeps the taint (the idiom
  behind 41 of the 80 false negatives in 0.9.2). Conditions that fold to a
  constant prune the dead branch. Literal dicts, lists and `configparser`
  objects are tracked per key.
- **Guards.** Early returns on complete mitigations refine the value after
  them: allowlist membership, `isdigit()`-style checks, a
  `urlparse(u).netloc` allowlist, and a resolved-path containment check.
- **Sources.** Methods that return request data (request wrappers) are sources
  when called on an object built from the request, in the same file or across
  files. `request.path` is not a source in a view whose routes have no
  converters.
- **New Python rules.** Reflected XSS from view return values and `Markup`,
  `|safe` in templates, open redirect, XXE with external entities enabled,
  LDAP and XPath injection, trust boundary (session stores), weak randomness
  for tokens and session values, `hashlib.new("md5")`, pathlib file access,
  `compile()` as a code sink, and `set_cookie()` without `secure=True`
  (CWE-614) or `httponly=True` (CWE-1004).
- **Fewer sink-only findings.** `shell=True`, `os.system` and `pickle.loads`
  whose payload is built only from literals are no longer reported.
  `yaml.load` with an unsafe loader is still reported, graded by taint.
- **Function parameters.** SQL built by formatting a function parameter is
  reported at low confidence. The regex tier used to catch some of these, but
  the engine dropped its CWE-89 findings wherever the taint tier ran.

### What the numbers say

- **On OWASP BenchmarkPython Nephilex now scores +89.4 pooled and +91.3 by
  category average (mapped)**, against +18.6 and +7.5 for Bandit and +14.2 and
  +6.0 for Semgrep. Because the rules were developed with this dataset visible
  and it is generated from a small set of templates, read this as "Nephilex
  handles the idioms in this benchmark", not as a real-world detection rate.
- **The 74 false positives** are 66 cases guarded only by blocklist checks that
  Nephilex deliberately does not trust (see above), 5 `yaml.load(...,
  Loader=yaml.Loader)` calls on a constant document (an unsafe loader is still
  reported, at low severity, because it is wrong code even when today's input
  is constant), and 3 payloads that come from a wrapper method in another file
  returning a constant, which the regex tier, grading one file at a time,
  cannot see.
- **Strict mode** (+70.8) is lower mainly because Nephilex reports MD5/SHA-1 as
  CWE-327 against the benchmark's CWE-328 label (71 cases) and `eval`/`exec`
  as CWE-95 against its parent CWE-94 (20 cases); the other 5 misses are the
  path-traversal cases whose only sink is an existence check.
- **On SecurityEval Nephilex ties Bandit on mapped recall (32 samples each)** but
  trails it on CWE-average recall (18.4% vs 23.3%) and CWE breadth (17 vs 21
  CWEs). Without the detections from rules added after reading SecurityEval,
  Nephilex is at 27 samples. SecurityEval covers many classes Nephilex has no Python
  rule for (hard-coded passwords as CWE-259, log injection, temporary files,
  regex DoS, SSRF), and most samples are helper functions with no web request.

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
  require a proven untrusted source (the Nephilex taint tier) relative to tools
  that flag sinks unconditionally (Bandit).
- **CWE mapping caveats.** Tools pick different CWEs for the same issue (MD5 is
  CWE-327 in Bandit, Semgrep and Nephilex, but the benchmark label is CWE-328), so
  `strict` understates every tool and `mapped` depends on the committed groups
  and overrides. Both are published; the mapping tables are embedded in each
  results file.
- **Python only.** These datasets measure the Python SAST and taint tiers. They
  say nothing about Nephilex's JavaScript/TypeScript tiers, secrets, dependency,
  IaC, container or LLM-application scanners.
- **Default configurations only.** Semgrep was run with the `p/python` registry
  ruleset on the Community Edition engine (no cross-file Pro analysis); another
  ruleset (for example `p/default`) or Semgrep Pro would give different numbers.
  Nephilex was run without an AI provider (`--no-ai`), so AI triage is not measured.
  Bandit and Semgrep were not tuned for these datasets. Nephilex's rules were
  revised after studying its OWASP misses, with no case held out (see
  "Methodology checks"); no rule refers to a benchmark file, test id,
  helper or generated name.
- **Single run, single machine.** All three tools are deterministic for a fixed
  input, but the runs were made once, on Windows. Nephilex's default scanner set
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
regressions in what Nephilex finds and how fast.

## Methodology and honesty notes

- Runs are deterministic and offline (`--no-ai`, caching disabled) so numbers are
  comparable across machines.
- Numbers that get worse are published anyway. A benchmark that only ever improves
  is marketing, not measurement.
- The labeled corpus is intentionally small and unambiguous. Growing it (more
  languages, more classes, adversarial safe cases) directly improves the quality
  signal, and pull requests that add labeled cases are among the most valuable
  contributions to the project.
