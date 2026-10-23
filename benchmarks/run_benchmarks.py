#!/usr/bin/env python3
"""Nephilex benchmark harness.

Runs Nephilex against known-vulnerable reference applications and records what it
finds and how long it takes, so precision/recall work has a reproducible
foundation and regressions in either signal or speed are visible per release.

Usage:

    python benchmarks/run_benchmarks.py                 # all corpora
    python benchmarks/run_benchmarks.py juice-shop      # one corpus

Corpora are shallow-cloned into ``benchmarks/.corpora/`` (gitignored) and the
exact commit is recorded in the results, so numbers are attributable to a
precise corpus state. Results land in ``benchmarks/results/<corpus>.json`` and
a combined ``benchmarks/results/SUMMARY.md``.

Notes on honest benchmarking:

* These are *finding inventories*, not precision/recall, that requires a
  ground-truth mapping per corpus (tracked in the corpus entry as
  ``ground_truth``; contributions welcome). Publishing the inventory is still
  useful: it shows coverage shape and catches per-release regressions.
* Scans run offline-deterministic (``--no-ai``, caching disabled) so numbers
  are comparable across machines and runs.
* NIST SARD/Juliet: the Python and Java cases require a manual download from
  https://samate.nist.gov/SARD/ (license click-through). Point the
  ``NEPHILEX_BENCH_SARD_DIR`` environment variable at the extracted directory and
  the ``sard-local`` corpus becomes available.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPORA_DIR = HERE / ".corpora"
RESULTS_DIR = HERE / "results"


@dataclass
class Corpus:
    name: str
    git_url: str | None = None  # None => local path via env var
    env_dir: str | None = None
    description: str = ""
    # Optional path to a ground-truth findings file for precision/recall.
    ground_truth: str | None = None
    scan_args: list[str] = field(default_factory=list)


CORPORA = [
    Corpus(
        name="juice-shop",
        git_url="https://github.com/juice-shop/juice-shop",
        description="OWASP Juice Shop, modern JS/TS web app, the standard "
        "deliberately-vulnerable target.",
    ),
    Corpus(
        name="dvwa",
        git_url="https://github.com/digininja/DVWA",
        description="Damn Vulnerable Web Application (PHP), exercises the "
        "secrets/deps/IaC layers on a non-Python/JS stack.",
    ),
    Corpus(
        name="webgoat",
        git_url="https://github.com/WebGoat/WebGoat",
        description="OWASP WebGoat (Java), exercises coverage on a JVM stack.",
    ),
    Corpus(
        name="sard-local",
        env_dir="NEPHILEX_BENCH_SARD_DIR",
        description="NIST SARD/Juliet cases (manual download; see module "
        "docstring). Ground-truth labels ship with the suite.",
    ),
]


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def _checkout(corpus: Corpus) -> tuple[Path, str]:
    """Return (path, commit-or-source-id) for a corpus, cloning if needed."""
    if corpus.env_dir:
        root = os.environ.get(corpus.env_dir, "")
        if not root or not Path(root).is_dir():
            raise FileNotFoundError(
                f"corpus '{corpus.name}' needs {corpus.env_dir} to point at a "
                "local directory (manual download)"
            )
        return Path(root), f"local:{root}"
    dest = CORPORA_DIR / corpus.name
    if not dest.exists():
        print(f"  cloning {corpus.git_url} (shallow)...")
        _run(["git", "clone", "--depth", "1", corpus.git_url, str(dest)])
    commit = _run(["git", "-C", str(dest), "rev-parse", "HEAD"]).stdout.strip()
    return dest, commit


def _scan(target: Path, extra_args: list[str]) -> tuple[dict, float]:
    out = CORPORA_DIR / "_scan.json"
    cmd = [
        sys.executable,
        "-m",
        "nephilex",
        "scan",
        str(target),
        "--no-ai",
        "--no-cache",
        "--quiet",
        "-f",
        "json",
        "-o",
        str(out),
        *extra_args,
    ]
    start = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.perf_counter() - start
    if proc.returncode not in (0, 1):  # 1 = fail-on threshold, still a report
        raise RuntimeError(f"nephilex scan failed ({proc.returncode}):\n{proc.stderr}")
    return json.loads(out.read_text(encoding="utf-8")), elapsed


def bench(corpus: Corpus) -> dict | None:
    print(f"[{corpus.name}] {corpus.description}")
    try:
        target, commit = _checkout(corpus)
    except FileNotFoundError as exc:
        print(f"  skipped: {exc}")
        return None
    report, elapsed = _scan(target, corpus.scan_args)
    findings = report.get("findings", [])
    result = {
        "corpus": corpus.name,
        "source": corpus.git_url or corpus.env_dir,
        "commit": commit,
        "nephilex_version": report.get("nephilex_version"),
        "scan_seconds": round(elapsed, 2),
        "total_findings": len(findings),
        "by_scanner": dict(Counter(f["scanner"] for f in findings)),
        "by_severity": dict(Counter(str(f["severity"]) for f in findings)),
        "ground_truth": corpus.ground_truth,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / f"{corpus.name}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(
        f"  {result['total_findings']} findings in {result['scan_seconds']}s "
        f"({result['by_scanner']})"
    )
    return result


def summarize(results: list[dict]) -> None:
    lines = [
        "# Nephilex benchmark summary",
        "",
        "Finding inventories on known-vulnerable corpora (not precision/recall "
        "yet, see run_benchmarks.py). Regenerate with "
        "`python benchmarks/run_benchmarks.py`.",
        "",
        "| Corpus | Commit | Nephilex | Findings | Time (s) | By scanner |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        by_scanner = ", ".join(f"{k}: {v}" for k, v in sorted(r["by_scanner"].items()))
        lines.append(
            f"| {r['corpus']} | `{str(r['commit'])[:10]}` | {r['nephilex_version']} "
            f"| {r['total_findings']} | {r['scan_seconds']} | {by_scanner} |"
        )
    (RESULTS_DIR / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nSummary written to {RESULTS_DIR / 'SUMMARY.md'}")


def main() -> int:
    wanted = set(sys.argv[1:])
    chosen = [c for c in CORPORA if not wanted or c.name in wanted]
    if not chosen:
        print(f"Unknown corpus. Available: {', '.join(c.name for c in CORPORA)}")
        return 2
    results = [r for c in chosen if (r := bench(c)) is not None]
    if results:
        summarize(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
