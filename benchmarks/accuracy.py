#!/usr/bin/env python3
"""Labeled-corpus accuracy benchmark: real precision and recall, no downloads.

The main harness (``run_benchmarks.py``) clones large reference apps and reports
*finding inventories*, which catch regressions but cannot give precision/recall
without a ground-truth mapping. This file is the complement: a small, fully
labeled corpus that ships in the repo so the numbers are reproducible on any
machine with one command and no network.

Each case is a single file that is either **vulnerable** (Argus should raise at
least one actionable finding) or **safe** (Argus should raise none). From that we
compute, per domain and overall:

* **Recall**    = caught vulnerable cases / all vulnerable cases  (did we miss a bug?)
* **Precision** = caught vulnerable cases / (caught + findings on safe cases)

This is deliberately a *small, honest* set. It is not a substitute for the large
public corpora (Juice Shop, WebGoat, DVWA, NIST SARD), which the main harness
covers. It exists so every release has published, reproducible accuracy numbers,
and so a regression in either direction fails CI.

    python benchmarks/accuracy.py            # print the table
    python benchmarks/accuracy.py --json     # also write results/accuracy.json
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from argus.core.config import Config
from argus.core.engine import ScanEngine
from argus.core.models import Severity
from argus.core.project import Project
from argus.plugins import register_builtins

HERE = Path(__file__).resolve().parent
RESULTS_DIR = HERE / "results"

# Only actionable findings count, both for catching bugs and for false positives.
MIN_SEVERITY = Severity.LOW


@dataclass
class Case:
    name: str
    domain: str
    filename: str
    vulnerable: bool
    code: str


# --- the labeled corpus ----------------------------------------------------
# Vulnerable cases must fire at least one finding; safe cases must fire none.
CASES: list[Case] = [
    # secrets
    Case("secret-aws-key", "secrets", "config.py", True,
         'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
         'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'),
    Case("secret-placeholder", "secrets", "config.py", False,
         'AWS_ACCESS_KEY_ID = "REPLACE_WITH_YOUR_KEY"  # example placeholder\n'),

    # SAST: command execution through the shell
    Case("sast-shell-true", "sast", "run.py", True,
         'import subprocess\n'
         'def run(host):\n'
         '    subprocess.run("ping " + host, shell=True)\n'),
    Case("sast-shell-safe", "sast", "run.py", False,
         'import subprocess\n'
         'def run(host):\n'
         '    subprocess.run(["ping", host])\n'),

    # SAST: unsafe deserialization
    Case("sast-yaml-load", "sast", "load.py", True,
         'import yaml\n'
         'def load(raw):\n'
         '    return yaml.load(raw)\n'),
    Case("sast-yaml-safe", "sast", "load.py", False,
         'import yaml\n'
         'def load(raw):\n'
         '    return yaml.safe_load(raw)\n'),

    # SAST: weak hash
    Case("sast-weak-hash", "sast", "hash.py", True,
         'import hashlib\n'
         'def digest(pw):\n'
         '    return hashlib.md5(pw.encode()).hexdigest()\n'),
    Case("sast-strong-hash", "sast", "hash.py", False,
         'import hashlib\n'
         'def digest(pw):\n'
         '    return hashlib.sha256(pw.encode()).hexdigest()\n'),

    # Taint: SQL injection from a request parameter
    Case("taint-sql-injection", "taint", "view.py", True,
         'from flask import request\n'
         'def q(cursor):\n'
         '    uid = request.args.get("id")\n'
         '    cursor.execute("SELECT * FROM users WHERE id = \'%s\'" % uid)\n'),
    Case("taint-sql-parameterized", "taint", "view.py", False,
         'from flask import request\n'
         'def q(cursor):\n'
         '    uid = request.args.get("id")\n'
         '    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))\n'),

    # IaC: container hardening
    Case("iac-docker-latest-root", "iac", "Dockerfile", True,
         'FROM python:latest\n'
         'COPY . /app\n'
         'CMD ["python", "app.py"]\n'),
    Case("iac-docker-pinned-nonroot", "iac", "Dockerfile", False,
         'FROM python:3.12-slim\n'
         'RUN useradd --create-home app\n'
         'USER app\n'
         'COPY . /app\n'
         'CMD ["python", "app.py"]\n'),

    # LLM / AI security (OWASP Top 10 for LLM Apps). There is no standard public
    # benchmark for these classes, so this labeled set is itself a contribution.

    # LLM01 Prompt Injection: untrusted input concatenated into a prompt.
    Case("llm-prompt-injection", "llm", "ai.py", True,
         'import openai\n'
         'def ask(request):\n'
         '    prompt = "Summarize: " + request.args.get("q")\n'
         '    return openai.ChatCompletion.create(model="gpt-4", messages=[{"role": "user", "content": prompt}])\n'),
    Case("llm-prompt-injection-safe", "llm", "ai.py", False,
         'import openai\n'
         'def ask(request):\n'
         '    q = request.args.get("q")\n'
         '    return openai.ChatCompletion.create(model="gpt-4", messages=[{"role": "user", "content": q}])\n'),

    # LLM02 Insecure Output Handling: model output flows into eval().
    Case("llm-insecure-output", "llm", "ai.py", True,
         'import openai\n'
         'def run():\n'
         '    resp = openai.ChatCompletion.create(model="gpt-4", messages=[])\n'
         '    out = resp.choices[0].message.content\n'
         '    eval(out)\n'),
    Case("llm-insecure-output-safe", "llm", "ai.py", False,
         'import openai\n'
         'import json\n'
         'def run():\n'
         '    resp = openai.ChatCompletion.create(model="gpt-4", messages=[])\n'
         '    out = resp.choices[0].message.content\n'
         '    data = json.loads(out)\n'
         '    return data["answer"]\n'),

    # LLM05 Supply Chain: remote code + unsafe deserialization at model load.
    Case("llm-trust-remote-code", "llm", "ai.py", True,
         'from transformers import AutoModel\n'
         'm = AutoModel.from_pretrained("acme/x", trust_remote_code=True)\n'),
    Case("llm-torch-load-pickle", "llm", "ai.py", True,
         'import torch\n'
         'weights = torch.load("model.pt")\n'),
    Case("llm-torch-load-safe", "llm", "ai.py", False,
         'import torch\n'
         'weights = torch.load("model.pt", weights_only=True)\n'),

    # LLM06 Sensitive Information Disclosure: secret embedded in a prompt.
    Case("llm-secret-in-prompt", "llm", "ai.py", True,
         'import openai\n'
         'system_prompt = "You are a bot. Use API key sk-abcdef1234567890abcdef to authenticate."\n'),
    Case("llm-secret-in-prompt-safe", "llm", "ai.py", False,
         'import openai\n'
         'system_prompt = "You are a helpful assistant."\n'),

    # LLM08 Excessive Agency: agent wired to a shell-execution tool.
    Case("llm-agent-shell-tool", "llm", "ai.py", True,
         'from langchain.tools import ShellTool\n'
         'tool = ShellTool()\n'),
    Case("llm-agent-tool-safe", "llm", "ai.py", False,
         'from langchain.agents import initialize_agent\n'
         'agent = initialize_agent(tools=[], llm=None)\n'),
]


def _scan_case(case: Case) -> int:
    """Scan one case in isolation; return the count of actionable findings."""
    tmp = Path(tempfile.mkdtemp(prefix="argus-bench-"))
    try:
        (tmp / case.filename).write_text(case.code, encoding="utf-8")
        cfg = Config(scanner_options={"dependencies": {"online": False}})
        result = ScanEngine(cfg).scan(Project.from_path(tmp))
        return sum(1 for f in result.sorted_findings() if f.severity >= MIN_SEVERITY)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _rate(num: int, den: int) -> float:
    return num / den if den else 1.0


def main(write_json: bool = False) -> int:
    register_builtins()

    # Per-domain tallies: tp (caught vuln), fn (missed vuln), fp (findings on safe).
    domains: dict[str, dict[str, int]] = {}
    misses: list[str] = []
    false_pos: list[str] = []

    for case in CASES:
        d = domains.setdefault(case.domain, {"tp": 0, "fn": 0, "fp": 0})
        n = _scan_case(case)
        if case.vulnerable:
            if n > 0:
                d["tp"] += 1
            else:
                d["fn"] += 1
                misses.append(case.name)
        else:
            if n > 0:
                d["fp"] += n
                false_pos.append(f"{case.name} (+{n})")

    print("Argus AppSec, labeled-corpus accuracy")
    print("=" * 52)
    print(
        "NOTE: This is a small in-repo labeled corpus for regression detection only.\n"
        "      It is NOT a claim of real-world 100% accuracy on production codebases."
    )
    print(f"{'domain':<10} {'recall':>8} {'precision':>11} {'vuln':>6} {'safe-FP':>9}")
    print("-" * 52)
    tot = {"tp": 0, "fn": 0, "fp": 0}
    report: dict[str, object] = {
        "domains": {},
        "min_severity": MIN_SEVERITY.label,
        "scope": "labeled_corpus_v1",
        "disclaimer": (
            "Scores reflect a small in-repo labeled corpus used for regression "
            "detection only. They are not a claim of real-world accuracy on "
            "arbitrary production codebases."
        ),
    }
    for name in sorted(domains):
        d = domains[name]
        recall = _rate(d["tp"], d["tp"] + d["fn"])
        precision = _rate(d["tp"], d["tp"] + d["fp"])
        vuln = d["tp"] + d["fn"]
        print(f"{name:<10} {recall:>7.0%} {precision:>10.0%} {vuln:>6} {d['fp']:>9}")
        report["domains"][name] = {  # type: ignore[index]
            "recall": round(recall, 3), "precision": round(precision, 3),
            "vulnerable_cases": vuln, "false_positives": d["fp"],
        }
        for k in tot:
            tot[k] += d[k]

    overall_recall = _rate(tot["tp"], tot["tp"] + tot["fn"])
    overall_precision = _rate(tot["tp"], tot["tp"] + tot["fp"])
    print("-" * 52)
    print(f"{'OVERALL':<10} {overall_recall:>7.0%} {overall_precision:>10.0%} "
          f"{tot['tp'] + tot['fn']:>6} {tot['fp']:>9}")
    report["overall"] = {
        "recall": round(overall_recall, 3), "precision": round(overall_precision, 3),
        "vulnerable_cases": tot["tp"] + tot["fn"], "false_positives": tot["fp"],
    }
    if misses:
        print("\nMissed (false negatives):", ", ".join(misses))
    if false_pos:
        print("False positives on safe cases:", ", ".join(false_pos))

    if write_json:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        (RESULTS_DIR / "accuracy.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nWrote {RESULTS_DIR / 'accuracy.json'}")

    # Exit non-zero if the corpus is not perfectly classified, so CI can gate.
    return 0 if not misses and not false_pos else 1


if __name__ == "__main__":
    sys.exit(main(write_json="--json" in sys.argv))
