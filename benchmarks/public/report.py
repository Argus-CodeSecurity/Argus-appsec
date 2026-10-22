"""Generate ``benchmarks/results/public/SUMMARY.md`` from the results JSON files."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.public.tools import TOOLS


def pct(x: object) -> str:
    """Percentage with one decimal, or ``n/a`` for an undefined metric."""
    if x is None:
        return "n/a"
    return f"{float(x) * 100:.1f}%"  # type: ignore[arg-type]


def signed(x: object) -> str:
    if x is None:
        return "n/a"
    return f"{float(x) * 100:+.1f}"  # type: ignore[arg-type]


def _ok_tools(doc: dict) -> list[str]:
    return [t for t in TOOLS if doc["tools"].get(t, {}).get("status") == "ok"]


def _run_lines(doc: dict) -> list[str]:
    lines = ["| Tool | Version | Run date (UTC) | Seconds | Command |", "|---|---|---|---|---|"]
    for tool in TOOLS:
        entry = doc["tools"].get(tool)
        if not entry:
            continue
        if entry.get("status") != "ok":
            lines.append(f"| {tool} | not run | | | {entry.get('reason', '')} |")
            continue
        run = entry["run"]
        cmd = " ".join(run.get("command", []))
        lines.append(
            f"| {tool} | {run.get('version')} | {run.get('started_at')} | "
            f"{run.get('seconds')} | `{cmd}` |"
        )
    semgrep = doc["tools"].get("semgrep", {})
    if semgrep.get("status") == "ok":
        run = semgrep["run"]
        lines.append("")
        lines.append(
            f"Semgrep ruleset `{run.get('ruleset')}`: {run.get('ruleset_rules')} rules, "
            f"sha256 `{str(run.get('ruleset_sha256'))[:16]}...`, fetched "
            f"{run.get('ruleset_fetched_at')}."
        )
    return lines


def owasp_section(doc: dict) -> list[str]:
    ds = doc["dataset"]
    ok = _ok_tools(doc)
    lines = [
        f"## {ds['title']}",
        "",
        f"Commit `{ds['commit']}`, {ds['cases']} test cases ({ds['vulnerable_cases']} "
        f"vulnerable, {ds['safe_cases']} safe) in {ds['categories']} CWE categories. "
        "Score = TPR - FPR (OWASP Benchmark). Pooled = counts summed over all cases; "
        "category average = unweighted mean over categories (the official scorecard).",
        "",
        "| Tool | Mode | TP | FP | TN | FN | TPR | FPR | Precision | F1 "
        "| Score (pooled) | Score (category avg) |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for tool in ok:
        for mode in ("mapped", "strict"):
            o = doc["tools"][tool]["metrics"][mode]["overall"]
            lines.append(
                f"| {tool} | {mode} | {o['tp']} | {o['fp']} | {o['tn']} | {o['fn']} "
                f"| {pct(o['tpr'])} | {pct(o['fpr'])} | {pct(o['precision'])} "
                f"| {pct(o['f1'])} | {signed(o['score'])} "
                f"| {signed(o['category_average']['score'])} |"
            )
    if ok:
        lines += [
            "",
            "Per category, mapped mode, as TPR / FPR (score):",
            "",
            "| Category | CWE | Cases (vuln/safe) | " + " | ".join(ok) + " |",
            "|---|---|---|" + "---|" * len(ok),
        ]
        first = doc["tools"][ok[0]]["metrics"]["mapped"]["per_category"]
        for cat in sorted(first):
            c0 = first[cat]
            cells = []
            for tool in ok:
                c = doc["tools"][tool]["metrics"]["mapped"]["per_category"][cat]
                cells.append(f"{pct(c['tpr'])} / {pct(c['fpr'])} ({signed(c['score'])})")
            vuln = c0["tp"] + c0["fn"]
            safe = c0["fp"] + c0["tn"]
            lines.append(f"| {cat} | {c0['cwe']} | {vuln}/{safe} | " + " | ".join(cells) + " |")
    lines += ["", *_run_lines(doc), ""]
    return lines


def recall_section(doc: dict) -> list[str]:
    ds = doc["dataset"]
    ok = _ok_tools(doc)
    lines = [
        f"## {ds['title']}",
        "",
        f"Commit `{ds['commit']}`, {ds['samples']} samples over {ds['cwes']} CWEs. "
        "Every sample is labeled vulnerable and there are no safe samples, so only "
        "recall is measurable; precision, FPR and F1 are undefined. `any` counts a "
        "sample as detected when the tool reports anything in it, whatever the CWE.",
        "",
        "| Tool | Mode | Detected | Recall | CWE-average recall | CWEs with a detection |",
        "|---|---|---|---|---|---|",
    ]
    for tool in ok:
        for mode in ("mapped", "strict", "any"):
            o = doc["tools"][tool]["metrics"][mode]["overall"]
            lines.append(
                f"| {tool} | {mode} | {o['detected']}/{o['samples']} | {pct(o['recall'])} "
                f"| {pct(o['cwe_average_recall'])} | {o['cwes_with_any_detection']}/{o['cwes']} |"
            )
    if ok:
        lines += [
            "",
            "Per CWE, mapped mode, detected samples:",
            "",
            "| CWE | Samples | " + " | ".join(ok) + " |",
            "|---|---|" + "---|" * len(ok),
        ]
        first = doc["tools"][ok[0]]["metrics"]["mapped"]["per_cwe"]
        for cwe in sorted(first, key=lambda k: int(k.split("-")[1])):
            cells = [
                str(doc["tools"][t]["metrics"]["mapped"]["per_cwe"][cwe]["detected"]) for t in ok
            ]
            lines.append(f"| {cwe} | {first[cwe]['samples']} | " + " | ".join(cells) + " |")
    lines += ["", *_run_lines(doc), ""]
    return lines


def write_summary(results_dir: Path) -> Path:
    lines = [
        "# Public benchmark summary",
        "",
        "Generated by `python benchmarks/public/run.py`; do not edit by hand. "
        "Methodology, mapping rules and limitations: `docs/benchmarks.md`. "
        "`mapped` uses the committed CWE equivalence groups in "
        "`benchmarks/public/mapping.py`; `strict` requires the exact labeled CWE.",
        "",
    ]
    for path in sorted(results_dir.glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if "dataset" not in doc:
            continue
        if doc["dataset"].get("has_negatives"):
            lines += owasp_section(doc)
        else:
            lines += recall_section(doc)
    out = results_dir / "SUMMARY.md"
    # LF on every platform so a re-run on Windows does not rewrite every line.
    out.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8", newline="\n")
    return out
