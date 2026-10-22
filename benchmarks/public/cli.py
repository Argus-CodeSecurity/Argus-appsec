"""Command line for the public labeled-dataset benchmark. See ``run.py``."""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import platform
import sys
from collections import Counter
from pathlib import Path

from benchmarks.public import datasets, mapping, report, scoring, tools

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent
CORPORA = BENCH / ".corpora"
RESULTS = BENCH / "results" / "public"
SCHEMA_VERSION = 1


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python benchmarks/public/run.py",
        description="Precision/recall of Argus, Bandit and Semgrep on public labeled datasets.",
    )
    p.add_argument(
        "--dataset",
        default="all",
        help=f"one of {', '.join(datasets.DATASETS)} or 'all' (default)",
    )
    p.add_argument("--tools", default=",".join(tools.TOOLS), help="comma-separated tools")
    p.add_argument(
        "--offline",
        action="store_true",
        help="no network and no tool runs: re-score from the raw-output cache in "
        "benchmarks/.corpora/raw, falling back to the committed normalized findings",
    )
    p.add_argument("--fetch-only", action="store_true", help="download datasets and exit")
    p.add_argument("--bandit", help="path to the bandit executable (or ARGUS_BENCH_BANDIT)")
    p.add_argument("--semgrep", help="path to the semgrep executable (or ARGUS_BENCH_SEMGREP)")
    p.add_argument(
        "--semgrep-config",
        default=tools.SEMGREP_DEFAULT_CONFIG,
        help="Semgrep registry ruleset (p/...) or local rules file (default p/python)",
    )
    p.add_argument(
        "--refresh-semgrep-rules",
        action="store_true",
        help="re-download the cached Semgrep registry ruleset",
    )
    return p.parse_args(argv)


def _findings_path(dataset: str, tool: str) -> Path:
    return RESULTS / "findings" / dataset / f"{tool}.json"


def _write_findings(dataset: str, tool: str, meta: dict, found: list[scoring.Finding]) -> None:
    """Commit-friendly normalized findings: no code, no local paths."""
    rows = sorted((f.file, f.line, f.rule_id, sorted(f.cwes)) for f in found)
    path = _findings_path(dataset, tool)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {"meta": meta, "columns": ["file", "line", "rule_id", "cwes"], "findings": rows}
    path.write_text(json.dumps(body, indent=1) + "\n", encoding="utf-8", newline="\n")


def _read_findings(dataset: str, tool: str) -> tuple[dict, list[scoring.Finding]] | None:
    path = _findings_path(dataset, tool)
    if not path.is_file():
        return None
    body = json.loads(path.read_text(encoding="utf-8"))
    found = [scoring.Finding(f, int(ln), r, frozenset(c)) for f, ln, r, c in body["findings"]]
    return body["meta"], found


def _scored_file(dataset: str, path: str, sample_ids: set[str]) -> bool:
    if dataset == "owasp-python":
        return scoring.owasp_case_id(path) is not None
    return path.rsplit("/", 1)[-1] in sample_ids


def _inventory(
    dataset: str, found: list[scoring.Finding], sample_ids: set[str]
) -> dict[str, object]:
    """Which rules fired on scored files and with which CWEs (mapping audit)."""
    scored = [f for f in found if _scored_file(dataset, f.file, sample_ids)]
    by_rule = Counter((f.rule_id, tuple(sorted(f.cwes))) for f in scored)
    return {
        "findings_total": len(found),
        "findings_in_scored_files": len(scored),
        "findings_in_scored_files_without_cwe": sum(1 for f in scored if not f.cwes),
        "rules": [
            {"rule_id": r, "cwes": list(c), "count": n}
            for (r, c), n in sorted(by_rule.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
    }


def _score(dataset: str, checkout: datasets.Checkout, tool: str, found: list) -> dict:
    if dataset == "owasp-python":
        cases = datasets.load_owasp_cases(checkout)
        return {m: scoring.score_owasp(cases, found, tool, m) for m in scoring.MODES}
    samples = datasets.load_securityeval_samples(checkout)
    return {
        m: scoring.score_labeled_recall(samples, found, tool, m) for m in (*scoring.MODES, "any")
    }


def _dataset_block(checkout: datasets.Checkout) -> dict[str, object]:
    spec = checkout.spec
    block: dict[str, object] = {
        "name": spec.name,
        "title": spec.title,
        "repo": spec.repo,
        "commit": spec.commit,
        "archive_url": spec.archive_url,
        "archive_sha256": checkout.archive_sha256,
        "labels_file": spec.labels,
        "has_negatives": spec.has_negatives,
    }
    if spec.name == "owasp-python":
        cases = datasets.load_owasp_cases(checkout)
        block["cases"] = len(cases)
        block["vulnerable_cases"] = sum(1 for c in cases if c.vulnerable)
        block["safe_cases"] = sum(1 for c in cases if not c.vulnerable)
        block["categories"] = len({c.category for c in cases})
    else:
        samples = datasets.load_securityeval_samples(checkout)
        block["samples"] = len(samples)
        block["cwes"] = len({s.cwe for s in samples})
    return block


def run_dataset(name: str, wanted: list[str], args: argparse.Namespace) -> dict | None:
    spec = datasets.DATASETS[name]
    print(f"[{name}] {spec.title} @ {spec.commit[:12]}")
    checkout = datasets.fetch(spec, CORPORA, offline=args.offline)
    if args.fetch_only:
        return None
    sample_ids: set[str] = set()
    if name == "securityeval":
        sample_ids = {s.sample_id for s in datasets.load_securityeval_samples(checkout)}

    opts = tools.ToolOptions(
        bandit=args.bandit,
        semgrep=args.semgrep,
        semgrep_config=args.semgrep_config,
        refresh_semgrep_rules=args.refresh_semgrep_rules,
        corpora=CORPORA,
    )
    raw_dir = CORPORA / "raw" / name
    out_path = RESULTS / f"{name}.json"
    previous: dict = {}
    if out_path.is_file():
        old = json.loads(out_path.read_text(encoding="utf-8"))
        if old.get("dataset", {}).get("commit") == spec.commit:
            previous = old.get("tools", {})

    results: dict[str, object] = {}
    for tool in tools.TOOLS:
        if tool not in wanted:
            if tool in previous:
                results[tool] = previous[tool]  # carried over from an earlier run
            continue
        print(f"  {tool}: ", end="", flush=True)
        try:
            if args.offline:
                loaded = tools.load_raw(tool, checkout.scan_root, raw_dir)
                source = "raw cache"
                if loaded is None:
                    loaded = _read_findings(name, tool)
                    source = "committed normalized findings"
                if loaded is None:
                    raise tools.ToolUnavailable("no cached output to re-score")
                meta, found = loaded
                meta = {**meta, "rescored_from": source}
            else:
                meta = tools.run_tool(tool, checkout.scan_root, raw_dir, opts)
                loaded = tools.load_raw(tool, checkout.scan_root, raw_dir)
                assert loaded is not None
                found = loaded[1]
        except tools.ToolUnavailable as exc:
            print(f"not run ({exc})")
            results[tool] = {"status": "not_run", "reason": str(exc)}
            continue
        if not args.offline or meta.get("rescored_from") == "raw cache":
            _write_findings(
                name, tool, {k: v for k, v in meta.items() if k != "rescored_from"}, found
            )
        results[tool] = {
            "status": "ok",
            "run": meta,
            "inventory": _inventory(name, found, sample_ids),
            "metrics": _score(name, checkout, tool, found),
        }
        print(f"{len(found)} findings ({meta.get('version')})")

    doc = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat(),
        "mode": "offline-rescore" if args.offline else "live",
        "host": {"os": platform.system(), "python": platform.python_version()},
        "dataset": _dataset_block(checkout),
        "scoring": {
            "modes": list(scoring.MODES) + ([] if spec.has_negatives else ["any"]),
            "mapping": mapping.tables_snapshot(),
        },
        "tools": results,
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"  wrote {out_path.relative_to(BENCH.parent)}")
    return doc


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    names = list(datasets.DATASETS) if args.dataset == "all" else [args.dataset]
    unknown = [n for n in names if n not in datasets.DATASETS]
    if unknown:
        print(f"unknown dataset {unknown[0]!r}; choose from {', '.join(datasets.DATASETS)}")
        return 2
    wanted = [t.strip() for t in args.tools.split(",") if t.strip()]
    bad = [t for t in wanted if t not in tools.TOOLS]
    if bad:
        print(f"unknown tool {bad[0]!r}; choose from {', '.join(tools.TOOLS)}")
        return 2
    for name in names:
        run_dataset(name, wanted, args)
    if not args.fetch_only:
        summary = report.write_summary(RESULTS)
        print(f"summary: {summary.relative_to(BENCH.parent)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
