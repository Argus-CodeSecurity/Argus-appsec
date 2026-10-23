"""Run the tools on the fetched cases, then score and write the results.

``scan`` runs Nephilex, Bandit and Semgrep on both versions of every fetched
case and then scores. ``score`` re-scores from the committed per-case files in
``benchmarks/results/heldout/cases`` without running any tool.

Layout under ``benchmarks/.corpora/heldout`` (git ignored):

* ``files/<case_id>/{vulnerable,patched}/<path>``: the downloaded files.
* ``raw/<tool>/``: each tool's raw JSON output and run metadata.

Nephilex runs once per case and version, so its cross-file analysis can never
connect two unrelated projects. Bandit and Semgrep CE analyze one file at a
time, so each runs once over the whole tree; their findings are attributed to
cases by path.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import platform
import subprocess
import sys
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from benchmarks.heldout import cli, fetch, report
from benchmarks.heldout import scoring as hs
from benchmarks.heldout.selection import from_ranges
from benchmarks.public import mapping
from benchmarks.public import tools as ptools
from benchmarks.public.scoring import Finding

TOOLS = ("nephilex", "bandit", "semgrep")
SEMGREP_CONFIGS = ("p/python", "p/javascript")
# Languages each tool analyzes; other cases are "not applicable", not misses.
APPLIES: dict[str, frozenset[str]] = {
    "nephilex": frozenset({"python", "javascript", "typescript"}),
    "bandit": frozenset({"python"}),
    "semgrep": frozenset({"python", "javascript", "typescript"}),
}
_AST_TIER = {"python": "ast-python", "javascript": "ast-js", "typescript": "ast-js"}

RAW = cli.CACHE / "raw"
CASES_OUT = cli.RESULTS / "cases"


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- case loading -------------------------------------------------------------


def scored_cases(doc: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Cases with both versions fetched and verified, plus excluded ones with reasons."""
    excluded = dict((doc.get("fetch") or {}).get("excluded_cases") or {})
    ok = []
    for case in doc["cases"]:
        if case["case_id"] in excluded:
            continue
        content = case.get("content") or {}
        for version in fetch.VERSIONS:
            path = fetch.case_file(cli.FILES, case, version)
            want = (content.get(version) or {}).get("sha256")
            if not path.is_file():
                excluded[case["case_id"]] = f"{version} file not fetched"
                break
            if want != _sha256(path):
                excluded[case["case_id"]] = f"{version} file does not match the manifest hash"
                break
        else:
            ok.append(case)
    return ok, excluded


def to_case(c: dict[str, Any]) -> hs.Case:
    return hs.Case(
        case_id=c["case_id"],
        ghsa_id=c["ghsa_id"],
        ecosystem=c["ecosystem"],
        language=c["language"],
        labels=tuple(c["label_cwes"]),
        vulnerable_lines=frozenset(from_ranges(c["vulnerable_lines"])),
        patched_lines=frozenset(from_ranges(c["patched_lines"])),
    )


# --- tool runs ------------------------------------------------------------------

# Normalized findings: tool -> case_id -> version -> findings
Found = dict[str, dict[str, list[Finding]]]


def _nephilex_one(case: dict[str, Any], version: str) -> dict[str, Any]:
    root = cli.FILES / case["case_id"] / version
    out_dir = RAW / "nephilex"
    raw = out_dir / f"{case['case_id']}.{version}.json"
    cmd = [
        sys.executable,
        "-m",
        "nephilex",
        "scan",
        str(root),
        "--no-ai",
        "--no-cache",
        "--quiet",
        "-f",
        "json",
        "-o",
        str(raw),
    ]
    raw.unlink(missing_ok=True)
    start = time.perf_counter()
    # cwd is our raw directory, never the downloaded tree: ``-m`` puts cwd on
    # sys.path and the downloaded files are untrusted.
    proc = subprocess.run(cmd, cwd=out_dir, capture_output=True, text=True)
    seconds = time.perf_counter() - start
    if proc.returncode not in (0, 1) or not raw.is_file():
        tail = (proc.stderr or proc.stdout or "")[-2000:]
        raise RuntimeError(f"nephilex failed on {case['case_id']} {version}: {tail}")
    report_doc = json.loads(raw.read_text(encoding="utf-8"))
    scanners = list(report_doc.get("scanners_run") or [])
    tier = _AST_TIER[case["language"]]
    if tier not in scanners:
        raise RuntimeError(
            f"{tier} did not run on {case['case_id']} {version}; install the [ast] extra"
        )
    return {
        "case_id": case["case_id"],
        "version": version,
        "seconds": round(seconds, 2),
        "exit_code": proc.returncode,
        "nephilex_version": report_doc.get("nephilex_version"),
        "scanners_failed": report_doc.get("scanners_failed") or [],
        "findings": ptools.parse_nephilex(report_doc, root),
    }


def run_nephilex(cases: list[dict[str, Any]], jobs: int) -> tuple[dict[str, Any], Found]:
    (RAW / "nephilex").mkdir(parents=True, exist_ok=True)
    started = _now()
    work = [(c, v) for c in cases for v in fetch.VERSIONS]
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        results = list(pool.map(lambda cv: _nephilex_one(*cv), work))
    found: Found = {}
    failed: dict[str, list[str]] = {}
    versions = set()
    for r in results:
        found.setdefault(r["case_id"], {})[r["version"]] = r["findings"]
        versions.add(str(r["nephilex_version"]))
        if r["scanners_failed"]:
            failed[f"{r['case_id']}.{r['version']}"] = [str(s) for s in r["scanners_failed"]]
    meta = {
        "tool": "nephilex",
        "started_at": started,
        "version": ", ".join(sorted(versions)),
        "command": [
            "nephilex",
            "scan",
            "<case>/<version>",
            "--no-ai",
            "--no-cache",
            "--quiet",
            "-f",
            "json",
            "-o",
            "<raw_output>",
        ],  # fmt: skip
        "runs": len(results),
        "seconds": round(time.perf_counter() - t0, 1),
        "scanners_failed": failed,
        "notes": "one run per case and version; offline heuristic provider (--no-ai); "
        "default scanners incl. the [ast] tier",
    }
    return meta, found


def _attribute(findings: Iterable[Finding]) -> Found:
    """Split whole-tree findings into case and version by their path."""
    found: Found = {}
    for f in findings:
        parts = f.file.split("/", 2)
        if len(parts) < 3 or parts[1] not in fetch.VERSIONS:
            continue
        found.setdefault(parts[0], {}).setdefault(parts[1], []).append(f)
    return found


def _error_paths(errors: Iterable[dict[str, Any]], key: str) -> list[str]:
    out = set()
    root = str(cli.FILES).replace("\\", "/").rstrip("/") + "/"
    for e in errors:
        path = str(e.get(key) or "").replace("\\", "/")
        if path.lower().startswith(root.lower()):
            path = path[len(root) :]
        if path:
            out.add("/".join(path.split("/")[:2]))
    return sorted(out)


def run_bandit(exe: str | None) -> tuple[dict[str, Any], Found]:
    out_dir = RAW / "bandit"
    opts = ptools.ToolOptions(bandit=exe, corpora=cli.CORPORA)
    meta = ptools.run_tool("bandit", cli.FILES, out_dir, opts)
    raw = json.loads((out_dir / "bandit.json").read_text(encoding="utf-8"))
    meta["parse_errors"] = _error_paths(raw.get("errors") or [], "filename")
    return meta, _attribute(ptools.parse_bandit(raw, cli.FILES))


def run_semgrep(exe: str | None, refresh: bool) -> tuple[dict[str, Any], Found]:
    path = ptools._resolve(exe, "NEPHILEX_BENCH_SEMGREP", "semgrep")
    env = ptools._clean_env()
    rulesets = []
    rule_files = []
    for config in SEMGREP_CONFIGS:
        opts = ptools.ToolOptions(
            semgrep=exe, semgrep_config=config, refresh_semgrep_rules=refresh, corpora=cli.CORPORA
        )
        rules, rules_meta = ptools._semgrep_rules(opts)
        rulesets.append(rules_meta)
        rule_files.append(rules)
    out_dir = RAW / "semgrep"
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / "semgrep.json"
    raw_path.unlink(missing_ok=True)
    cmd = [path, "scan"]
    for rules in rule_files:
        cmd += ["--config", rules.name]
    cmd += [
        "--metrics=off",
        "--disable-version-check",
        # The cases live under a git-ignored directory of this repository.
        "--no-git-ignore",
        "--json",
        "-o",
        str(raw_path),
        "--quiet",
        str(cli.FILES),
    ]
    started = _now()
    # Run from the ruleset directory with bare file names so registry rule ids
    # are not prefixed (see benchmarks/public/tools.py).
    code, seconds = ptools._execute(cmd, (0, 1), rule_files[0].parent, env)
    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    subs = {
        path: "semgrep",
        **{r.name: c for r, c in zip(rule_files, SEMGREP_CONFIGS, strict=True)},
    }
    meta = {
        "tool": "semgrep",
        "started_at": started,
        "raw_sha256": _sha256(raw_path),
        "version": ptools._version([path, "--version"], env),
        "command": ptools._portable(cmd, cli.FILES, raw_path, subs),
        "exit_code": code,
        "seconds": round(seconds, 1),
        "rulesets": rulesets,
        "semgrep_errors": len(raw.get("errors") or []),
        "parse_errors": _error_paths(raw.get("errors") or [], "path"),
        "notes": "registry rulesets cached locally; Semgrep CE engine; default settings",
    }
    (out_dir / "semgrep.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta, _attribute(ptools.parse_semgrep(raw, cli.FILES))


def nephilex_commit() -> dict[str, Any]:
    """The Nephilex source the benchmark ran against."""
    repo = cli.BENCH.parent

    def git(*args: str) -> str:
        proc = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True)
        return proc.stdout.strip()

    return {
        "commit": git("rev-parse", "HEAD"),
        "src_nephilex_modified": bool(git("status", "--porcelain", "--", "src/nephilex")),
    }


# --- per-case records and scoring -------------------------------------------------


def _rows(findings: Iterable[Finding]) -> list[list[Any]]:
    return [[f.line, f.rule_id, sorted(f.cwes)] for f in sorted(findings, key=_fkey)]


def _fkey(f: Finding) -> tuple[int, str, tuple[int, ...]]:
    return (f.line, f.rule_id, tuple(sorted(f.cwes)))


def write_case_files(
    cases: list[dict[str, Any]],
    excluded: dict[str, str],
    found_by_tool: dict[str, Found],
    errors_by_tool: dict[str, set[str]],
) -> None:
    """One JSON per case: manifest entry plus every tool's findings (no code)."""
    CASES_OUT.mkdir(parents=True, exist_ok=True)
    for old in CASES_OUT.glob("*.json"):
        old.unlink()
    doc = cli.load_manifest()
    by_id = {c["case_id"]: c for c in cases}
    for case in doc["cases"]:
        cid = case["case_id"]
        record: dict[str, Any] = {"case": case}
        if cid not in by_id:
            record["status"] = "excluded"
            record["exclusion_reason"] = excluded.get(cid, "not scored")
        else:
            record["status"] = "scored"
            record["tools"] = {}
            for tool, found in found_by_tool.items():
                if case["language"] not in APPLIES[tool]:
                    record["tools"][tool] = {"status": "not_applicable"}
                    continue
                per = found.get(cid, {})
                record["tools"][tool] = {
                    "status": "ok",
                    "parse_error_versions": sorted(
                        v for v in fetch.VERSIONS if f"{cid}/{v}" in errors_by_tool.get(tool, ())
                    ),
                    "findings": {v: _rows(per.get(v, [])) for v in fetch.VERSIONS},
                }
        path = CASES_OUT / f"{cid}.json"
        path.write_text(cli.dump_json(record) + "\n", encoding="utf-8", newline="\n")


def read_case_files() -> tuple[list[dict[str, Any]], dict[str, str], dict[str, Found]]:
    cases: list[dict[str, Any]] = []
    excluded: dict[str, str] = {}
    found_by_tool: dict[str, Found] = {}
    for path in sorted(CASES_OUT.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        case = record["case"]
        if record["status"] != "scored":
            excluded[case["case_id"]] = record.get("exclusion_reason", "")
            continue
        cases.append(case)
        local = fetch.local_relpath(case["path_patched"])
        for tool, entry in record["tools"].items():
            if entry.get("status") != "ok":
                continue
            per = found_by_tool.setdefault(tool, {}).setdefault(case["case_id"], {})
            for version, rows in entry["findings"].items():
                per[version] = [Finding(local, int(ln), r, frozenset(c)) for ln, r, c in rows]
    return cases, excluded, found_by_tool


def score_tool(tool: str, cases: list[dict[str, Any]], found: Found) -> dict[str, Any]:
    applicable = [to_case(c) for c in cases if c["language"] in APPLIES[tool]]

    def outcomes(mode: str, window: int) -> list[hs.Outcome]:
        return [
            hs.score_case(
                tool,
                c,
                found.get(c.case_id, {}).get("vulnerable", []),
                found.get(c.case_id, {}).get("patched", []),
                mode,
                window,
            )
            for c in applicable
        ]

    metrics: dict[str, Any] = {}
    per_case: dict[str, dict[str, Any]] = {}
    for mode in hs.MODES:
        res = outcomes(mode, hs.WINDOW)
        metrics[mode] = {
            "overall": hs.summarize(res),
            "advisories": hs.summarize_advisories(applicable, res),
            "by_cwe": hs.breakdown(applicable, res, lambda c: [f"CWE-{x}" for x in c.labels]),
            "by_language": hs.breakdown(applicable, res, lambda c: [c.language]),
            "by_language_family": hs.breakdown(
                applicable,
                res,
                lambda c: ["python" if c.language == "python" else "javascript/typescript"],
            ),
            "by_ecosystem": hs.breakdown(applicable, res, lambda c: [c.ecosystem]),
        }
        for o in res:
            per_case.setdefault(o.case_id, {})[mode] = {
                "detected": o.detected,
                "flagged_after_fix": o.flagged_after_fix,
            }
    sensitivity = {
        str(w): {m: hs.summarize(outcomes(m, w)) for m in hs.MODES} for w in hs.SENSITIVITY_WINDOWS
    }
    return {
        "applicable_cases": len(applicable),
        "metrics": metrics,
        "window_sensitivity": sensitivity,
        "per_case": per_case,
    }


def write_results(
    cases: list[dict[str, Any]],
    excluded: dict[str, str],
    found_by_tool: dict[str, Found],
    runs: dict[str, dict[str, Any]],
    nephilex_src: dict[str, Any],
    mode: str,
) -> dict[str, Any]:
    manifest = cli.load_manifest()
    tools: dict[str, Any] = {}
    per_case: dict[str, dict[str, Any]] = {}
    for tool in TOOLS:
        if tool not in found_by_tool:
            tools[tool] = runs.get(tool) or {"status": "not_run", "reason": "no output"}
            continue
        scored = score_tool(tool, cases, found_by_tool[tool])
        per_case[tool] = scored.pop("per_case")
        tools[tool] = {"status": "ok", "run": runs.get(tool, {}), **scored}
    _add_outcomes(per_case)
    doc = {
        "schema_version": cli.SCHEMA_VERSION,
        "generated_at": _now(),
        "mode": mode,
        "host": {"os": platform.system(), "python": platform.python_version()},
        "nephilex_source": nephilex_src,
        "manifest": {
            "path": "benchmarks/heldout/manifest.json",
            "sha256": _sha256(cli.MANIFEST),
            "selected_at": manifest.get("selected_at"),
            "cases_selected": len(manifest["cases"]),
            "cases_scored": len(cases),
            "cases_excluded": dict(sorted(excluded.items())),
            "advisories_scored": len({c["ghsa_id"] for c in cases}),
            "languages": _count(c["language"] for c in cases),
            "ecosystems": _count(c["ecosystem"] for c in cases),
        },
        "scoring": {
            "window": hs.WINDOW,
            "sensitivity_windows": list(hs.SENSITIVITY_WINDOWS),
            "modes": list(hs.MODES),
            "applies": {k: sorted(v) for k, v in APPLIES.items()},
            "mapping": mapping.tables_snapshot(),
        },
        "tools": tools,
    }
    cli.RESULTS.mkdir(parents=True, exist_ok=True)
    out = cli.RESULTS / "heldout.json"
    out.write_text(cli.dump_json(doc) + "\n", encoding="utf-8", newline="\n")
    summary = report.write_summary(doc, cli.RESULTS / "SUMMARY.md")
    print(f"wrote {out.relative_to(cli.BENCH.parent)} and {summary.relative_to(cli.BENCH.parent)}")
    return doc


def _add_outcomes(per_case: dict[str, dict[str, Any]]) -> None:
    """Write each tool's outcome into the per-case files."""
    for path in sorted(CASES_OUT.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        if record["status"] != "scored":
            continue
        cid = record["case"]["case_id"]
        record["outcomes"] = {
            tool: {"window": hs.WINDOW, **per_case[tool][cid]}
            for tool in TOOLS
            if cid in per_case.get(tool, {})
        }
        path.write_text(cli.dump_json(record) + "\n", encoding="utf-8", newline="\n")


def _count(values: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items()))


# --- commands ---------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> int:
    doc = cli.load_manifest()
    cases, excluded = scored_cases(doc)
    print(f"{len(cases)} cases to scan, {len(excluded)} excluded")
    found_by_tool: dict[str, Found] = {}
    runs: dict[str, dict[str, Any]] = {}
    errors: dict[str, set[str]] = {}
    for tool in TOOLS:
        print(f"  {tool}: ", end="", flush=True)
        try:
            if tool == "nephilex":
                meta, found = run_nephilex(cases, args.jobs)
            elif tool == "bandit":
                meta, found = run_bandit(args.bandit)
            else:
                meta, found = run_semgrep(args.semgrep, args.refresh_semgrep_rules)
        except ptools.ToolUnavailable as exc:
            print(f"not run ({exc})")
            runs[tool] = {"status": "not_run", "reason": str(exc)}
            continue
        runs[tool] = meta
        found_by_tool[tool] = found
        errors[tool] = set(meta.get("parse_errors") or [])
        total = sum(len(v) for per in found.values() for v in per.values())
        print(f"{total} findings in cases ({meta.get('version')}, {meta.get('seconds')} s)")
    write_case_files(cases, excluded, found_by_tool, errors)
    (cli.RESULTS / "runs.json").write_text(
        cli.dump_json({"nephilex_source": nephilex_commit(), "runs": runs}) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    write_results(cases, excluded, found_by_tool, runs, nephilex_commit(), "live")
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    cases, excluded, found_by_tool = read_case_files()
    runs_doc = json.loads((cli.RESULTS / "runs.json").read_text(encoding="utf-8"))
    write_results(
        cases, excluded, found_by_tool, runs_doc["runs"], runs_doc["nephilex_source"], "rescore"
    )
    return 0


def add_parsers(sub: Any) -> None:
    s = sub.add_parser("scan", help="run Nephilex, Bandit and Semgrep on the cases, then score")
    s.add_argument("--bandit", help="path to bandit (or NEPHILEX_BENCH_BANDIT)")
    s.add_argument("--semgrep", help="path to semgrep (or NEPHILEX_BENCH_SEMGREP)")
    s.add_argument("--jobs", type=int, default=4, help="parallel Nephilex runs (default 4)")
    s.add_argument(
        "--refresh-semgrep-rules", action="store_true", help="re-download the Semgrep rulesets"
    )
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("score", help="re-score from the committed per-case results")
    r.set_defaults(func=cmd_score)
