"""Run Argus, Bandit and Semgrep and normalize their JSON into ``Finding`` records.

Each runner writes the tool's raw JSON plus a ``.meta.json`` next to it in the
raw cache (``benchmarks/.corpora/raw/<dataset>/``). Parsers are pure functions
of the raw JSON so ``--offline`` can re-score without running anything.

Command lines are recorded with ``<dataset_root>`` and ``<raw_output>``
placeholders so committed results do not embed local machine paths.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from benchmarks.public.scoring import Finding, parse_cwe, parse_cwes

TOOLS = ("argus", "bandit", "semgrep")
SEMGREP_DEFAULT_CONFIG = "p/python"


class ToolUnavailable(RuntimeError):
    """The tool is not installed or cannot run here; recorded as not run."""


@dataclass
class ToolOptions:
    bandit: str | None = None
    semgrep: str | None = None
    semgrep_config: str = SEMGREP_DEFAULT_CONFIG
    refresh_semgrep_rules: bool = False
    corpora: Path = Path(".")


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _clean_env() -> dict[str, str]:
    """Environment for third-party tools: no PYTHONPATH leaking Argus's tree."""
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["SEMGREP_SEND_METRICS"] = "off"
    return env


def _portable(cmd: list[str], root: Path, raw: Path, extra: dict[str, str]) -> list[str]:
    subs = {str(root): "<dataset_root>", str(raw): "<raw_output>", **extra}
    return [subs.get(part, part) for part in cmd]


def _execute(
    cmd: list[str], ok_codes: tuple[int, ...], cwd: Path, env: dict[str, str] | None
) -> tuple[int, float]:
    start = time.perf_counter()
    proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    elapsed = time.perf_counter() - start
    if proc.returncode not in ok_codes:
        tail = (proc.stderr or proc.stdout or "")[-4000:]
        raise RuntimeError(f"{cmd[0]} exited {proc.returncode}:\n{tail}")
    return proc.returncode, elapsed


def _version(cmd: list[str], env: dict[str, str] | None) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
    out = (proc.stdout or proc.stderr).strip().splitlines()
    return out[0].strip() if out else "unknown"


def _resolve(explicit: str | None, env_var: str, name: str) -> str:
    candidate = explicit or os.environ.get(env_var) or shutil.which(name)
    if not candidate or not Path(candidate).exists():
        raise ToolUnavailable(
            f"{name} not found (pass --{name} PATH, set {env_var}, or put it on PATH)"
        )
    return candidate


# --- Argus ------------------------------------------------------------------


def run_argus(root: Path, raw: Path, opts: ToolOptions) -> dict[str, object]:
    cmd = [
        sys.executable,
        "-m",
        "argus",
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
    # cwd is the raw cache dir (ours), never the dataset: ``-m`` puts cwd on
    # sys.path and the dataset is untrusted.
    code, elapsed = _execute(cmd, (0, 1), raw.parent, None)
    report = json.loads(raw.read_text(encoding="utf-8"))
    scanners = list(report.get("scanners_run") or [])
    if "ast-python" not in scanners:
        raise RuntimeError(
            "the ast-python tier did not run; install the [ast] extra "
            "(pip install 'argus-appsec[ast]') so the benchmark measures it"
        )
    return {
        "version": str(report.get("argus_version")),
        "command": ["argus", *_portable(cmd[3:], root, raw, {})],
        "exit_code": code,
        "seconds": round(elapsed, 1),
        "scanners_run": scanners,
        "scanners_failed": report.get("scanners_failed") or [],
        "notes": "offline heuristic provider (--no-ai); default scanners incl. the [ast] tier",
    }


def parse_argus(report: dict, root: Path) -> list[Finding]:
    out = []
    for f in report.get("findings", []):
        loc = f.get("location") or {}
        out.append(
            Finding(
                file=_rel(str(loc.get("path", "")), root),
                line=int(loc.get("start_line") or 0),
                rule_id=str(f.get("rule_id", "")),
                cwes=parse_cwes(f.get("cwe") or []),
            )
        )
    return out


# --- Bandit -----------------------------------------------------------------


def run_bandit(root: Path, raw: Path, opts: ToolOptions) -> dict[str, object]:
    exe = _resolve(opts.bandit, "ARGUS_BENCH_BANDIT", "bandit")
    env = _clean_env()
    cmd = [exe, "-r", str(root), "-f", "json", "-o", str(raw), "-q"]
    code, elapsed = _execute(cmd, (0, 1), raw.parent, env)
    return {
        "version": _version([exe, "--version"], env),
        "command": _portable(cmd, root, raw, {exe: "bandit"}),
        "exit_code": code,
        "seconds": round(elapsed, 1),
        "notes": "default configuration (all plugins, all severities and confidences)",
    }


def parse_bandit(report: dict, root: Path) -> list[Finding]:
    out = []
    for r in report.get("results", []):
        cwe = (r.get("issue_cwe") or {}).get("id")
        parsed = parse_cwe(cwe)
        out.append(
            Finding(
                file=_rel(str(r.get("filename", "")), root),
                line=int(r.get("line_number") or 0),
                rule_id=str(r.get("test_id", "")),
                cwes=frozenset({parsed}) if parsed else frozenset(),
            )
        )
    return out


# --- Semgrep ----------------------------------------------------------------


def _semgrep_rules(opts: ToolOptions) -> tuple[Path, dict[str, object]]:
    """Cache the registry ruleset locally so re-runs use identical rules.

    Registry rulesets are not version-pinned upstream, so the cached file's
    SHA-256, rule count and fetch date are recorded with the results.
    """
    name = opts.semgrep_config
    if not name.startswith("p/"):
        path = Path(name)
        if not path.is_file():
            raise ToolUnavailable(f"semgrep config {name} is neither p/<ruleset> nor a file")
        fetched = "local file"
    else:
        path = opts.corpora / "semgrep-rules" / (name.replace("/", "-") + ".yaml")
        meta_path = path.with_suffix(".meta.json")
        if opts.refresh_semgrep_rules or not path.is_file():
            path.parent.mkdir(parents=True, exist_ok=True)
            url = f"https://semgrep.dev/c/{name}"
            print(f"  fetching Semgrep ruleset {url}")
            with urllib.request.urlopen(url, timeout=120) as resp:
                path.write_bytes(resp.read())
            meta_path.write_text(json.dumps({"url": url, "fetched_at": _now()}), "utf-8")
        fetched = json.loads(meta_path.read_text("utf-8"))["fetched_at"]
    text = path.read_text(encoding="utf-8")
    rules = sum(1 for line in text.splitlines() if line.startswith("- id:"))
    return path, {
        "ruleset": name,
        "ruleset_sha256": _sha256_file(path),
        "ruleset_rules": rules,
        "ruleset_fetched_at": fetched,
    }


def run_semgrep(root: Path, raw: Path, opts: ToolOptions) -> dict[str, object]:
    exe = _resolve(opts.semgrep, "ARGUS_BENCH_SEMGREP", "semgrep")
    env = _clean_env()
    rules, rules_meta = _semgrep_rules(opts)
    # Run from the ruleset's directory and pass the bare file name: Semgrep
    # prefixes rule ids with the config file's directory relative to cwd, and
    # this keeps the registry ids (python.lang.security...) unchanged.
    cmd = [
        exe,
        "scan",
        "--config",
        rules.name,
        "--metrics=off",
        "--disable-version-check",
        # The corpora live under a git-ignored directory of this repository;
        # without this flag Semgrep would skip every file.
        "--no-git-ignore",
        "--json",
        "-o",
        str(raw),
        "--quiet",
        str(root),
    ]
    code, elapsed = _execute(cmd, (0, 1), rules.parent, env)
    errors = json.loads(raw.read_text(encoding="utf-8")).get("errors") or []
    return {
        "version": _version([exe, "--version"], env),
        "command": _portable(cmd, root, raw, {exe: "semgrep", rules.name: opts.semgrep_config}),
        "exit_code": code,
        "seconds": round(elapsed, 1),
        "semgrep_errors": len(errors),
        "notes": "registry ruleset cached locally; Semgrep CE engine; default settings",
        **rules_meta,
    }


def parse_semgrep(report: dict, root: Path) -> list[Finding]:
    out = []
    for r in report.get("results", []):
        meta = (r.get("extra") or {}).get("metadata") or {}
        raw_cwe = meta.get("cwe") or []
        if isinstance(raw_cwe, str):
            raw_cwe = [raw_cwe]
        out.append(
            Finding(
                file=_rel(str(r.get("path", "")), root),
                line=int((r.get("start") or {}).get("line") or 0),
                rule_id=str(r.get("check_id", "")),
                cwes=parse_cwes(raw_cwe),
            )
        )
    return out


# --- shared -----------------------------------------------------------------


def _rel(path: str, root: Path) -> str:
    """POSIX path relative to the scanned root, whatever form the tool used."""
    p = path.replace("\\", "/")
    root_s = str(root).replace("\\", "/").rstrip("/")
    if os.path.isabs(path):
        with contextlib.suppress(ValueError):  # different drive on Windows
            p = os.path.relpath(path, root).replace("\\", "/")
    elif p.lower().startswith(root_s.lower() + "/"):
        p = p[len(root_s) + 1 :]
    return p.removeprefix("./")


RUNNERS: dict[str, Callable[[Path, Path, ToolOptions], dict[str, object]]] = {
    "argus": run_argus,
    "bandit": run_bandit,
    "semgrep": run_semgrep,
}
PARSERS: dict[str, Callable[[dict, Path], list[Finding]]] = {
    "argus": parse_argus,
    "bandit": parse_bandit,
    "semgrep": parse_semgrep,
}


def run_tool(tool: str, root: Path, raw_dir: Path, opts: ToolOptions) -> dict[str, object]:
    """Run ``tool`` on ``root``; write raw JSON and meta; return the meta."""
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw = raw_dir / f"{tool}.json"
    raw.unlink(missing_ok=True)
    started = _now()
    meta = RUNNERS[tool](root, raw, opts)
    meta = {"tool": tool, "started_at": started, "raw_sha256": _sha256_file(raw), **meta}
    (raw_dir / f"{tool}.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def load_raw(tool: str, root: Path, raw_dir: Path) -> tuple[dict, list[Finding]] | None:
    """Re-parse a cached raw output; None when nothing is cached."""
    raw = raw_dir / f"{tool}.json"
    meta_path = raw_dir / f"{tool}.meta.json"
    if not raw.is_file() or not meta_path.is_file():
        return None
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    findings = PARSERS[tool](json.loads(raw.read_text(encoding="utf-8")), root)
    return meta, findings
