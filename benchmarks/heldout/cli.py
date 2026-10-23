"""Command line for the held-out benchmark. See ``run.py``.

Every command takes ``--set``: ``v1`` (the frozen held-out set, the default),
``dev`` (the development set) or ``timesplit`` (the time-split test set).
Each set has its own manifest, download cache and results directory
(``BenchSet``), so no command for one set can read or overwrite another's.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from benchmarks.heldout import fetch, selection
from benchmarks.heldout.github import Client

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent
REPO = BENCH.parent
CORPORA = BENCH / ".corpora"
SCHEMA_VERSION = 1


@dataclass(frozen=True)
class BenchSet:
    """Where one benchmark set keeps its manifest, downloads and results."""

    name: str
    manifest: Path
    cache: Path  # git-ignored, under benchmarks/.corpora
    results: Path
    results_file: str
    title: str
    note: str = ""

    @property
    def api(self) -> Path:
        return self.cache / "api"

    @property
    def files(self) -> Path:
        return self.cache / "files"

    @property
    def raw(self) -> Path:
        return self.cache / "raw"

    @property
    def cases_out(self) -> Path:
        return self.results / "cases"


SETS: dict[str, BenchSet] = {
    "v1": BenchSet(
        "v1",
        HERE / "manifest.json",
        CORPORA / "heldout",
        BENCH / "results" / "heldout",
        "heldout.json",
        "Held-out benchmark: real fix commits",
    ),
    "dev": BenchSet(
        "dev",
        HERE / "sets" / "dev" / "manifest.json",
        CORPORA / "dev",
        BENCH / "results" / "dev",
        "dev.json",
        "Development set: real fix commits",
        "Development data, not a claim: this set is studied to improve detection, "
        "so its numbers say nothing about code Nephilex was not developed on. "
        "Release numbers come from the time-split set.",
    ),
    "timesplit": BenchSet(
        "timesplit",
        HERE / "sets" / "timesplit" / "manifest.json",
        CORPORA / "timesplit",
        BENCH / "results" / "timesplit",
        "timesplit.json",
        "Time-split test set: real fix commits",
    ),
}
V1 = SETS["v1"]
# Earlier sets each set excludes (every advisory they examined).
PRIOR: dict[str, tuple[str, ...]] = {"v1": (), "dev": ("v1",), "timesplit": ("v1", "dev")}

# v1 paths, kept for callers that predate ``--set``.
CACHE = V1.cache
FILES = V1.files
MANIFEST = V1.manifest
RESULTS = V1.results

Git = Callable[[list[str]], tuple[int, str]]


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def _today() -> _dt.date:
    return _dt.datetime.now(_dt.timezone.utc).date()


def _git(args: list[str]) -> tuple[int, str]:
    proc = subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True)
    return proc.returncode, proc.stdout.strip()


def rel(path: Path) -> str:
    """Repository-relative POSIX path (the path itself when outside the repository)."""
    try:
        return path.resolve().relative_to(REPO).as_posix()
    except ValueError:
        return path.as_posix()


def load_manifest(bs: BenchSet = V1) -> dict[str, Any]:
    return json.loads(bs.manifest.read_text(encoding="utf-8"))


_INT_LIST = re.compile(r"\[\s*(-?\d+(?:,\s*-?\d+)*)\s*\]")


def dump_json(doc: object) -> str:
    """Indented JSON with lists of integers kept on one line (line ranges, CWEs)."""
    text = json.dumps(doc, indent=1, ensure_ascii=False)
    return _INT_LIST.sub(lambda m: "[" + ", ".join(re.split(r",\s*", m.group(1))) + "]", text)


def save_manifest(doc: dict[str, Any], bs: BenchSet = V1) -> None:
    bs.manifest.parent.mkdir(parents=True, exist_ok=True)
    bs.manifest.write_text(dump_json(doc) + "\n", encoding="utf-8", newline="\n")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prior_sets(names: Iterable[str]) -> selection.PriorSets:
    """What the named earlier sets examined, read from their manifests."""
    prior = selection.PriorSets()
    for name in names:
        bs = SETS[name]
        doc = load_manifest(bs)
        prior = prior.merge(
            selection.prior_from_manifest(doc, name, rel(bs.manifest), _sha256(bs.manifest))
        )
    return prior


# --- the time-split freeze guard ------------------------------------------------

_FULL_SHA = re.compile(r"[0-9a-f]{40}")


def src_matches_commit(commit: str, git: Git | None = None) -> list[str]:
    """Problems that stop ``src/nephilex`` here from being the code at ``commit``."""
    git = git or _git
    if not _FULL_SHA.fullmatch(commit):
        return [
            f"--rules-frozen-at {commit!r} must be a full 40-character lower-case commit "
            "SHA (a branch or tag can move)"
        ]
    code, _ = git(["rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}"])
    if code != 0:
        return [f"{commit} is not a commit in this repository"]
    problems = []
    code, _ = git(["diff", "--quiet", commit, "--", "src/nephilex"])
    if code != 0:
        problems.append(f"src/nephilex differs from the frozen commit {commit}")
    _, untracked = git(["ls-files", "--others", "--exclude-standard", "--", "src/nephilex"])
    if untracked:
        problems.append("src/nephilex has untracked files that are not in the frozen commit")
    return problems


def timesplit_problems(
    *,
    rules_frozen_at: str | None,
    until: str | None,
    since: str,
    today: _dt.date,
    git: Git | None = None,
    sets: dict[str, BenchSet] | None = None,
) -> list[str]:
    """Every reason not to select the time-split set now (empty: go ahead).

    The time-split cases must stay unseen until the detection rules for the
    next release are frozen. Selection therefore needs an explicit
    acknowledgement: ``--rules-frozen-at`` names the commit whose
    ``src/nephilex`` is frozen, and the checkout running the selection must
    have exactly that ``src/nephilex``. The window must be closed (``until``
    before today, UTC) so the population cannot grow after selection, the set
    is selected only once, and the earlier sets it excludes must exist.
    """
    sets = SETS if sets is None else sets
    problems: list[str] = []
    if not rules_frozen_at:
        problems.append(
            "--rules-frozen-at <commit> is required: the time-split set may only be "
            "selected after the detection rules for the next release are frozen at "
            "that commit"
        )
    else:
        problems += src_matches_commit(rules_frozen_at, git)
    if not until:
        problems.append("--until YYYY-MM-DD (the freeze date) is required")
    else:
        try:
            rule = selection.timesplit_rule(until, since)
        except ValueError as exc:
            problems.append(str(exc))
        else:
            if _dt.date.fromisoformat(rule.published_window[1]) >= today:
                problems.append(
                    f"--until {until} must be before today ({today.isoformat()}, UTC) "
                    "so that no advisory can still be added to the window"
                )
    ts = sets["timesplit"]
    if ts.manifest.exists():
        problems.append(
            f"{ts.manifest.name} already exists in {ts.manifest.parent}: "
            "a time-split set is selected once"
        )
    for name in PRIOR["timesplit"]:
        if not sets[name].manifest.is_file():
            problems.append(f"the {name} manifest it excludes is missing: {sets[name].manifest}")
    return problems


# --- commands -------------------------------------------------------------------


def _rule_doc(rule: selection.SetRule) -> dict[str, Any]:
    return {
        "source": "GitHub Advisory Database REST API, type=reviewed",
        "ecosystems": list(selection.ECOSYSTEMS),
        "published_window": list(rule.published_window),
        "claimed_cwes": {str(k): v for k, v in selection.CLAIMED_CWES.items()},
        "target_cwes": sorted(selection.TARGET_CWES),
        "languages": selection.LANGUAGES,
        "max_files_per_advisory": selection.MAX_FILES_PER_ADVISORY,
        "case_budget": dict(rule.case_budget),
        "max_file_bytes": selection.MAX_FILE_BYTES,
        "sampling": rule.sampling,
    }


def cmd_select(args: argparse.Namespace) -> int:
    from benchmarks.heldout.select_cases import select

    bs = SETS[args.set]
    freeze: dict[str, Any] | None = None
    if bs.name == "timesplit":
        problems = timesplit_problems(
            rules_frozen_at=args.rules_frozen_at,
            until=args.until,
            since=args.since,
            today=_today(),
        )
        if problems:
            print("refusing to select the time-split set:", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            return 2
        rule = selection.timesplit_rule(args.until, args.since)
        freeze = {
            "rules_frozen_at": args.rules_frozen_at,
            "harness_commit": _git(["rev-parse", "HEAD"])[1],
            "src_nephilex_identical_to_frozen_commit": True,
            "acknowledged_at": _now(),
        }
    elif args.until or args.rules_frozen_at or args.since != selection.TIMESPLIT_START:
        print(
            "--until, --since and --rules-frozen-at apply to --set timesplit only", file=sys.stderr
        )
        return 2
    elif bs.manifest.exists() and not args.replace:
        print(
            f"{rel(bs.manifest)} exists and is the frozen record of the {bs.name} set; "
            "pass --replace to select it again",
            file=sys.stderr,
        )
        return 2
    else:
        rule = selection.DEV_RULE if bs.name == "dev" else selection.V1_RULE

    prior = prior_sets(PRIOR[bs.name])
    client = Client(bs.api, api_command=args.api_command, offline=args.offline)
    result = select(client, rule, prior)
    doc: dict[str, Any] = {"schema_version": SCHEMA_VERSION}
    if bs.name != "v1":
        doc["set"] = bs.name
    doc["selected_at"] = _now()
    if freeze:
        doc["freeze"] = freeze
    doc["rule"] = _rule_doc(rule)
    if prior.sources:
        doc["excluded_prior_sets"] = list(prior.sources)
    doc.update(result)
    save_manifest(doc, bs)
    print(f"API requests: {client.requests}")
    for eco, stats in result["population"].items():
        print(f"[{eco}]")
        for k, v in stats.items():
            print(f"  {k}: {v}")
    print(f"cases: {len(result['cases'])}; wrote {rel(bs.manifest)}")
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    bs = SETS[args.set]
    doc = load_manifest(bs)
    client = Client(bs.api)
    failures: dict[str, str] = {}
    for case in doc["cases"]:
        reason = fetch.fetch_case(client, bs.files, case)
        if reason:
            failures[case["case_id"]] = reason
            print(f"  {case['case_id']}: {reason}")
    doc["fetch"] = {"fetched_at": _now(), "excluded_cases": failures}
    if not args.no_write:
        save_manifest(doc, bs)
    print(f"fetched {len(doc['cases']) - len(failures)}/{len(doc['cases'])} cases")
    return 0


def add_set_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--set",
        choices=sorted(SETS),
        default="v1",
        help="benchmark set: v1 (frozen held-out, default), dev (development) "
        "or timesplit (time-split test set)",
    )


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python benchmarks/heldout/run.py",
        description="Held-out benchmark on real fix commits from GitHub advisories.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("select", help="apply the selection rule and rewrite the set's manifest")
    add_set_arg(s)
    s.add_argument(
        "--api-command",
        help="external command that GETs a GitHub API path and prints JSON "
        "(default: built-in client using GITHUB_TOKEN if set)",
    )
    s.add_argument("--offline", action="store_true", help="use only the cached API responses")
    s.add_argument(
        "--replace",
        action="store_true",
        help="v1 and dev only: overwrite the existing manifest (the time-split set is "
        "never selected twice)",
    )
    s.add_argument(
        "--until",
        help="timesplit only: last publication date (YYYY-MM-DD, inclusive, before today)",
    )
    s.add_argument(
        "--since",
        default=selection.TIMESPLIT_START,
        help=f"timesplit only: first publication date (default {selection.TIMESPLIT_START})",
    )
    s.add_argument(
        "--rules-frozen-at",
        metavar="COMMIT",
        help="timesplit only, required: full SHA of the commit whose src/nephilex is the "
        "frozen detection code; the checkout must match it",
    )
    s.set_defaults(func=cmd_select)

    f = sub.add_parser("fetch", help="download both versions of every manifest case")
    add_set_arg(f)
    f.add_argument(
        "--no-write", action="store_true", help="verify only; do not update the manifest"
    )
    f.set_defaults(func=cmd_fetch)

    # Imported here: harness imports this module for its paths.
    from benchmarks.heldout import harness

    harness.add_parsers(sub)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
