"""Command line for the held-out benchmark. See ``run.py``."""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
from pathlib import Path
from typing import Any

from benchmarks.heldout import fetch, selection
from benchmarks.heldout.github import Client

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent
CORPORA = BENCH / ".corpora"
CACHE = CORPORA / "heldout"
FILES = CACHE / "files"
MANIFEST = HERE / "manifest.json"
RESULTS = BENCH / "results" / "heldout"
SCHEMA_VERSION = 1


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def load_manifest() -> dict[str, Any]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


_INT_LIST = re.compile(r"\[\s*(-?\d+(?:,\s*-?\d+)*)\s*\]")


def dump_json(doc: object) -> str:
    """Indented JSON with lists of integers kept on one line (line ranges, CWEs)."""
    text = json.dumps(doc, indent=1, ensure_ascii=False)
    return _INT_LIST.sub(lambda m: "[" + ", ".join(re.split(r",\s*", m.group(1))) + "]", text)


def save_manifest(doc: dict[str, Any]) -> None:
    MANIFEST.write_text(dump_json(doc) + "\n", encoding="utf-8", newline="\n")


def cmd_select(args: argparse.Namespace) -> int:
    from benchmarks.heldout.select_cases import select

    client = Client(CACHE / "api", api_command=args.api_command, offline=args.offline)
    result = select(client)
    doc = {
        "schema_version": SCHEMA_VERSION,
        "selected_at": _now(),
        "rule": {
            "source": "GitHub Advisory Database REST API, type=reviewed",
            "ecosystems": list(selection.ECOSYSTEMS),
            "published_window": list(selection.PUBLISHED_WINDOW),
            "claimed_cwes": {str(k): v for k, v in selection.CLAIMED_CWES.items()},
            "target_cwes": sorted(selection.TARGET_CWES),
            "languages": selection.LANGUAGES,
            "max_files_per_advisory": selection.MAX_FILES_PER_ADVISORY,
            "case_budget": selection.CASE_BUDGET,
            "max_file_bytes": selection.MAX_FILE_BYTES,
            "sampling": "advisories ordered by sha256(GHSA id), taken until the budget is reached",
        },
        **result,
    }
    save_manifest(doc)
    print(f"API requests: {client.requests}")
    for eco, stats in result["population"].items():
        print(f"[{eco}]")
        for k, v in stats.items():
            print(f"  {k}: {v}")
    print(f"cases: {len(result['cases'])}; wrote {MANIFEST.relative_to(BENCH.parent)}")
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    doc = load_manifest()
    client = Client(CACHE / "api")
    failures: dict[str, str] = {}
    for case in doc["cases"]:
        reason = fetch.fetch_case(client, FILES, case)
        if reason:
            failures[case["case_id"]] = reason
            print(f"  {case['case_id']}: {reason}")
    doc["fetch"] = {"fetched_at": _now(), "excluded_cases": failures}
    if not args.no_write:
        save_manifest(doc)
    print(f"fetched {len(doc['cases']) - len(failures)}/{len(doc['cases'])} cases")
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python benchmarks/heldout/run.py",
        description="Held-out benchmark on real fix commits from GitHub advisories.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("select", help="apply the selection rule and rewrite manifest.json")
    s.add_argument(
        "--api-command",
        help="external command that GETs a GitHub API path and prints JSON "
        "(default: built-in client using GITHUB_TOKEN if set)",
    )
    s.add_argument("--offline", action="store_true", help="use only the cached API responses")
    s.set_defaults(func=cmd_select)

    f = sub.add_parser("fetch", help="download both versions of every manifest case")
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
