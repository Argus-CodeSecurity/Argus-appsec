"""Golden-file integration test: an end-to-end scan of a pinned fixture must keep
producing the same normalized findings. This catches cross-cutting regressions no
unit test sees (a change in one tier that quietly drops or moves a finding).

When the diff is an intentional improvement, regenerate the golden:
    python -m pytest tests/test_golden_snapshot.py  # see the printed diff, then
    update tests/fixtures/golden_app.expected.json to match.
"""

from __future__ import annotations

import json
from pathlib import Path

from nephilex.core.config import Config
from nephilex.core.engine import ScanEngine
from nephilex.core.project import Project

_FIXTURE = Path(__file__).parent / "fixtures" / "golden_app"
_GOLDEN = Path(__file__).parent / "fixtures" / "golden_app.expected.json"


def _snapshot() -> list[str]:
    # Deterministic tiers only, so the golden is stable with or without the AST
    # extra and never touches the network.
    cfg = Config(scanners=["patterns", "secrets", "iac"])
    result = ScanEngine(cfg).scan(Project.from_path(_FIXTURE))
    return sorted(
        f"{f.scanner}:{f.rule_id}@{f.location.path}:{f.location.start_line}"
        for f in result.findings
    )


def test_scan_matches_golden_snapshot():
    actual = _snapshot()
    expected = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    assert actual == expected, (
        "Findings drifted from the golden snapshot.\n"
        f"  removed: {sorted(set(expected) - set(actual))}\n"
        f"  added:   {sorted(set(actual) - set(expected))}\n"
        "If this change is intentional, update tests/fixtures/golden_app.expected.json."
    )
