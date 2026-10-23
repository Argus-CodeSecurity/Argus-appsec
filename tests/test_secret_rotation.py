"""Secrets-rotation tracker: catch 'live and still not rotated' across scans."""

from __future__ import annotations

from datetime import date

from nephilex.core.models import Finding, Location, Severity
from nephilex.scanners import secret_verify
from nephilex.scanners.secret_rotation import RotationTracker, track_rotations


def _live_finding() -> Finding:
    return Finding(
        id="1",
        rule_id="secrets.aws-access-key-id",
        scanner="secrets",
        title="Hardcoded credential",
        description="d",
        location=Location(path="a.py", start_line=1, snippet="KEY = 'AKIAIOSFODNN7EXAMPLE'"),
        severity=Severity.CRITICAL,
        metadata={"verification": secret_verify.LIVE},
    )


def test_first_sighting_records_but_does_not_escalate(tmp_path):
    state = tmp_path / "rot.json"
    f = _live_finding()
    track_rotations([f], state, today=date(2026, 1, 1))
    assert "STILL LIVE" not in f.title
    assert RotationTracker.load(state).state  # recorded


def test_still_live_later_escalates(tmp_path):
    state = tmp_path / "rot.json"
    track_rotations([_live_finding()], state, today=date(2026, 1, 1))
    f2 = _live_finding()  # same fingerprint (same snippet/rule/path)
    track_rotations([f2], state, today=date(2026, 1, 11))
    assert "STILL LIVE after 10 day(s)" in f2.title
    assert f2.metadata["days_live"] == 10


def test_rotated_secret_is_pruned(tmp_path):
    state = tmp_path / "rot.json"
    track_rotations([_live_finding()], state, today=date(2026, 1, 1))
    track_rotations([], state, today=date(2026, 1, 5))  # no longer live -> resolved
    assert RotationTracker.load(state).state == {}


def test_non_live_findings_are_ignored(tmp_path):
    state = tmp_path / "rot.json"
    f = _live_finding()
    f.metadata["verification"] = secret_verify.INVALID
    track_rotations([f], state, today=date(2026, 1, 1))
    assert RotationTracker.load(state).state == {}
