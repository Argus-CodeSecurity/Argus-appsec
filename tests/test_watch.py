"""Tests for argus watch scheduler."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from argus.core.models import Finding, Location, ScanResult, Severity
from argus.watch.scheduler import (
    latest_snapshot_path,
    load_snapshot,
    run_watch_cycle,
    run_watch_loop,
    state_dir_for,
)


def _scan(target: str, *findings: Finding) -> ScanResult:
    return ScanResult(
        target=target,
        started_at=datetime.now(timezone.utc),
        argus_version="0.8.0",
        findings=list(findings),
    )


def _f(rule: str) -> Finding:
    return Finding(
        id=f"x:{rule}", rule_id=rule, scanner="patterns", title=rule,
        description="", location=Location(path="a.py", snippet="bad()"),
        severity=Severity.HIGH,
    )


def test_state_dir_sanitizes_target():
    assert state_dir_for("https://github.com/org/repo", Path(".argus/watch")).name.startswith("https")


def test_watch_cycle_persists_and_detects_drift(tmp_path: Path):
    store = tmp_path / "state"
    calls = {"n": 0}

    def scan_fn():
        calls["n"] += 1
        return _scan("repo", _f("r1")) if calls["n"] == 1 else _scan("repo", _f("r2"))

    first = run_watch_cycle(scan_fn=scan_fn, state_dir=store, fail_on_drift=None)
    assert first.drift is None
    assert load_snapshot(latest_snapshot_path(store)) is not None

    second = run_watch_cycle(scan_fn=scan_fn, state_dir=store, fail_on_drift=Severity.HIGH)
    assert second.drift is not None
    assert len(second.drift.added) == 1
    assert second.exit_code == 1


def test_watch_once_exits(tmp_path: Path):
    code = run_watch_loop(
        scan_fn=lambda: _scan("once"),
        state_dir=tmp_path / "s",
        interval_seconds=1,
        once=True,
        fail_on_drift=None,
        push_fn=None,
    )
    assert code == 0


def test_watch_cli_registered():
    import typer

    from argus.cli.main import app

    assert "watch" in typer.main.get_command(app).commands
