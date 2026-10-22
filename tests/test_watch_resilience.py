"""argus watch: failed pushes are retried, errors do not stop the loop, state stays bounded."""

from __future__ import annotations

import os
import stat
from datetime import datetime, timezone
from pathlib import Path

import pytest

from argus.core.models import Finding, Location, ScanResult, Severity
from argus.watch import scheduler
from argus.watch.scheduler import (
    latest_snapshot_path,
    load_snapshot,
    prune_snapshots,
    run_watch_cycle,
    run_watch_loop,
    state_dir_for,
)


def _scan(*rules: str) -> ScanResult:
    return ScanResult(
        target="repo",
        started_at=datetime.now(timezone.utc),
        findings=[
            Finding(
                id=f"x:{r}",
                rule_id=r,
                scanner="patterns",
                title=r,
                description="",
                location=Location(path="a.py", snippet="bad()"),
                severity=Severity.HIGH,
            )
            for r in rules
        ],
    )


def test_failed_push_does_not_advance_baseline(tmp_path: Path):
    store = tmp_path / "state"
    run_watch_cycle(scan_fn=lambda: _scan("r1"), state_dir=store)

    def failing_push(result):
        raise RuntimeError("cloud down")

    with pytest.raises(RuntimeError):
        run_watch_cycle(scan_fn=lambda: _scan("r1", "r2"), state_dir=store, push_fn=failing_push)
    latest = load_snapshot(latest_snapshot_path(store))
    assert latest is not None and [f.rule_id for f in latest.findings] == ["r1"]

    pushed: list[ScanResult] = []
    retry = run_watch_cycle(
        scan_fn=lambda: _scan("r1", "r2"),
        state_dir=store,
        push_fn=pushed.append,
        fail_on_drift=Severity.HIGH,
    )
    # The change is still reported as drift and is pushed on the retry.
    assert retry.drift is not None and len(retry.drift.added) == 1
    assert retry.exit_code == 1
    assert len(pushed) == 1


def test_commit_fn_runs_only_after_successful_push(tmp_path: Path):
    committed: list[int] = []

    def failing_push(result):
        raise RuntimeError("nope")

    with pytest.raises(RuntimeError):
        run_watch_cycle(
            scan_fn=lambda: _scan(),
            state_dir=tmp_path,
            push_fn=failing_push,
            commit_fn=lambda: committed.append(1),
        )
    assert committed == []
    run_watch_cycle(
        scan_fn=lambda: _scan(),
        state_dir=tmp_path,
        push_fn=lambda r: None,
        commit_fn=lambda: committed.append(1),
    )
    assert committed == [1]


def test_loop_survives_failing_cycles(tmp_path: Path, monkeypatch):
    calls = {"scan": 0, "sleep": 0}
    errors: list[Exception] = []

    def scan_fn():
        calls["scan"] += 1
        if calls["scan"] == 1:
            raise RuntimeError("scanner crashed")
        return _scan()

    def fake_sleep(seconds):
        calls["sleep"] += 1
        if calls["sleep"] >= 3:
            raise KeyboardInterrupt

    monkeypatch.setattr(scheduler.time, "sleep", fake_sleep)
    code = run_watch_loop(
        scan_fn=scan_fn,
        state_dir=tmp_path,
        interval_seconds=1,
        once=False,
        fail_on_drift=None,
        push_fn=None,
        on_error=errors.append,
    )
    assert code == 0
    assert calls["scan"] == 3  # kept going after the first failure
    assert len(errors) == 1 and "scanner crashed" in str(errors[0])


def test_once_mode_still_raises(tmp_path: Path):
    def boom():
        raise RuntimeError("x")

    with pytest.raises(RuntimeError):
        run_watch_loop(
            scan_fn=boom,
            state_dir=tmp_path,
            interval_seconds=1,
            once=True,
            fail_on_drift=None,
            push_fn=None,
        )


def test_archives_are_pruned(tmp_path: Path):
    for _ in range(5):
        run_watch_cycle(scan_fn=lambda: _scan(), state_dir=tmp_path, keep_snapshots=3)
    assert len(list(tmp_path.glob("scan-*.json"))) == 3
    assert latest_snapshot_path(tmp_path).is_file()
    assert prune_snapshots(tmp_path, 1) and len(list(tmp_path.glob("scan-*.json"))) == 1


def test_keep_snapshots_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv(scheduler.KEEP_SNAPSHOTS_ENV, "2")
    for _ in range(4):
        run_watch_cycle(scan_fn=lambda: _scan(), state_dir=tmp_path)
    assert len(list(tmp_path.glob("scan-*.json"))) == 2


def test_state_dir_names_are_unique_and_contained(tmp_path: Path):
    a = state_dir_for("org/repo", tmp_path)
    b = state_dir_for("org_repo", tmp_path)
    assert a != b  # sanitised forms collide; the hash suffix keeps them apart
    for hostile in ("..", ".", "../../etc", ""):
        d = state_dir_for(hostile, tmp_path)
        assert d.parent == tmp_path
        assert d.resolve().is_relative_to(tmp_path.resolve())
        assert d.name not in (".", "..")


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_snapshots_are_private(tmp_path: Path):
    store = tmp_path / "state"
    outcome = run_watch_cycle(scan_fn=lambda: _scan("r1"), state_dir=store)
    assert stat.S_IMODE(store.stat().st_mode) == 0o700
    assert stat.S_IMODE(outcome.snapshot_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(latest_snapshot_path(store).stat().st_mode) == 0o600
