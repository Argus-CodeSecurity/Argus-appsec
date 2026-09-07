"""Local continuous scan scheduler for Argus."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from argus.analysis.drift import ScanDriftReport, compare_scans, highest_added_severity
from argus.core.models import ScanResult, Severity

if TYPE_CHECKING:
    pass


@dataclass
class WatchCycleResult:
    scan: ScanResult
    drift: ScanDriftReport | None
    snapshot_path: Path
    exit_code: int = 0


def state_dir_for(target: str, base: Path) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in target)[:120]
    return base / safe


def latest_snapshot_path(state_dir: Path) -> Path:
    return state_dir / "latest.json"


def load_snapshot(path: Path) -> ScanResult | None:
    if not path.is_file():
        return None
    try:
        return ScanResult.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def save_snapshot(result: ScanResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")


def run_watch_cycle(
    *,
    scan_fn: Callable[[], ScanResult],
    state_dir: Path,
    fail_on_drift: Severity | None = None,
    push_fn: Callable[[ScanResult], None] | None = None,
) -> WatchCycleResult:
    """Run one scan, compare to the previous snapshot, persist the new one."""
    previous = load_snapshot(latest_snapshot_path(state_dir))
    result = scan_fn()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = state_dir / f"scan-{ts}.json"
    save_snapshot(result, archive)
    save_snapshot(result, latest_snapshot_path(state_dir))

    drift = compare_scans(previous, result) if previous else None
    if push_fn is not None:
        push_fn(result)

    exit_code = 0
    if drift and fail_on_drift and highest_added_severity(drift) >= fail_on_drift:
        exit_code = 1

    return WatchCycleResult(
        scan=result,
        drift=drift,
        snapshot_path=archive,
        exit_code=exit_code,
    )


def run_watch_loop(
    *,
    scan_fn: Callable[[], ScanResult],
    state_dir: Path,
    interval_seconds: int,
    once: bool,
    fail_on_drift: Severity | None,
    push_fn: Callable[[ScanResult], None] | None,
    on_cycle: Callable[[WatchCycleResult], None] | None = None,
) -> int:
    """Run watch cycles until interrupted or ``once`` is set."""
    worst = 0
    while True:
        outcome = run_watch_cycle(
            scan_fn=scan_fn,
            state_dir=state_dir,
            fail_on_drift=fail_on_drift,
            push_fn=push_fn,
        )
        if on_cycle:
            on_cycle(outcome)
        worst = max(worst, outcome.exit_code)
        if once:
            return worst
        try:
            time.sleep(max(1, interval_seconds))
        except KeyboardInterrupt:
            return worst
