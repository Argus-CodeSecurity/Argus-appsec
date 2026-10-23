"""Local continuous scan scheduler for Nephilex.

Each cycle scans, compares against the last snapshot, pushes (when enabled)
and only then advances ``latest.json``. If the push fails the snapshot is not
advanced, so the next cycle diffs against the same baseline and the change is
pushed again instead of being lost. A failing cycle in a long-running loop is
logged and the loop keeps going.

Snapshots contain findings for the monitored code, so state directories are
created ``0700`` and files ``0600`` where the OS supports POSIX modes, and old
archives are pruned to the newest ``keep_snapshots``.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from nephilex.analysis.drift import ScanDriftReport, compare_scans, highest_added_severity
from nephilex.core.models import ScanResult, Severity

log = logging.getLogger("nephilex.watch")

#: Archived ``scan-*.json`` snapshots kept per state directory by default.
DEFAULT_KEEP_SNAPSHOTS = 50
#: Environment override for :data:`DEFAULT_KEEP_SNAPSHOTS`.
KEEP_SNAPSHOTS_ENV = "NEPHILEX_WATCH_KEEP_SNAPSHOTS"


@dataclass
class WatchCycleResult:
    scan: ScanResult
    drift: ScanDriftReport | None
    snapshot_path: Path
    exit_code: int = 0


def state_dir_for(target: str, base: Path) -> Path:
    """A per-target directory under ``base``.

    The readable prefix is sanitised and the name ends with a short sha256 of
    the full target, so distinct targets never share a directory (even when
    their sanitised forms collide or are truncated) and names like ``..``
    cannot step outside ``base``.
    """
    digest = hashlib.sha256(target.encode("utf-8")).hexdigest()[:12]
    # Keep the readable part short: Windows paths are still limited to 260 chars.
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in target)[-60:]
    safe = safe.strip(".") or "target"
    return base / f"{safe}-{digest}"


def latest_snapshot_path(state_dir: Path) -> Path:
    return state_dir / "latest.json"


def _keep_default() -> int:
    raw = os.environ.get(KEEP_SNAPSHOTS_ENV, "")
    try:
        return max(1, int(raw)) if raw else DEFAULT_KEEP_SNAPSHOTS
    except ValueError:
        return DEFAULT_KEEP_SNAPSHOTS


def ensure_private_dir(path: Path) -> None:
    """Create ``path`` (and parents) and restrict it to the owner on POSIX."""
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        with contextlib.suppress(OSError):
            os.chmod(path, 0o700)


def write_private_file(path: Path, data: str) -> None:
    """Atomically write ``data`` to ``path`` with mode 0600 (POSIX)."""
    ensure_private_dir(path.parent)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data.encode("utf-8"))
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


def load_snapshot(path: Path) -> ScanResult | None:
    if not path.is_file():
        return None
    try:
        return ScanResult.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def save_snapshot(result: ScanResult, path: Path) -> None:
    write_private_file(path, result.model_dump_json(indent=2) + "\n")


def prune_snapshots(state_dir: Path, keep: int) -> list[Path]:
    """Delete all but the newest ``keep`` archived snapshots. Returns removed paths."""

    def _age(p: Path) -> tuple[int, str]:
        try:
            return (p.stat().st_mtime_ns, p.name)
        except OSError:
            return (0, p.name)

    archives = sorted(state_dir.glob("scan-*.json"), key=_age)
    stale = archives[: max(0, len(archives) - max(1, keep))]
    for path in stale:
        with contextlib.suppress(OSError):
            path.unlink()
    return stale


def _archive_path(state_dir: Path) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = state_dir / f"scan-{ts}.json"
    n = 1
    while path.exists():  # two cycles in the same second
        path = state_dir / f"scan-{ts}-{n}.json"
        n += 1
    return path


def run_watch_cycle(
    *,
    scan_fn: Callable[[], ScanResult],
    state_dir: Path,
    fail_on_drift: Severity | None = None,
    push_fn: Callable[[ScanResult], None] | None = None,
    commit_fn: Callable[[], None] | None = None,
    keep_snapshots: int | None = None,
) -> WatchCycleResult:
    """Run one scan, compare to the previous snapshot, push, then persist.

    ``latest.json`` (and anything ``commit_fn`` persists, e.g. an integrity
    baseline) is only written after ``push_fn`` succeeds. If the scan or the
    push raises, the exception propagates and the baseline is untouched, so
    the next cycle reports and pushes the same change again.
    """
    previous = load_snapshot(latest_snapshot_path(state_dir))
    result = scan_fn()
    drift = compare_scans(previous, result) if previous else None

    archive = _archive_path(state_dir)
    save_snapshot(result, archive)
    prune_snapshots(state_dir, keep_snapshots if keep_snapshots is not None else _keep_default())

    if push_fn is not None:
        push_fn(result)
    save_snapshot(result, latest_snapshot_path(state_dir))
    if commit_fn is not None:
        commit_fn()

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
    on_error: Callable[[Exception], None] | None = None,
    keep_snapshots: int | None = None,
) -> int:
    """Run watch cycles until interrupted or ``once`` is set.

    With ``once`` an error propagates to the caller (nothing was persisted, so
    a rerun retries). Otherwise a failed cycle is logged, passed to
    ``on_error`` and the loop continues with the next interval.
    """
    worst = 0
    while True:
        try:
            outcome = run_watch_cycle(
                scan_fn=scan_fn,
                state_dir=state_dir,
                fail_on_drift=fail_on_drift,
                push_fn=push_fn,
                keep_snapshots=keep_snapshots,
            )
        except Exception as exc:
            if once:
                raise
            log.error("watch cycle failed, will retry next interval: %s", exc)
            if on_error:
                on_error(exc)
        else:
            if on_cycle:
                on_cycle(outcome)
            worst = max(worst, outcome.exit_code)
        if once:
            return worst
        try:
            time.sleep(max(1, interval_seconds))
        except KeyboardInterrupt:
            return worst
