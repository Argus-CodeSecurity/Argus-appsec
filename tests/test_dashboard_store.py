"""Dashboard storage: report timestamps, retention and file permissions."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("sqlmodel")

from sqlmodel import Session, select  # noqa: E402

from argus.core.models import ScanResult  # noqa: E402
from argus.dashboard import db, store  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_db(monkeypatch):
    monkeypatch.setenv("ARGUS_DASHBOARD_DB", ":memory:")
    db.reset_engine_for_tests()


def _report(target: str, when: datetime) -> str:
    return ScanResult(target=target, started_at=when, finished_at=when).model_dump_json()


def test_scan_time_is_clamped_to_now():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    future = ScanResult(target="x", started_at=now + timedelta(days=3650))
    past = ScanResult(target="x", started_at=now - timedelta(days=1))
    naive = ScanResult(target="x", started_at=datetime(2025, 6, 1))
    assert store._scan_time(future, now) == now
    assert store._scan_time(past, now) == now - timedelta(days=1)
    assert store._scan_time(naive, now) == datetime(2025, 6, 1, tzinfo=timezone.utc)


def test_far_future_report_does_not_stay_latest():
    with Session(db.get_engine()) as s:
        store.ingest_report(s, _report("demo", datetime(9999, 1, 1, tzinfo=timezone.utc)))
        real = store.ingest_report(s, _report("demo", datetime.now(timezone.utc)))
        latest = store.list_projects(s)[0]["latest"]
        assert latest.id == real.id


def test_enforce_retention_keeps_newest_and_drops_empty_projects():
    base = datetime.now(timezone.utc) - timedelta(hours=10)
    with Session(db.get_engine()) as s:
        for i, name in enumerate(["a", "b", "b", "c"]):
            store.ingest_report(s, _report(name, base + timedelta(hours=i)))
        assert store.enforce_retention(s, 2) == 2
        scans = s.exec(select(db.Scan)).all()
        assert len(scans) == 2
        assert sorted(p["project"].name for p in store.list_projects(s)) == ["b", "c"]
        assert store.enforce_retention(s, 2) == 0
        kept = {sc.id for sc in scans}
        assert {f.scan_id for f in s.exec(select(db.Finding)).all()} <= kept
