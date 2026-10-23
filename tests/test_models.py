"""Tests for the core data models."""

from __future__ import annotations

from datetime import datetime, timezone

from nephilex.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    ScanResult,
    Severity,
)


def _finding(**kwargs) -> Finding:
    base = dict(
        id="x:1",
        rule_id="x.rule",
        scanner="x",
        title="t",
        description="d",
        location=Location(path="a.py", start_line=1),
    )
    base.update(kwargs)
    return Finding(**base)


def test_severity_parse_and_order():
    assert Severity.parse("high") is Severity.HIGH
    assert Severity.parse("CRITICAL") is Severity.CRITICAL
    assert Severity.parse(3) is Severity.HIGH
    assert Severity.CRITICAL > Severity.LOW


def test_risk_score_monotonic_in_severity():
    low = _finding(severity=Severity.LOW).risk_score()
    high = _finding(severity=Severity.HIGH).risk_score()
    crit = _finding(severity=Severity.CRITICAL).risk_score()
    assert low < high < crit
    assert 0 <= low <= 100 and 0 <= crit <= 100


def test_confidence_and_likelihood_raise_score():
    a = _finding(
        severity=Severity.HIGH, confidence=Confidence.LOW, likelihood=Likelihood.RARE
    ).risk_score()
    b = _finding(
        severity=Severity.HIGH, confidence=Confidence.HIGH, likelihood=Likelihood.ALMOST_CERTAIN
    ).risk_score()
    assert b > a


def test_scan_result_sorting_and_counts():
    result = ScanResult(target="t", started_at=datetime.now(timezone.utc))
    result.add(_finding(id="low", severity=Severity.LOW))
    result.add(_finding(id="crit", severity=Severity.CRITICAL))
    result.add(_finding(id="med", severity=Severity.MEDIUM))

    ordered = result.sorted_findings()
    assert [f.severity for f in ordered] == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]
    counts = result.counts_by_severity()
    assert counts["Critical"] == 1 and counts["Low"] == 1
    assert result.highest_severity() is Severity.CRITICAL


def test_aggregate_risk_dominated_by_worst():
    """A single critical should outweigh many lows."""
    only_lows = ScanResult(target="t", started_at=datetime.now(timezone.utc))
    for i in range(20):
        only_lows.add(_finding(id=f"l{i}", severity=Severity.LOW))

    one_crit = ScanResult(target="t", started_at=datetime.now(timezone.utc))
    one_crit.add(_finding(id="c", severity=Severity.CRITICAL))

    assert one_crit.aggregate_risk() > only_lows.aggregate_risk()


def test_fingerprint_stable():
    f1 = _finding()
    f2 = _finding()
    assert f1.fingerprint() == f2.fingerprint()


def test_empty_result_zero_risk():
    result = ScanResult(target="t", started_at=datetime.now(timezone.utc))
    assert result.aggregate_risk() == 0.0
