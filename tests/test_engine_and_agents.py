"""Tests for the scan engine, agents, and the heuristic provider path."""

from __future__ import annotations

import pytest

from nephilex.ai.factory import build_provider
from nephilex.core.config import AIConfig, Config
from nephilex.core.engine import ScanEngine
from nephilex.core.models import Severity


def test_full_scan_offline(vulnerable_project):
    """The default (offline) pipeline produces enriched, sorted findings."""
    cfg = Config(attack_simulation=True, generate_patches=True)
    result = ScanEngine(cfg).scan(vulnerable_project)

    assert result.findings
    # Sorted: first finding is the most severe.
    assert result.findings[0].severity == result.highest_severity()
    # Enrichment filled reasoning on every finding.
    assert all(f.why_vulnerable for f in result.findings)


def test_attack_simulation_on_high_severity(vulnerable_project):
    cfg = Config(attack_simulation=True)
    result = ScanEngine(cfg).scan(vulnerable_project)
    sims = [f for f in result.findings if f.exploit is not None]
    assert sims, "expected at least one attack simulation"
    ex = sims[0].exploit
    assert ex.discovery and ex.exploit_walkthrough and ex.sandbox_ok


def test_patch_generation_verified(vulnerable_project):
    cfg = Config(generate_patches=True)
    result = ScanEngine(cfg).scan(vulnerable_project)
    patched = [f for f in result.findings if f.remediation and f.remediation.patch]
    assert patched, "expected at least one generated patch"
    # yaml.load / md5 / shell=True fixes are deterministic and self-verified.
    assert any(f.remediation.verified for f in patched)


def test_min_severity_filter(vulnerable_project):
    cfg = Config(min_severity=Severity.CRITICAL)
    result = ScanEngine(cfg).scan(vulnerable_project)
    assert all(f.severity >= Severity.CRITICAL for f in result.findings)


def test_fail_on_gating(vulnerable_project):
    cfg = Config(fail_on=Severity.HIGH)
    engine = ScanEngine(cfg)
    result = engine.scan(vulnerable_project)
    assert engine.should_fail(result) is True

    cfg2 = Config(fail_on=None)
    engine2 = ScanEngine(cfg2)
    assert engine2.should_fail(result) is False


def test_scanner_selection(vulnerable_project):
    cfg = Config(scanners=["secrets"])
    result = ScanEngine(cfg).scan(vulnerable_project)
    assert set(result.scanners_run) == {"secrets"}
    assert all(f.scanner == "secrets" for f in result.findings)


def test_provider_fallback_to_heuristic():
    """Requesting an unavailable provider falls back rather than failing."""
    with pytest.warns(UserWarning, match="not available"):
        provider = build_provider(AIConfig(provider="anthropic"))
    # No key/SDK in the test environment -> heuristic.
    assert provider.name == "heuristic"
    assert provider.is_remote is False


def test_unknown_provider_falls_back():
    with pytest.warns(UserWarning, match="Unknown AI provider"):
        provider = build_provider(AIConfig(provider="does-not-exist"))
    assert provider.name == "heuristic"
