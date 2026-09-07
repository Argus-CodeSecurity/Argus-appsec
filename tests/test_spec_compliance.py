"""Tests for scan profiles and host posture."""

from __future__ import annotations

import pytest

from argus.profiles import PROFILES, apply_profile


def test_apply_profile_fast():
    scanners = apply_profile("fast")
    assert "secrets" in scanners
    assert "dependencies" in scanners


def test_apply_profile_standard_empty():
    assert apply_profile("standard") == []


def test_unknown_profile():
    with pytest.raises(ValueError, match="Unknown profile"):
        apply_profile("nope")


def test_all_profiles_documented():
    assert set(PROFILES.keys()) == {"fast", "standard", "deep", "supply-chain", "ci", "production"}


def test_host_assess_returns_scan():
    from argus.agent.host_posture import assess_host

    result = assess_host(label="test-host")
    assert result.target == "host:test-host"
    assert result.scanners_run == ["host"]


def test_fim_first_run_no_findings(tmp_path):
    from argus.agent.fim import check_integrity

    f = tmp_path / "cfg.txt"
    f.write_text("v1\n", encoding="utf-8")
    state = tmp_path / "integrity.json"
    r1 = check_integrity([str(f)], state)
    assert r1.findings == []
    f.write_text("v2\n", encoding="utf-8")
    r2 = check_integrity([str(f)], state)
    assert any(x.rule_id == "fim.content-changed" for x in r2.findings)


def test_baseline_and_server_cli_registered():
    import typer

    from argus.cli.main import app

    cmds = typer.main.get_command(app).commands
    assert "baseline" in cmds
    assert "server" in cmds
    assert "secrets" in cmds
    assert "iac" in cmds
    assert "api" in cmds
