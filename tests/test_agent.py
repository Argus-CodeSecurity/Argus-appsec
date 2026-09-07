"""Tests for argus agent."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.agent.config import load_agent_config, write_default_agent_config


def test_load_agent_config(tmp_path: Path):
    cfg_path = tmp_path / "agent.yml"
    cfg_path.write_text(
        "interval: 120\n"
        "host_label: test-host\n"
        "targets:\n"
        "  - path: .\n"
        "    scanners: [secrets]\n",
        encoding="utf-8",
    )
    cfg = load_agent_config(cfg_path)
    assert cfg.interval == 120
    assert cfg.host_label == "test-host"
    assert len(cfg.targets) == 1
    assert cfg.targets[0].scanners == ["secrets"]


def test_load_agent_config_requires_targets(tmp_path: Path):
    cfg_path = tmp_path / "bad.yml"
    cfg_path.write_text("interval: 60\n", encoding="utf-8")
    with pytest.raises(ValueError, match="targets"):
        load_agent_config(cfg_path)


def test_write_default_agent_config(tmp_path: Path):
    path = tmp_path / ".argus" / "agent.yml"
    write_default_agent_config(path)
    assert path.is_file()
    cfg = load_agent_config(path)
    assert cfg.targets


def test_agent_cli_registered():
    import typer
    from argus.cli.main import app

    assert "agent" in typer.main.get_command(app).commands
