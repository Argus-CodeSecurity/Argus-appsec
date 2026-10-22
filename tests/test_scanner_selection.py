"""Scanner selection fails closed on typos and survives broken applicability checks."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from argus.cli.main import app
from argus.core.config import Config, ConfigError
from argus.core.engine import ScanEngine
from argus.core.models import Finding
from argus.core.plugin import Scanner, ScannerContext, registry
from argus.core.project import Project

runner = CliRunner()


def _project(tmp_path: Path) -> Project:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    return Project.from_path(tmp_path)


def _cfg(**kwargs) -> Config:
    cfg = Config(**kwargs)
    cfg.ai.enabled = False
    cfg.cache = False
    return cfg


def test_unknown_scanner_name_is_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="secret"):
        ScanEngine(_cfg(scanners=["secret"])).scan(_project(tmp_path))


def test_excluding_everything_requested_is_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="no scanners"):
        ScanEngine(_cfg(scanners=["secrets"], exclude_scanners=["secrets"])).scan(
            _project(tmp_path)
        )


def test_cli_unknown_scanner_exits_2(tmp_path: Path) -> None:
    _project(tmp_path)
    res = runner.invoke(
        app, ["scan", str(tmp_path), "--scanners", "secret", "--quiet", "--no-ai", "--no-cache"]
    )
    assert res.exit_code == 2, res.output


def test_yaml_string_scanners_is_rejected(tmp_path: Path) -> None:
    _project(tmp_path)
    (tmp_path / ".argus.yml").write_text("scanners: patterns\n", encoding="utf-8")
    res = runner.invoke(app, ["scan", str(tmp_path), "--quiet", "--no-ai", "--no-cache"])
    assert res.exit_code == 2, res.output


class _ExplodingApplies(Scanner):
    name = "test-exploding-applies"
    description = "test only"

    def applies_to(self, project: Project) -> bool:
        raise AttributeError("'int' object has no attribute 'get'")

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:  # pragma: no cover
        return []


def test_applies_to_crash_is_recorded_not_fatal(tmp_path: Path, monkeypatch) -> None:
    scanners = dict(registry.scanners())
    scanners[_ExplodingApplies.name] = _ExplodingApplies
    monkeypatch.setattr(registry, "scanners", lambda: dict(scanners))

    cfg = _cfg(scanners=[_ExplodingApplies.name, "secrets"])
    engine = ScanEngine(cfg)
    result = engine.scan(_project(tmp_path))
    assert result.scanners_failed == [_ExplodingApplies.name]
    assert any("test-exploding-applies" in e for e in result.errors)
    assert "secrets" in result.scanners_run
