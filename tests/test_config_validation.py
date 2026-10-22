"""Config values are type-checked, never coerced into something else."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from argus.cli.main import app
from argus.core.config import Config, ConfigError
from argus.core.models import Severity

runner = CliRunner()


@pytest.mark.parametrize("key", ["scanners", "exclude_scanners", "exclude_paths"])
def test_string_where_list_expected_is_rejected(key: str) -> None:
    # list("dist/*") would be ['d', 'i', ..., '*'] and '*' excludes every file.
    with pytest.raises(ConfigError, match=key):
        Config.from_dict({key: "dist/*"})


def test_non_string_list_items_are_rejected() -> None:
    with pytest.raises(ConfigError):
        Config.from_dict({"exclude_paths": ["ok/**", 3]})


def test_valid_lists_load() -> None:
    cfg = Config.from_dict({"scanners": ["secrets", "patterns"],
                            "exclude_paths": ["dist/*"], "exclude_scanners": None})
    assert cfg.scanners == ["secrets", "patterns"]
    assert cfg.exclude_paths == ["dist/*"]
    assert cfg.exclude_scanners == []


@pytest.mark.parametrize("data", [
    {"cache": "false"},
    {"fail_on_error": "yes"},
    {"scanner_options": ["secrets"]},
    {"scanner_options": {"secrets": "on"}},
    {"allow": {"rule": "x"}},
    {"allow": ["x"]},
    {"policies": "block-all"},
    {"ai": "anthropic"},
    {"ai": {"enabled": "no"}},
    {"ai": {"max_tokens": "lots"}},
    {"fail_on": "hgih"},
    {"min_severity": "everything"},
])
def test_wrong_types_are_config_errors(data: dict) -> None:
    with pytest.raises(ConfigError):
        Config.from_dict(data)


def test_severities_parse() -> None:
    cfg = Config.from_dict({"fail_on": "High", "min_severity": "low", "fail_on_error": True})
    assert cfg.fail_on is Severity.HIGH
    assert cfg.min_severity is Severity.LOW
    assert cfg.fail_on_error is True


def test_yaml_top_level_must_be_mapping(tmp_path: Path) -> None:
    (tmp_path / ".argus.yml").write_text("- scanners\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="mapping"):
        Config.load(project_root=tmp_path)


def test_invalid_yaml_is_config_error(tmp_path: Path) -> None:
    (tmp_path / ".argus.yml").write_text("scanners: [\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="YAML"):
        Config.load(project_root=tmp_path)


def test_missing_explicit_config_is_still_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        Config.load(path=tmp_path / "nope.yml")


def test_cli_exits_2_on_invalid_config(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    cfg = tmp_path / "bad.yml"
    cfg.write_text("exclude_paths: 'dist/*'\n", encoding="utf-8")
    res = runner.invoke(app, ["scan", str(tmp_path), "-c", str(cfg), "--quiet", "--no-ai"])
    assert res.exit_code == 2, res.output
    assert "exclude_paths" in res.output

    res = runner.invoke(app, ["secrets", str(tmp_path), "-c", str(cfg), "--quiet"])
    assert res.exit_code == 2, res.output


def test_cli_unknown_profile_exits_2(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    res = runner.invoke(app, ["scan", str(tmp_path), "--profile", "turbo", "--quiet"])
    assert res.exit_code == 2, res.output
