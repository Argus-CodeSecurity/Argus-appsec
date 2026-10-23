"""Deeply nested YAML is rejected cleanly wherever Nephilex reads YAML.

PyYAML parses recursively, so a few thousand nested brackets exhaust the stack
and raise RecursionError, which is not a yaml.YAMLError. Found by the fuzz
harnesses in fuzz/. Each reader must turn it into its normal error, or skip the
file, instead of crashing the run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nephilex.agent.config import load_agent_config
from nephilex.context.schema import parse_context
from nephilex.core.config import Config, ConfigError
from nephilex.exceptions import load_exceptions
from nephilex.scanners import custom_rules, dast

DEEP = "[" * 5000


def test_config_rejects_deep_nesting() -> None:
    with pytest.raises(ConfigError, match="nested too deeply"):
        Config.from_yaml(DEEP)


def test_context_rejects_deep_nesting() -> None:
    with pytest.raises(ConfigError, match="nested too deeply"):
        parse_context(DEEP)


def test_exceptions_file_rejects_deep_nesting(tmp_path: Path) -> None:
    path = tmp_path / "exceptions.yml"
    path.write_text(DEEP, encoding="utf-8")
    with pytest.raises(ConfigError, match="cannot read exceptions file"):
        load_exceptions(path)


def test_custom_rules_file_is_skipped(tmp_path: Path) -> None:
    path = tmp_path / "rules.yml"
    path.write_text(DEEP, encoding="utf-8")
    assert custom_rules._load_file(path) == []


def test_dast_ignores_a_deeply_nested_project_config(tmp_path: Path) -> None:
    (tmp_path / ".nephilex.yml").write_text(DEEP, encoding="utf-8")
    assert dast._project_declared_urls(tmp_path) == set()


def test_agent_config_rejects_deep_nesting(tmp_path: Path) -> None:
    path = tmp_path / "agent.yml"
    path.write_text(DEEP, encoding="utf-8")
    with pytest.raises(ValueError, match="not valid YAML"):
        load_agent_config(path)
