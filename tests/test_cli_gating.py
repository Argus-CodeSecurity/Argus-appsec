"""CLI gating must fail closed: bad input is a usage error (exit 2), never a pass."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from argus.cli.main import app
from argus.core.models import Severity

runner = CliRunner()


def _clean_project(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return tmp_path


def test_severity_parse_rejects_unknown_with_value_error() -> None:
    with pytest.raises(ValueError, match="critical"):
        Severity.parse("hgih")
    with pytest.raises(ValueError):
        Severity.parse(42)
    assert Severity.parse(" High ") is Severity.HIGH


@pytest.mark.parametrize("flag", ["--fail-on", "--min-severity"])
def test_scan_bad_severity_is_usage_error(tmp_path: Path, flag: str) -> None:
    res = runner.invoke(app, ["scan", str(_clean_project(tmp_path)), flag, "hgih",
                              "--quiet", "--no-ai"])
    assert res.exit_code == 2, res.output


def test_focused_scan_bad_fail_on_is_usage_error(tmp_path: Path) -> None:
    res = runner.invoke(app, ["secrets", str(_clean_project(tmp_path)),
                              "--fail-on", "nope", "--quiet"])
    assert res.exit_code == 2, res.output
