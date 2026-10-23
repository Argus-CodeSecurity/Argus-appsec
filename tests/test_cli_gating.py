"""CLI gating must fail closed: bad input is a usage error (exit 2), never a pass."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from nephilex.cli.main import app
from nephilex.core.models import Severity

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
    res = runner.invoke(
        app, ["scan", str(_clean_project(tmp_path)), flag, "hgih", "--quiet", "--no-ai"]
    )
    assert res.exit_code == 2, res.output


def test_focused_scan_bad_fail_on_is_usage_error(tmp_path: Path) -> None:
    res = runner.invoke(
        app, ["secrets", str(_clean_project(tmp_path)), "--fail-on", "nope", "--quiet"]
    )
    assert res.exit_code == 2, res.output


# --- scanner crashes must not pass a gate -----------------------------------
@pytest.fixture
def crashing_secrets(monkeypatch):
    """Make the secrets scanner crash, as a parser bug on hostile input would."""
    from nephilex.core.plugin import registry

    cls = registry.get_scanner("secrets")

    def boom(self, ctx):
        raise RuntimeError("parser exploded")

    monkeypatch.setattr(cls, "scan", boom)
    monkeypatch.setattr(cls, "cacheable", lambda self, ctx: False)


def test_config_errors_fail_gate_defaults() -> None:
    from nephilex.core.config import Config

    assert Config().errors_fail_gate(gating=True) is True
    assert Config().errors_fail_gate(gating=False) is False
    assert Config(fail_on_error=False).errors_fail_gate(gating=True) is False
    assert Config(fail_on_error=True).errors_fail_gate(gating=False) is True


def test_scan_fails_on_scanner_error_when_gating(tmp_path: Path, crashing_secrets) -> None:
    project = str(_clean_project(tmp_path))
    base = [
        "scan",
        project,
        "--scanners",
        "secrets",
        "--quiet",
        "--no-ai",
        "--no-cache",
        "-f",
        "json",
    ]
    assert runner.invoke(app, [*base, "--fail-on", "critical"]).exit_code == 1
    assert runner.invoke(app, [*base, "--fail-on", "critical", "--no-fail-on-error"]).exit_code == 0
    # Without a threshold the run does not gate, so errors are only reported.
    assert runner.invoke(app, base).exit_code == 0


def test_focused_scan_fails_on_scanner_error(tmp_path: Path, crashing_secrets) -> None:
    project = str(_clean_project(tmp_path))
    res = runner.invoke(app, ["secrets", project, "--fail-on", "critical", "--quiet"])
    assert res.exit_code == 1, res.output
    assert runner.invoke(app, ["secrets", project, "--quiet"]).exit_code == 0


def test_policy_check_fails_on_scanner_error(tmp_path: Path, crashing_secrets) -> None:
    project = _clean_project(tmp_path)
    (project / ".nephilex.yml").write_text(
        "policies:\n  - id: block-secrets\n    when:\n      scanner: secrets\n    action: block\n",
        encoding="utf-8",
    )
    res = runner.invoke(app, ["policy", "check", str(project), "--scanners", "secrets", "--quiet"])
    assert res.exit_code == 1, res.output
