"""Policies are validated up front; a policy gate never fails open on a typo."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nephilex.cli.main import app
from nephilex.core.models import Finding, Location, ScanResult, Severity
from nephilex.policy import PolicyError, evaluate, load_policies

runner = CliRunner()


def _result() -> ScanResult:
    r = ScanResult(target=".", started_at=datetime.now(timezone.utc))
    r.add(
        Finding(
            id="secrets:x:1",
            rule_id="secrets.aws-key",
            scanner="secrets",
            title="AWS key",
            description="d",
            severity=Severity.HIGH,
            location=Location(path="a.py", start_line=1),
        )
    )
    return r


@pytest.mark.parametrize(
    "policies",
    [
        "block-all",
        [{"when": {"severity": "high"}, "action": "block"}],  # no id
        [{"id": "x", "when": {"severity": "high"}, "action": "deny"}],  # bad action
        [{"id": "x", "when": {"severity": "high"}}],  # no action
        [{"id": "x", "when": {"scaner": "secrets"}, "action": "block"}],  # typo key
        [{"id": "x", "when": {}, "action": "block"}],  # empty when
        [{"id": "x", "when": {"severity": "hgih"}, "action": "block"}],  # bad severity
        [{"id": "x", "when": {"scanner": None}, "action": "block"}],  # null value
        [{"id": "x", "when": {"scanner": "secrets"}, "action": "block", "ation": "warn"}],
        [
            {"id": "x", "when": {"scanner": "a"}, "action": "block"},
            {"id": "x", "when": {"scanner": "b"}, "action": "warn"},
        ],  # duplicate id
        ["block"],
    ],
)
def test_invalid_policies_raise(policies) -> None:
    with pytest.raises(PolicyError):
        load_policies(policies)
    if isinstance(policies, list):
        with pytest.raises(PolicyError):
            evaluate(_result(), policies)


def test_valid_policies_load_from_list_or_config_mapping() -> None:
    policies = [{"id": "block-secrets", "when": {"scanner": "secrets"}, "action": "BLOCK"}]
    assert load_policies(policies)[0]["action"] == "block"
    assert load_policies({"policies": policies})[0]["id"] == "block-secrets"
    outcome = evaluate(_result(), policies)
    assert not outcome.passed


def _project(tmp_path: Path, config: str) -> Path:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / ".nephilex.yml").write_text(config, encoding="utf-8")
    return tmp_path


def test_cli_invalid_policy_exits_2(tmp_path: Path) -> None:
    project = _project(
        tmp_path, "policies:\n  - id: x\n    when:\n      scaner: secrets\n    action: block\n"
    )
    res = runner.invoke(app, ["policy", "check", str(project), "--scanners", "secrets", "--quiet"])
    assert res.exit_code == 2, res.output


def test_cli_no_policies_exits_2(tmp_path: Path) -> None:
    project = _project(tmp_path, "fail_on: high\n")
    res = runner.invoke(app, ["policy", "check", str(project), "--scanners", "secrets", "--quiet"])
    assert res.exit_code == 2, res.output


def test_cli_valid_policy_passes_on_clean_project(tmp_path: Path) -> None:
    project = _project(
        tmp_path, "policies:\n  - id: x\n    when:\n      scanner: secrets\n    action: block\n"
    )
    res = runner.invoke(app, ["policy", "check", str(project), "--scanners", "secrets", "--quiet"])
    assert res.exit_code == 0, res.output
