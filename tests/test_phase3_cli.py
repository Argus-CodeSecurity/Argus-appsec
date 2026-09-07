"""CLI focused infrastructure commands."""

from __future__ import annotations

from pathlib import Path

from argus.core.config import Config
from argus.core.plugin import ScannerContext
from argus.core.project import Project
from argus.scanners.cicd import CicdScanner


def test_cicd_cli_helper_finds_workflow_issue(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows" / "ci.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text(
        "on:\n  pull_request_target:\njobs:\n  x:\n    steps:\n"
        "      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    ctx = ScannerContext(project=Project.from_path(tmp_path), config=Config())
    rules = {f.rule_id for f in CicdScanner().scan(ctx)}
    assert "cicd.pull-request-target" in rules


def test_cli_registers_infrastructure_commands() -> None:
    import typer
    from argus.cli.main import app

    click_app = typer.main.get_command(app)
    names = set(click_app.commands)
    assert {"cicd", "container", "cloud"}.issubset(names)
