"""CLI flags that carry operator intent into the core: bind safety, hooks."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from nephilex.cli.main import app

runner = CliRunner()


def test_dashboard_refuses_public_bind_without_token(monkeypatch):
    pytest.importorskip("fastapi")
    monkeypatch.delenv("NEPHILEX_DASHBOARD_TOKEN", raising=False)
    served: list[str] = []
    monkeypatch.setattr("nephilex.dashboard.app.serve", lambda **kw: served.append("x"))
    result = runner.invoke(app, ["dashboard", "--host", "0.0.0.0"])
    assert result.exit_code == 2
    assert "NEPHILEX_DASHBOARD_TOKEN" in result.output
    # No URL is announced and nothing is served for a refused bind.
    assert "http://0.0.0.0" not in result.output
    assert served == []


def test_fix_passes_no_verify_to_the_workflow(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    seen = {}

    def fake_workflow(project, findings, options):
        from nephilex.remediation.applier import ApplyReport
        from nephilex.remediation.pullrequest import FixOutcome

        seen["no_verify"] = options.no_verify
        return FixOutcome(applied=ApplyReport(dry_run=True))

    monkeypatch.setattr("nephilex.remediation.pullrequest.run_fix_workflow", fake_workflow)
    result = runner.invoke(app, ["fix", str(tmp_path), "--dry-run", "--no-verify", "-q"])
    assert result.exit_code == 0, result.output
    assert seen["no_verify"] is True

    seen.clear()
    runner.invoke(app, ["fix", str(tmp_path), "--dry-run", "-q"])
    assert seen["no_verify"] is False
