"""`argus watch` must see changes made between cycles."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

import argus.watch
from argus.cli.main import app

runner = CliRunner()


def test_each_watch_cycle_rescans_current_files(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    results = []

    def fake_loop(*, scan_fn, **_kwargs) -> int:
        results.append(scan_fn())
        # Change the tree between cycles: a new file and edited content.
        (repo / "keys.py").write_text('AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"\n',
                                      encoding="utf-8")
        results.append(scan_fn())
        return 0

    monkeypatch.setattr(argus.watch, "run_watch_loop", fake_loop)
    res = runner.invoke(app, ["watch", str(repo), "--scanners", "secrets",
                              "--state-dir", str(tmp_path / "state"), "--quiet"])
    assert res.exit_code == 0, res.output
    first, second = results
    assert not first.findings
    assert any(f.location.path == "keys.py" for f in second.findings)


def test_watch_bad_target_exits_2(tmp_path: Path) -> None:
    res = runner.invoke(app, ["watch", str(tmp_path / "missing"), "--once", "--quiet"])
    assert res.exit_code == 2, res.output
