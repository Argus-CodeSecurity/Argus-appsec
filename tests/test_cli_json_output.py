"""JSON written to stdout must be byte-for-byte parseable (no Rich wrapping/markup)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from nephilex.cli.main import app

runner = CliRunner()

_LONG = "a-really-long-package-name-that-would-be-soft-wrapped-by-rich-at-80-columns"


def _project(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    # The extras marker looks like Rich markup and the long name exceeds the
    # console width; either one used to corrupt the printed JSON.
    (tmp_path / "requirements.txt").write_text(
        f"{_LONG}==1.0.0\nrequests[security]==2.31.0\n", encoding="utf-8"
    )
    return tmp_path


def test_sbom_stdout_is_valid_json(tmp_path: Path) -> None:
    res = runner.invoke(app, ["sbom", str(_project(tmp_path))])
    assert res.exit_code == 0, res.output
    doc = json.loads(res.stdout)
    assert _LONG in json.dumps(doc)


def test_inventory_stdout_is_valid_json(tmp_path: Path) -> None:
    res = runner.invoke(app, ["inventory", str(_project(tmp_path)), "--quiet"])
    assert res.exit_code == 0, res.output
    payload = json.loads(res.stdout)
    assert _LONG in json.dumps(payload)
