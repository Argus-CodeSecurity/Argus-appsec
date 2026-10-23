"""``scan`` and ``check`` report the same rule for the same line.

When the regex and AST tiers both catch one weakness and tie on confidence and
severity, the engine used to keep whichever scanner ran first. ``scan`` and
``check`` run scanners in different orders, so a tainted ``yaml.load`` was
``patterns.python-yaml-load`` in one and ``ast-python.ast-unsafe-deserialization``
in the other, and ``check`` lost the deterministic fix an editor applies.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nephilex.cli.main import app

APP = """\
import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/load")
def load():
    raw = request.args.get("data")
    return str(yaml.load(raw))
"""

runner = CliRunner()


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    return tmp_path


def _at_line(doc: dict, line: int) -> list[dict]:
    return [
        f
        for f in doc["findings"]
        if f["location"].get("start_line") == line and "CWE-502" in f.get("cwe", [])
    ]


def test_scan_and_check_choose_the_same_finding(project: Path) -> None:
    scan = runner.invoke(app, ["scan", ".", "--no-ai", "--no-cache", "-q", "-f", "json"])
    check = runner.invoke(app, ["check", "app.py", "--no-cache", "-q", "-f", "json"])
    scan_hits = _at_line(json.loads(scan.stdout), 10)
    check_hits = _at_line(json.loads(check.stdout), 10)
    assert [f["rule_id"] for f in scan_hits] == [f["rule_id"] for f in check_hits]
    assert len(check_hits) == 1


def test_check_keeps_the_deterministic_fix(project: Path) -> None:
    check = runner.invoke(app, ["check", "app.py", "--no-cache", "-q", "-f", "json"])
    (finding,) = _at_line(json.loads(check.stdout), 10)
    assert finding["rule_id"] == "patterns.python-yaml-load"
    assert finding["remediation"]["verified"] is True
    assert "yaml.safe_load(raw)" in finding["remediation"]["patch"]
