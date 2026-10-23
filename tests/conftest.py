"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from nephilex.core.config import Config
from nephilex.core.project import Project
from nephilex.plugins import register_builtins

register_builtins()


@pytest.fixture(autouse=True)
def _isolated_scan_cache(tmp_path_factory, monkeypatch):
    """Point the scan/OSV caches at a per-session temp dir.

    Keeps test runs from reading stale entries out of (or littering) the real
    ~/.cache/nephilex. Cache behavior itself is exercised in test_cache.py.
    """
    monkeypatch.setenv("NEPHILEX_CACHE_DIR", str(tmp_path_factory.mktemp("nephilex-cache")))


@pytest.fixture(autouse=True)
def _offline_osv(request, monkeypatch):
    """Keep the whole suite offline and deterministic.

    The dependency scanner queries OSV over the network by default. In tests we
    force that to fail so it falls back to the bundled advisory seed. Tests that
    exercise the OSV client directly opt out with @pytest.mark.osv_network (and
    inject a mock transport), so they still never touch the real network.
    """
    if request.node.get_closest_marker("osv_network"):
        return
    from nephilex.scanners import osv

    def _raise(*args, **kwargs):
        raise osv.OSVError("network disabled in tests")

    monkeypatch.setattr(osv, "query", _raise)


@pytest.fixture(autouse=True)
def _offline_exploit_signals(request, monkeypatch):
    """Disable EPSS/KEV enrichment in tests unless explicitly exercised.

    Mirrors _offline_osv: the dependency scanner enriches CVE findings over the
    network by default. Force it to a no-op so the suite stays offline and fast.
    Tests that exercise the client opt in with @pytest.mark.exploit_network and
    inject a mock transport, so they still never touch the real network.
    """
    if request.node.get_closest_marker("exploit_network"):
        return
    from nephilex.scanners import exploit_signals

    monkeypatch.setattr(exploit_signals, "enrich", lambda *a, **k: {})


@pytest.fixture
def vulnerable_project(tmp_path: Path) -> Project:
    """A tiny project with one planted vulnerability of each major class."""
    (tmp_path / "app.py").write_text(
        "import hashlib, subprocess, yaml\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
        '@app.route("/user")\n'
        "def q():\n"
        '    uid = request.args.get("id")\n'
        "    cursor.execute(\"SELECT * FROM users WHERE id = '%s'\" % uid)\n"
        '@app.route("/ping")\n'
        "def run():\n"
        '    subprocess.run("ping " + request.args.get("host"), shell=True)\n'
        "def load(raw):\n"
        "    return yaml.load(raw)\n"
        "def h(p):\n"
        "    return hashlib.md5(p.encode()).hexdigest()\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\npyyaml==5.3.1\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(
        'FROM python:latest\nCOPY . /app\nCMD ["python", "app.py"]\n',
        encoding="utf-8",
    )
    return Project.from_path(tmp_path)


@pytest.fixture
def clean_project(tmp_path: Path) -> Project:
    """A project with no planted vulnerabilities."""
    (tmp_path / "main.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    return Project.from_path(tmp_path)


@pytest.fixture
def default_config() -> Config:
    return Config()
