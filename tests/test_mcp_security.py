"""MCP server: path confinement, untrusted scan trees, timeouts and UTF-8 stdio."""

from __future__ import annotations

import io
import json
import os
import time

import pytest

from nephilex.mcp import server


def _call(path: str) -> dict:
    resp = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "nephilex_scan", "arguments": {"path": path}},
        }
    )
    return resp["result"]


@pytest.fixture
def root(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.chdir(workspace)
    monkeypatch.delenv(server.ROOTS_ENV, raising=False)
    return workspace


def test_scan_inside_working_directory_is_allowed(root):
    result = _call(".")
    assert result["isError"] is False
    assert json.loads(result["content"][0]["text"])["summary"]["total_findings"] >= 0


@pytest.mark.parametrize(
    "path_fn",
    [
        lambda root: str(root.parent),
        lambda root: "..",
        lambda root: str(root / ".." / ".."),
        lambda root: os.path.expanduser("~"),
    ],
)
def test_paths_outside_the_roots_are_refused(root, path_fn):
    result = _call(path_fn(root))
    assert result["isError"] is True
    assert "outside the allowed roots" in result["content"][0]["text"]


def test_symlink_out_of_root_is_refused(root, tmp_path):
    outside = tmp_path / "secret-place"
    outside.mkdir()
    link = root / "escape"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")
    result = _call("escape")
    assert result["isError"] is True


def test_roots_env_extends_allowed_paths(root, tmp_path, monkeypatch):
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.setenv(server.ROOTS_ENV, os.pathsep.join([str(root), str(other)]))
    assert server.resolve_scan_path(str(other)) == other.resolve()


def test_scan_does_not_trust_project_config(root, monkeypatch):
    seen = {}

    class FakeEngine:
        def __init__(self, cfg):
            seen["trust"] = cfg.trust_project_config

        def scan(self, project):
            from datetime import datetime, timezone

            from nephilex.core.models import ScanResult

            return ScanResult(target=str(project.root), started_at=datetime.now(timezone.utc))

    monkeypatch.setattr("nephilex.core.engine.ScanEngine", FakeEngine)
    assert _call(".")["isError"] is False
    assert seen["trust"] is False


def test_scan_timeout_is_reported(root, monkeypatch):
    monkeypatch.setenv(server.TIMEOUT_ENV, "1")
    monkeypatch.setattr(server, "_scan_timeout", lambda: 0.05)

    class SlowEngine:
        def __init__(self, cfg):
            pass

        def scan(self, project):
            time.sleep(0.5)

    monkeypatch.setattr("nephilex.core.engine.ScanEngine", SlowEngine)
    result = _call(".")
    assert result["isError"] is True
    assert "did not finish" in result["content"][0]["text"]


def test_run_stdio_forces_utf8_on_real_streams(monkeypatch):
    class Stream(io.StringIO):
        def __init__(self, text=""):
            super().__init__(text)
            self.reconfigured: dict = {}

        def reconfigure(self, **kwargs):
            self.reconfigured = kwargs

    fake_in = Stream('{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}\n')
    fake_out = Stream()
    monkeypatch.setattr(server.sys, "stdin", fake_in)
    monkeypatch.setattr(server.sys, "stdout", fake_out)
    server.run_stdio()
    assert fake_in.reconfigured.get("encoding") == "utf-8"
    assert fake_out.reconfigured == {"encoding": "utf-8", "newline": "\n"}
    assert json.loads(fake_out.getvalue())["id"] == 1
