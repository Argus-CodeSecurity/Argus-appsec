"""A scanned repository's own config is untrusted unless the target is local."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

import argus.targets
from argus.cli.main import app
from argus.core.config import Config, load_project_config
from argus.core.project import Project
from argus.targets import ResolvedTarget

runner = CliRunner()

# A hostile repo's config that would hide everything if honored.
_HOSTILE_CONFIG = 'exclude_paths: ["**"]\nexclude_scanners: ["secrets"]\n'
_SECRET = 'AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"\n'


def _repo(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / ".argus.yml").write_text(_HOSTILE_CONFIG, encoding="utf-8")
    (tmp_path / "settings.py").write_text(_SECRET, encoding="utf-8")
    return tmp_path


def test_config_default_is_untrusted() -> None:
    assert Config().trust_project_config is False


def test_local_project_config_is_trusted(tmp_path: Path) -> None:
    cfg = load_project_config(Project.from_path(_repo(tmp_path)))
    assert cfg.trust_project_config is True
    assert cfg.exclude_paths == ["**"]


def test_remote_project_config_is_ignored(tmp_path: Path) -> None:
    project = Project.from_path(_repo(tmp_path), origin="github")
    cfg = load_project_config(project)
    assert cfg.trust_project_config is False
    assert cfg.exclude_paths == []
    assert cfg.exclude_scanners == []


def test_remote_project_config_honored_with_explicit_trust(tmp_path: Path) -> None:
    project = Project.from_path(_repo(tmp_path), origin="github")
    cfg = load_project_config(project, trust_remote=True)
    assert cfg.trust_project_config is True
    assert cfg.exclude_paths == ["**"]


def test_explicit_config_always_honored(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    mine = tmp_path / "mine.yml"
    mine.write_text("fail_on: high\n", encoding="utf-8")
    cfg = load_project_config(Project.from_path(repo, origin="github"), mine)
    assert cfg.fail_on is not None and cfg.fail_on.label == "High"
    assert cfg.trust_project_config is False


@pytest.fixture
def remote_repo(tmp_path: Path, monkeypatch) -> Path:
    """Make every CLI command resolve its target as if it were a fresh clone."""
    repo = _repo(tmp_path / "clone")

    def fake_resolve(target: str, *, branch: str | None = None) -> ResolvedTarget:
        return ResolvedTarget(project=Project.from_path(repo, origin="github"))

    monkeypatch.setattr(argus.targets, "resolve", fake_resolve)
    return repo


def test_focused_command_ignores_remote_config(remote_repo: Path) -> None:
    res = runner.invoke(app, ["secrets", "https://github.com/evil/repo", "--fail-on", "low",
                              "--quiet"])
    assert res.exit_code == 1, res.output


def test_scan_ignores_remote_config(remote_repo: Path) -> None:
    res = runner.invoke(app, ["scan", "https://github.com/evil/repo", "--fail-on", "low",
                              "--quiet", "--no-ai", "-f", "json"])
    assert res.exit_code == 1, res.output


def test_baseline_create_ignores_remote_config(remote_repo: Path, tmp_path: Path) -> None:
    out = tmp_path / "baseline.json"
    res = runner.invoke(app, ["baseline", "create", "https://github.com/evil/repo",
                              "-o", str(out), "--quiet"])
    assert res.exit_code == 0, res.output
    assert '"secrets' in out.read_text(encoding="utf-8")


# --- in-tree suppressions (inline comments, .argus/exceptions.yml) ----------
_SHELL = 'import subprocess\nsubprocess.run("x", shell=True)  # argus-ignore reason="ok"\n'


def _suppression_repo(tmp_path: Path) -> Path:
    from argus.core.models import Finding

    (tmp_path / "app.py").write_text(_SHELL, encoding="utf-8")
    (tmp_path / "keys.py").write_text(_SECRET, encoding="utf-8")
    # Suppress every secrets finding by fingerprint via the exceptions file.
    project = Project.from_path(tmp_path)
    from argus.core.engine import ScanEngine

    cfg = Config(scanners=["secrets"], cache=False)
    cfg.ai.enabled = False
    found: list[Finding] = ScanEngine(cfg).scan(project).findings
    assert found
    entries = "".join(
        f"  - fingerprint: '{f.fingerprint()}'\n    status: suppress\n"
        f"    reason: accepted\n    owner: me\n" for f in found)
    (tmp_path / ".argus").mkdir()
    (tmp_path / ".argus" / "exceptions.yml").write_text(
        "exceptions:\n" + entries, encoding="utf-8")
    return tmp_path


def _scan(project: Project, *, trusted: bool):
    from argus.core.engine import ScanEngine

    cfg = Config(scanners=["patterns", "secrets"], cache=False,
                 trust_project_config=trusted)
    cfg.ai.enabled = False
    return ScanEngine(cfg).scan(project)


def test_untrusted_target_ignores_in_tree_suppressions(tmp_path: Path) -> None:
    repo = _suppression_repo(tmp_path)
    result = _scan(Project.from_path(repo, origin="github"), trusted=False)
    rules = {f.rule_id for f in result.findings}
    assert any("shell-true" in r for r in rules)
    assert any(f.scanner == "secrets" for f in result.findings)
    assert "exceptions_applied" not in result.project_summary


def test_trusted_target_applies_in_tree_suppressions(tmp_path: Path) -> None:
    repo = _suppression_repo(tmp_path)
    result = _scan(Project.from_path(repo), trusted=True)
    assert not any("shell-true" in f.rule_id for f in result.findings)
    assert not any(f.scanner == "secrets" for f in result.findings)
    assert result.project_summary.get("exceptions_applied")
