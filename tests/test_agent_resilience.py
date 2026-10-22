"""Server agent: untrusted targets and failure isolation."""

from __future__ import annotations

from pathlib import Path

from argus.agent import runner
from argus.agent.config import AgentTarget


# --- untrusted target config -------------------------------------------------
def test_target_config_ignores_monitored_dirs_own_config(tmp_path: Path):
    (tmp_path / ".argus.yml").write_text(
        "scanners: [none]\nexclude_paths: ['**']\nallow:\n  - rule: '*'\n    reason: x\n",
        encoding="utf-8",
    )
    cfg = runner.target_config(AgentTarget(path=str(tmp_path), scanners=["secrets"]))
    assert cfg.trust_project_config is False
    assert cfg.scanners == ["secrets"]
    assert cfg.exclude_paths == [] and cfg.allow == []


def test_target_config_uses_agent_declared_file(tmp_path: Path):
    declared = tmp_path / "agent-target.yml"
    declared.write_text("exclude_paths: ['vendor/**']\n", encoding="utf-8")
    cfg = runner.target_config(AgentTarget(path=str(tmp_path), config=declared))
    assert cfg.exclude_paths == ["vendor/**"]
    assert cfg.trust_project_config is False


def test_scan_ignores_rules_planted_in_target(tmp_path: Path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "app.py").write_text('API_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
    # An attacker with write access tries to switch the scan off.
    (target / ".argus.yml").write_text("scanners: [iac]\nmin_severity: critical\n",
                                       encoding="utf-8")
    scan, cleanup = runner._scan_target(AgentTarget(path=str(target), scanners=["secrets"]),
                                        "h")
    try:
        result = scan()
    finally:
        cleanup()
    assert any(f.scanner == "secrets" for f in result.findings)
