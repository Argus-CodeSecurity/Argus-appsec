"""Server agent: untrusted targets and failure isolation."""

from __future__ import annotations

import json
from pathlib import Path

from argus.agent import fim, runner
from argus.agent.config import AgentConfig, AgentTarget
from argus.upload import PushError


# --- untrusted target config ---------------------------------------------
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


# --- failure isolation -----------------------------------------------------
def _config(tmp_path: Path, **kw) -> AgentConfig:
    base = dict(state_dir=tmp_path / "state", host_posture=False, host_label="h")
    base.update(kw)
    return AgentConfig(**base)


def test_failing_target_does_not_stop_the_cycle(tmp_path: Path, monkeypatch):
    good = tmp_path / "good"
    good.mkdir()
    (good / "a.py").write_text("x = 1\n", encoding="utf-8")
    cfg = _config(tmp_path, targets=[
        AgentTarget(path=str(tmp_path / "missing-dir"), scanners=["secrets"]),
        AgentTarget(path=str(good), scanners=["secrets"]),
    ])
    seen: list[str] = []
    summary = runner.run_agent_cycle(cfg, on_target=lambda p, r: seen.append(p))
    assert seen == [str(good)]
    assert summary.targets_scanned == 1
    assert len(summary.errors) == 1
    assert summary.exit_code == 2


def test_step_failure_is_pushed_as_finding(tmp_path: Path, monkeypatch):
    pushed: list[dict] = []
    monkeypatch.setattr(runner, "push_result",
                        lambda payload, url, token: pushed.append(payload) or {})
    monkeypatch.setattr(runner, "assess_host",
                        lambda label=None: (_ for _ in ()).throw(RuntimeError("ss exploded")))
    cfg = _config(tmp_path, host_posture=True, push=True,
                  cloud_url="https://cloud.example.com", cloud_token="t")
    summary = runner.run_agent_cycle(cfg)
    assert summary.errors and "ss exploded" in summary.errors[0]
    assert len(pushed) == 1
    assert pushed[0]["findings"][0]["rule"] == "agent.step-failed"


def test_failed_push_keeps_integrity_baseline(tmp_path: Path, monkeypatch):
    watched = tmp_path / "sshd_config"
    watched.write_text("v1\n", encoding="utf-8")
    cfg = _config(tmp_path, integrity_paths=[str(watched)], push=True,
                  cloud_url="https://cloud.example.com", cloud_token="t")
    state_file = cfg.state_dir / "integrity.json"

    monkeypatch.setattr(runner, "push_result", lambda payload, url, token: {})
    runner.run_agent_cycle(cfg)  # baseline
    v1_hash = fim._hash_file(watched)[0]
    watched.write_text("v2 tampered\n", encoding="utf-8")

    def down(payload, url, token):
        raise PushError("cloud unreachable")

    monkeypatch.setattr(runner, "push_result", down)
    summary = runner.run_agent_cycle(cfg)
    assert summary.errors
    baseline = json.loads(state_file.read_text(encoding="utf-8"))
    assert baseline[str(watched)]["hash"] == v1_hash  # not advanced to the tampered file
    # The change must be reported again once the cloud is back.
    pushed: list[dict] = []
    monkeypatch.setattr(runner, "push_result",
                        lambda payload, url, token: pushed.append(payload) or {})
    runner.run_agent_cycle(cfg)
    rules = [f["rule"] for p in pushed for f in p["findings"]]
    assert "fim.content-changed" in rules


def test_loop_continues_after_cycle_error(tmp_path: Path, monkeypatch):
    calls = {"cycle": 0, "sleep": 0}

    def flaky_cycle(config):
        calls["cycle"] += 1
        if calls["cycle"] == 1:
            raise RuntimeError("boom")
        return runner.AgentCycleSummary()

    def fake_sleep(_):
        calls["sleep"] += 1
        if calls["sleep"] >= 2:
            raise KeyboardInterrupt

    monkeypatch.setattr(runner, "run_agent_cycle", flaky_cycle)
    monkeypatch.setattr(runner.time, "sleep", fake_sleep)
    assert runner.run_agent_loop(_config(tmp_path)) == 0
    assert calls["cycle"] == 2
