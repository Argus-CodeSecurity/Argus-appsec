"""Model enrichment is capped to the highest-risk findings."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from argus.ai.base import AIProvider
from argus.ai.heuristic import HeuristicProvider
from argus.core.config import Config, ConfigError
from argus.core.engine import ScanEngine
from argus.core.models import Finding, Location, ScanResult, Severity
from argus.core.project import Project


class _CountingModel(AIProvider):
    name = "counting-test-model"
    is_remote = True

    def __init__(self) -> None:
        super().__init__()
        self.prompts: list[str] = []

    def complete(self, system: str, user: str) -> str:
        self.prompts.append(user)
        return "WHY: model why\nATTACK: model attack\nIMPACT: model impact"


def _result(n: int) -> ScanResult:
    r = ScanResult(target=".", started_at=datetime.now(timezone.utc))
    for i in range(n):
        sev = Severity.CRITICAL if i % 10 == 0 else Severity.LOW
        r.add(Finding(id=f"t:r:{i}", rule_id=f"t.r{i}", scanner="t", title=f"finding-{i}",
                      description="d", severity=sev, cwe=["CWE-89"],
                      location=Location(path="a.py", start_line=i + 1)))
    return r


def _run(tmp_path: Path, ai: AIProvider, cfg: Config, n: int = 40) -> ScanResult:
    result = _result(n)
    ScanEngine(cfg)._run_agents(result, Project.from_path(tmp_path), ai)
    return result


def test_model_calls_capped_to_highest_risk(tmp_path: Path) -> None:
    cfg = Config()
    cfg.ai.max_findings = 4
    model = _CountingModel()
    result = _run(tmp_path, model, cfg)
    assert len(model.prompts) == 4
    # The four CRITICAL findings (indices 0, 10, 20, 30) are the ones sent.
    sent = {f.title for f in result.findings if f.why_vulnerable == "model why"}
    assert sent == {"finding-0", "finding-10", "finding-20", "finding-30"}
    # Everything else still gets offline reasoning.
    assert all(f.why_vulnerable for f in result.findings)


def test_zero_means_no_model_calls(tmp_path: Path) -> None:
    cfg = Config()
    cfg.ai.max_findings = 0
    model = _CountingModel()
    result = _run(tmp_path, model, cfg, n=5)
    assert model.prompts == []
    assert all(f.why_vulnerable for f in result.findings)


def test_heuristic_provider_is_not_capped(tmp_path: Path) -> None:
    cfg = Config()
    cfg.ai.max_findings = 1
    result = _run(tmp_path, HeuristicProvider(), cfg, n=10)
    assert all(f.why_vulnerable for f in result.findings)


def test_max_findings_config_validation() -> None:
    assert Config.from_dict({"ai": {"max_findings": 10}}).ai.max_findings == 10
    assert Config().ai.max_findings == 25
    for bad in (-1, "10", True):
        with pytest.raises(ConfigError):
            Config.from_dict({"ai": {"max_findings": bad}})
