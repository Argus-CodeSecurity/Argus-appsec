"""Contextual risk boost for reachable deps and the SSRF + cloud secret chain."""

from __future__ import annotations

from datetime import datetime, timezone

from argus.analysis.attack_chains import find_chains
from argus.analysis.risk_engine import enrich_contextual_risk
from argus.core.models import Confidence, Finding, Location, ScanResult, Severity
from argus.scanners.secrets import SecretsScanner


def _dep(reachability: str) -> Finding:
    return Finding(id="d", rule_id="dep.cve", scanner="dependencies", title="cve",
                   description="", severity=Severity.MEDIUM,
                   location=Location(path="requirements.txt"),
                   metadata={"reachability": reachability})


def test_imported_dependency_gets_reachability_boost():
    imported, unused = _dep("imported"), _dep("not_imported")
    result = ScanResult(target="t", started_at=datetime.now(timezone.utc),
                        findings=[imported, unused])
    enrich_contextual_risk(result)
    boost = imported.metadata["risk_factors"]["boost"]
    assert boost - unused.metadata["risk_factors"]["boost"] == 15


def _aws_key_finding() -> Finding:
    # Build it the way the secrets scanner does, including redaction.
    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    finding = SecretsScanner()._make_finding(
        rule_id="aws-access-key-id", index=1, path="cfg.py", lineno=1,
        line=f"key = '{key}'", matched=key, severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        title="Hardcoded credential: aws access key id",
    )
    assert "AKIA" not in (finding.location.snippet or "")
    return finding


def _ssrf() -> Finding:
    return Finding(id="s", rule_id="py.ssrf", scanner="patterns", title="ssrf",
                   description="", severity=Severity.HIGH, cwe=["CWE-918"],
                   location=Location(path="app.py", start_line=4))


def test_ssrf_and_redacted_aws_key_form_a_chain():
    chains = find_chains([_ssrf(), _aws_key_finding()])
    assert any(c.id == "ssrf-to-cloud-credentials" for c in chains)


def test_history_aws_secret_counts_as_cloud_secret():
    hist = Finding(id="h", rule_id="secrets.history.aws-secret-access-key",
                   scanner="secrets", title="Secret in git history", description="",
                   severity=Severity.HIGH,
                   location=Location(path="(git history)", snippet="abc... [redacted]"))
    assert any(c.id == "ssrf-to-cloud-credentials" for c in find_chains([_ssrf(), hist]))


def test_unrelated_secret_does_not_form_cloud_chain():
    gh = Finding(id="g", rule_id="secrets.github-token", scanner="secrets",
                 title="Hardcoded credential: github token", description="",
                 severity=Severity.HIGH,
                 location=Location(path="x.py", start_line=1, snippet="t = 'ghp... [redacted]'"))
    assert not any(c.id == "ssrf-to-cloud-credentials" for c in find_chains([_ssrf(), gh]))
