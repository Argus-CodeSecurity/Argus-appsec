"""Tests for opt-in live secret verification (network fully mocked)."""

from __future__ import annotations

import pytest

from argus.core.config import Config
from argus.core.models import Severity
from argus.core.plugin import ScannerContext, registry
from argus.core.project import Project
from argus.scanners import secret_verify


class _Resp:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


@pytest.fixture
def mock_httpx(monkeypatch):
    """Route secret_verify's httpx.get through a controllable stub."""
    calls = []

    def make(status_code, payload=None):
        def _get(url, headers=None, timeout=None):
            calls.append(url)
            return _Resp(status_code, payload)

        import httpx

        monkeypatch.setattr(httpx, "get", _get)

    make.calls = calls
    return make


def test_github_live_and_invalid(mock_httpx):
    mock_httpx(200)
    assert secret_verify.verify("github-token", "ghp_x") == secret_verify.LIVE
    mock_httpx(401)
    assert secret_verify.verify("github-token", "ghp_x") == secret_verify.INVALID


def test_slack_inspects_body(mock_httpx):
    mock_httpx(200, {"ok": True})
    assert secret_verify.verify("slack-token", "xoxb-1") == secret_verify.LIVE
    mock_httpx(200, {"ok": False})
    assert secret_verify.verify("slack-token", "xoxb-1") == secret_verify.INVALID


def test_openai_by_shape(mock_httpx):
    mock_httpx(200)
    # No explicit verifier for this rule id, but sk- shape routes to OpenAI.
    assert secret_verify.verify("high-entropy-string", "sk-abc123") == secret_verify.LIVE


def test_unsupported_type_is_unknown():
    # AWS has no safe read-only verifier; must never be reported as live/invalid.
    assert secret_verify.verify("aws-access-key-id", "AKIA...") == secret_verify.UNKNOWN


def test_network_error_is_unknown(monkeypatch):
    import httpx

    def _boom(*a, **k):
        raise httpx.ConnectError("no network")

    monkeypatch.setattr(httpx, "get", _boom)
    assert secret_verify.verify("github-token", "ghp_x") == secret_verify.UNKNOWN


def test_scanner_escalates_verified_live(tmp_path, mock_httpx, monkeypatch):
    mock_httpx(200)  # everything verifies live
    (tmp_path / "cfg.py").write_text('GITHUB_TOKEN = "ghp_' + "a" * 36 + '"\n', encoding="utf-8")
    project = Project.from_path(tmp_path)
    cfg = Config(scanner_options={"secrets": {"verify": True, "entropy": False}})
    ctx = ScannerContext(project=project, config=cfg, ai=None)
    findings = list(registry.get_scanner("secrets")().scan(ctx))

    gh = [f for f in findings if f.rule_id == "secrets.github-token"]
    assert gh, "expected the github token to be detected"
    assert gh[0].metadata["verification"] == "live"
    assert gh[0].severity == Severity.CRITICAL
    assert "VERIFIED LIVE" in gh[0].title
    # The raw secret must never be stored on the finding.
    assert "ghp_" + "a" * 36 not in str(gh[0].model_dump())


def test_secrets_scanner_not_cached_when_verifying(tmp_path):
    project = Project.from_path(tmp_path)
    scanner = registry.get_scanner("secrets")()
    verifying = ScannerContext(
        project=project, config=Config(scanner_options={"secrets": {"verify": True}}), ai=None
    )
    plain = ScannerContext(project=project, config=Config(), ai=None)
    assert scanner.cacheable(verifying) is False
    assert scanner.cacheable(plain) is True
