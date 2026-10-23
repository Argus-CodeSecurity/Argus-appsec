"""How the secrets scanner reports the git-history pass."""

from __future__ import annotations

from types import SimpleNamespace

from nephilex.core.config import Config
from nephilex.core.plugin import ScannerContext
from nephilex.core.project import Project
from nephilex.scanners import secrets_history
from nephilex.scanners.secrets import SecretsScanner


def _run(tmp_path, monkeypatch, result) -> list:
    monkeypatch.setattr(secrets_history, "find_history_secrets", lambda root: result)
    cfg = Config(scanner_options={"secrets": {"history": True}})
    ctx = ScannerContext(project=Project.from_path(tmp_path), config=cfg)
    return list(SecretsScanner().scan(ctx))


def _hs(fingerprint: str) -> SimpleNamespace:
    return SimpleNamespace(
        rule="aws-access-key-id",
        redacted="AKI... [redacted, 20 chars]",
        path="old.py",
        commit="abc123",
        fingerprint=fingerprint,
    )


def test_history_ids_use_the_fingerprint(tmp_path, monkeypatch):
    findings = _run(tmp_path, monkeypatch, ([_hs("1111aaaa"), _hs("2222bbbb")], False))
    ids = [f.id for f in findings if f.rule_id == "secrets.history.aws-access-key-id"]
    assert ids == [
        "secrets:history:aws-access-key-id:1111aaaa",
        "secrets:history:aws-access-key-id:2222bbbb",
    ]


def test_truncated_history_is_reported_without_findings(tmp_path, monkeypatch):
    findings = _run(tmp_path, monkeypatch, ([], True))
    notes = [f for f in findings if f.rule_id == "secrets.history-scan-incomplete"]
    assert len(notes) == 1
    assert notes[0].severity.label.lower() == "info"


def test_complete_history_has_no_incomplete_note(tmp_path, monkeypatch):
    findings = _run(tmp_path, monkeypatch, ([_hs("1111aaaa")], False))
    assert not any(f.rule_id == "secrets.history-scan-incomplete" for f in findings)
