"""Tests completing Phase 1/2 exit criteria."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from argus.analysis.auth_map import build_auth_map
from argus.analysis.symbol_reachability import (
    collect_python_symbols,
    extract_osv_symbols,
    symbol_verdict,
)
from argus.core.config import Config
from argus.core.plugin import ScannerContext
from argus.core.project import Project
from argus.sbom.diff import diff_components
from argus.scanners.api import ApiScanner
from argus.scanners.provenance import ProvenanceScanner
from argus.supply_chain.intel import _parse_feed_payload, load_malicious_packages


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _repo_two_versions(tmp_path: Path) -> Path:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "t@t.com")
    _git(tmp_path, "config", "user.name", "T")
    (tmp_path / "requirements.txt").write_text("flask==2.0.0\n", encoding="utf-8")
    _git(tmp_path, "add", "requirements.txt")
    _git(tmp_path, "commit", "-m", "a")
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    _git(tmp_path, "add", "requirements.txt")
    _git(tmp_path, "commit", "-m", "b")
    return tmp_path


def test_sbom_diff_components(tmp_path: Path):
    repo = _repo_two_versions(tmp_path)
    changes = diff_components(repo, "HEAD~1...HEAD")
    assert any(c.name == "flask" and c.change == "changed" for c in changes)


def test_auth_map_endpoint_table(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/admin/users')\nasync def x(): pass\n",
        encoding="utf-8",
    )
    entries = build_auth_map(Project.from_path(tmp_path))
    assert entries and entries[0].authentication == "missing"


def test_openapi_missing_security(tmp_path: Path):
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/admin/users": {
                "get": {"summary": "list"},
            },
        },
    }
    (tmp_path / "openapi.json").write_text(json.dumps(spec), encoding="utf-8")
    ctx = ScannerContext(project=Project.from_path(tmp_path), config=Config())
    rules = {f.rule_id for f in ApiScanner().scan(ctx)}
    assert "api.missing-security" in rules


def test_provenance_unsigned(tmp_path: Path):
    att = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "artifact.tgz"}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {"buildType": "https://example.com/build"},
    }
    (tmp_path / "provenance.json").write_text(json.dumps(att), encoding="utf-8")
    ctx = ScannerContext(project=Project.from_path(tmp_path), config=Config())
    rules = {f.rule_id for f in ProvenanceScanner().scan(ctx)}
    assert "provenance.missing-builder-id" in rules


def test_symbol_reachability_verdict(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "import yaml\nyaml.load(data)\n",
        encoding="utf-8",
    )
    syms = collect_python_symbols(Project.from_path(tmp_path))
    vuln = {"summary": "unsafe yaml.load", "affected": []}
    affected = extract_osv_symbols(vuln, "pyyaml")
    v = symbol_verdict("pyyaml", syms, affected, imported=True)
    assert v in ("symbol_reachable", "import_only", "unknown")


def test_intel_parses_osv_style_feed():
    data = [{"affected": [{"package": {"ecosystem": "npm", "name": "evil-pkg"}}]}]
    assert ("npm", "evil-pkg") in _parse_feed_payload(data)


def test_intel_bundled_offline():
    load_malicious_packages.cache_clear()
    assert load_malicious_packages(online=False)
