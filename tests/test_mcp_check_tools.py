"""The file-level MCP tools, exercised as JSON-RPC messages over stdio.

Every test drives :func:`argus.mcp.server.run_stdio` with newline-delimited
JSON-RPC requests, the way an MCP client does, and reads the responses back
from its stdout. One test starts the real ``argus mcp`` process.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from argus.mcp import packages, server, tools

VULN = "import yaml\n\n\ndef load(raw):\n    return yaml.load(raw)\n"
SECRET = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text(VULN, encoding="utf-8")
    (workspace / "keys.py").write_text(SECRET, encoding="utf-8")
    (workspace / "clean.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.chdir(workspace)
    monkeypatch.delenv(server.ROOTS_ENV, raising=False)
    monkeypatch.setenv(packages.OFFLINE_ENV, "1")
    tools.forget_all()
    return workspace


def rpc(*requests: dict) -> list[dict]:
    """Send requests through the stdio server; return the parsed responses."""
    stdin = io.StringIO("".join(json.dumps(r) + "\n" for r in requests))
    stdout = io.StringIO()
    server.run_stdio(stdin, stdout)
    return [json.loads(line) for line in stdout.getvalue().splitlines()]


def call(name: str, arguments: dict, req_id: int = 1) -> dict:
    (resp,) = rpc(
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert resp["id"] == req_id
    return resp["result"]


def payload(result: dict) -> dict:
    assert result["isError"] is False, result["content"][0]["text"]
    text = json.loads(result["content"][0]["text"])
    assert text == result["structuredContent"]
    return result["structuredContent"]


# --- tools/list ----------------------------------------------------------------
def test_tools_list_has_every_tool_with_read_only_annotations(root: Path) -> None:
    (resp,) = rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    listed = {t["name"]: t for t in resp["result"]["tools"]}
    assert set(listed) == {
        "argus_scan",
        "argus_check_files",
        "argus_check_snippet",
        "argus_check_package",
        "argus_fix",
    }
    for tool in listed.values():
        ann = tool["annotations"]
        assert ann["readOnlyHint"] is True
        assert ann["destructiveHint"] is False
        assert isinstance(ann["openWorldHint"], bool)
        assert tool["inputSchema"]["type"] == "object"
        assert tool["description"].isascii()
    assert listed["argus_check_package"]["annotations"]["openWorldHint"] is True
    assert listed["argus_check_files"]["annotations"]["openWorldHint"] is False


# --- argus_check_files ---------------------------------------------------------
def test_check_files_returns_structured_findings(root: Path) -> None:
    data = payload(call("argus_check_files", {"paths": ["app.py", str(root / "keys.py")]}))
    assert data["checked"] == ["app.py", "keys.py"]
    rules = {f["rule_id"]: f for f in data["findings"]}
    assert {"patterns.python-yaml-load", "secrets.aws-access-key-id"} <= set(rules)
    yaml_finding = rules["patterns.python-yaml-load"]
    assert yaml_finding["path"] == "app.py"
    assert yaml_finding["line"] == 5
    assert yaml_finding["severity"] == "high"
    assert yaml_finding["fix_available"] is True
    # Column 12 is where `yaml.load(` starts on `    return yaml.load(raw)`.
    assert yaml_finding["hook"].startswith("app.py:5:12: error high patterns.python-yaml-load:")
    assert data["summary"]["by_severity"]["critical"] >= 1
    assert data["summary"]["highest"] == "critical"


def test_check_files_clean(root: Path) -> None:
    data = payload(call("argus_check_files", {"paths": ["clean.py"]}))
    assert data["findings"] == []
    assert data["summary"]["total_findings"] == 0


@pytest.mark.parametrize(
    "paths",
    [
        [".."],
        ["../outside.py"],
        [os.path.expanduser("~")],
        ["missing.py"],
        [],
        "app.py",
        [1],
    ],
)
def test_check_files_refuses_bad_paths(root: Path, paths) -> None:
    (root.parent / "outside.py").write_text(VULN, encoding="utf-8")
    result = call("argus_check_files", {"paths": paths})
    assert result["isError"] is True


def test_check_files_directory_is_skipped(root: Path) -> None:
    (root / "pkg").mkdir()
    data = payload(call("argus_check_files", {"paths": ["pkg"]}))
    assert data["checked"] == []
    assert data["skipped"][0]["reason"].startswith("is a directory")


def test_check_files_relative_paths_use_the_first_root(root: Path, tmp_path, monkeypatch):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.setenv(server.ROOTS_ENV, str(root))
    data = payload(call("argus_check_files", {"paths": ["app.py"]}))
    assert data["checked"] == ["app.py"]


def test_check_files_does_not_trust_inline_suppressions(root: Path) -> None:
    (root / "app.py").write_text(
        VULN.replace(
            "yaml.load(raw)", 'yaml.load(raw)  # argus-ignore: python-yaml-load reason="ok"'
        ),
        encoding="utf-8",
    )
    data = payload(call("argus_check_files", {"paths": ["app.py"]}))
    assert any(f["rule_id"] == "patterns.python-yaml-load" for f in data["findings"])


def test_check_files_timeout(root: Path, monkeypatch) -> None:
    import time

    monkeypatch.setattr(server, "_scan_timeout", lambda: 0.05)
    monkeypatch.setattr(tools, "check_files", lambda args: time.sleep(0.5) or {})
    result = call("argus_check_files", {"paths": ["app.py"]})
    assert result["isError"] is True
    assert "did not finish" in result["content"][0]["text"]


# --- argus_check_snippet -------------------------------------------------------
def test_check_snippet_scans_in_a_temp_dir_not_the_project(root: Path) -> None:
    before = sorted(p.name for p in root.iterdir())
    data = payload(
        call("argus_check_snippet", {"code": "import yaml\nyaml.load(s)\n", "language": "python"})
    )
    assert data["filename"] == "snippet.py"
    assert [f["rule_id"] for f in data["findings"]] == ["patterns.python-yaml-load"]
    assert data["findings"][0]["line"] == 2
    assert sorted(p.name for p in root.iterdir()) == before


def test_check_snippet_filename_hint_keeps_directories(root: Path) -> None:
    data = payload(
        call(
            "argus_check_snippet",
            {"code": SECRET, "filename": "config/settings.py"},
        )
    )
    assert data["filename"] == "config/settings.py"
    assert data["findings"][0]["path"] == "config/settings.py"


@pytest.mark.parametrize(
    "arguments",
    [
        {"code": "x = 1\n"},
        {"code": "x = 1\n", "language": "klingon"},
        {"code": "x = 1\n", "filename": "../../escape.py"},
        {"code": 42, "language": "python"},
    ],
)
def test_check_snippet_bad_arguments(root: Path, arguments: dict) -> None:
    assert call("argus_check_snippet", arguments)["isError"] is True


def test_snippet_relpath_never_escapes() -> None:
    assert tools.snippet_relpath("/etc/passwd", None) == "passwd"
    assert tools.snippet_relpath("C:\\Users\\x\\app.py", None) == "app.py"
    assert tools.snippet_relpath("a b/c$d.py", None) == "a_b/c_d.py"
    assert tools.snippet_relpath(None, "Dockerfile") == "Dockerfile"
    with pytest.raises(ValueError):
        tools.snippet_relpath("a/../../b.py", None)


# --- argus_fix -----------------------------------------------------------------
def _find(data: dict, rule: str) -> dict:
    return next(f for f in data["findings"] if f["rule_id"] == rule)


def test_fix_returns_a_verified_diff_and_never_applies_it(root: Path) -> None:
    data = payload(call("argus_check_files", {"paths": ["app.py"]}))
    fid = _find(data, "patterns.python-yaml-load")["id"]
    fix = payload(call("argus_fix", {"finding_id": fid}))
    assert fix["available"] is True
    assert fix["verified"] is True
    assert fix["applied"] is False
    assert "-    return yaml.load(raw)" in fix["diff"]
    assert "+    return yaml.safe_load(raw)" in fix["diff"]
    assert fix["diff"].startswith("--- a/app.py\n+++ b/app.py\n@@ ")
    assert (root / "app.py").read_text(encoding="utf-8") == VULN


def test_fix_for_a_snippet_finding(root: Path) -> None:
    data = payload(
        call("argus_check_snippet", {"code": "import yaml\nyaml.load(s)\n", "filename": "x.py"})
    )
    fix = payload(call("argus_fix", {"finding_id": data["findings"][0]["id"]}))
    assert fix["available"] is True
    assert "+yaml.safe_load(s)" in fix["diff"]


def test_snippet_and_file_findings_do_not_collide(root: Path) -> None:
    files = payload(call("argus_check_files", {"paths": ["app.py"]}))
    payload(call("argus_check_snippet", {"code": "import yaml\nyaml.load(s)\n", "language": "py"}))
    fid = _find(files, "patterns.python-yaml-load")["id"]
    fix = payload(call("argus_fix", {"finding_id": fid}))
    assert fix["path"] == "app.py"
    assert "+    return yaml.safe_load(raw)" in fix["diff"]


def test_fix_without_a_deterministic_rewrite(root: Path) -> None:
    data = payload(call("argus_check_files", {"paths": ["keys.py"]}))
    finding = _find(data, "secrets.aws-access-key-id")
    assert finding["fix_available"] is False
    fix = payload(call("argus_fix", {"finding_id": finding["id"]}))
    assert fix["available"] is False
    assert fix["guidance"]


def test_fix_refuses_a_stale_line(root: Path) -> None:
    data = payload(call("argus_check_files", {"paths": ["app.py"]}))
    fid = _find(data, "patterns.python-yaml-load")["id"]
    (root / "app.py").write_text(VULN.replace("yaml.load", "yaml.safe_load"), encoding="utf-8")
    fix = payload(call("argus_fix", {"finding_id": fid}))
    assert fix["available"] is False
    assert "changed" in fix["reason"]


def test_fix_unknown_id(root: Path) -> None:
    result = call("argus_fix", {"finding_id": "nope"})
    assert result["isError"] is True
    assert "unknown finding id" in result["content"][0]["text"]


# --- argus_check_package -------------------------------------------------------
def test_package_known_malicious(root: Path) -> None:
    data = payload(call("argus_check_package", {"ecosystem": "npm", "name": "flatmap-stream"}))
    assert data["verdict"] == "malicious"
    assert data["malicious"]["known_malicious"] is True


def test_package_typosquat_offline(root: Path) -> None:
    data = payload(call("argus_check_package", {"ecosystem": "npm", "name": "lodahs"}))
    assert data["verdict"] == "suspicious"
    assert "lodash" in data["typosquat"]["resembles"]
    assert data["registry"]["status"] == "unknown"
    assert data["network"] is False


def test_package_ecosystem_aliases_and_validation(root: Path) -> None:
    data = payload(call("argus_check_package", {"ecosystem": "pip", "name": "requests"}))
    assert data["ecosystem"] == "PyPI"
    for bad in (
        {"ecosystem": "npm"},
        {"ecosystem": "apt", "name": "x"},
        {"ecosystem": "npm", "name": "../../etc"},
        {"ecosystem": "npm", "name": "x", "version": "1 2"},
    ):
        assert call("argus_check_package", bad)["isError"] is True


def _mock_registry(monkeypatch, status_for: dict[str, int]) -> list[str]:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        for needle, status in status_for.items():
            if needle in str(request.url):
                return httpx.Response(status, json={})
        return httpx.Response(500)

    monkeypatch.setattr(
        packages, "_registry_client", lambda: httpx.Client(transport=httpx.MockTransport(handler))
    )
    monkeypatch.setattr("argus.supply_chain.intel._fetch_remote", lambda *a, **k: None)
    return seen


def test_package_not_on_registry_is_possibly_hallucinated(root: Path, monkeypatch) -> None:
    monkeypatch.delenv(packages.OFFLINE_ENV)
    seen = _mock_registry(monkeypatch, {"/pypi/": 404})
    data = payload(
        call("argus_check_package", {"ecosystem": "PyPI", "name": "fastjson-validator-pro"})
    )
    assert data["verdict"] == "possibly_hallucinated"
    assert data["registry"]["status"] == "not_found"
    assert seen == ["https://pypi.org/pypi/fastjson-validator-pro/json"]


def test_package_registry_failure_is_unknown(root: Path, monkeypatch) -> None:
    monkeypatch.delenv(packages.OFFLINE_ENV)
    _mock_registry(monkeypatch, {})
    data = payload(call("argus_check_package", {"ecosystem": "npm", "name": "left-pad-x"}))
    assert data["registry"]["status"] == "unknown"
    assert data["verdict"] == "unknown"


def test_package_scoped_npm_url_and_vulnerabilities(root: Path, monkeypatch) -> None:
    from argus.core.models import Severity
    from argus.scanners import osv

    monkeypatch.delenv(packages.OFFLINE_ENV)
    seen = _mock_registry(monkeypatch, {"registry.npmjs.org": 200})
    advisory = osv.OSVAdvisory(
        id="GHSA-xxxx", summary="Prototype pollution", severity=Severity.HIGH, fixed="1.2.4"
    )
    monkeypatch.setattr(osv, "query", lambda eco, deps, **k: {("@scope/pkg", "1.2.3"): [advisory]})
    data = payload(
        call("argus_check_package", {"ecosystem": "npm", "name": "@scope/pkg", "version": "1.2.3"})
    )
    assert seen == ["https://registry.npmjs.org/@scope%2Fpkg"]
    assert data["registry"]["status"] == "exists"
    assert data["verdict"] == "vulnerable"
    assert data["vulnerabilities"]["advisories"][0]["fixed_in"] == "1.2.4"


def test_package_other_ecosystem_has_no_registry_lookup(root: Path, monkeypatch) -> None:
    monkeypatch.delenv(packages.OFFLINE_ENV)
    _mock_registry(monkeypatch, {})
    data = payload(call("argus_check_package", {"ecosystem": "Go", "name": "github.com/a/b"}))
    assert data["registry"]["status"] == "unknown"
    assert "no registry lookup" in data["registry"]["reason"]


# --- the real process --------------------------------------------------------------
def test_real_argus_mcp_process(root: Path) -> None:
    src = str(Path(__file__).resolve().parents[1] / "src")
    env = dict(os.environ)
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    env[packages.OFFLINE_ENV] = "1"
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "argus_check_files", "arguments": {"paths": ["app.py"]}},
        },
    ]
    proc = subprocess.run(
        [sys.executable, "-m", "argus", "mcp"],
        input="".join(json.dumps(r) + "\n" for r in requests),
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=root,
        env=env,
        timeout=120,
    )
    responses = [json.loads(line) for line in proc.stdout.splitlines()]
    assert [r["id"] for r in responses] == [1, 2], proc.stderr
    assert responses[0]["result"]["protocolVersion"] == "2025-06-18"
    found = responses[1]["result"]["structuredContent"]["findings"]
    assert any(f["rule_id"] == "patterns.python-yaml-load" for f in found)
