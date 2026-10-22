"""MCP server and agent configuration files (the ``agent-config`` scanner)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus.core.config import Config
from argus.core.engine import ScanEngine
from argus.core.plugin import ScannerContext, registry
from argus.core.project import Project
from argus.scanners import agent_config

TOKEN = "ghp_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"


def _scan(tmp_path: Path, rel: str, content: str | dict) -> list:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    text = content if isinstance(content, str) else json.dumps(content, indent=2)
    path.write_text(text, encoding="utf-8")
    ctx = ScannerContext(project=Project.from_path(tmp_path), config=Config(), ai=None)
    return list(registry.get_scanner("agent-config")().scan(ctx))


def _servers(**servers) -> dict:
    return {"mcpServers": servers}


def _rules(findings) -> list[str]:
    return [f.rule_id.split(".", 1)[1] for f in findings]


def test_registered_and_tagged(tmp_path):
    assert "agent-config" in registry.scanners()
    findings = _scan(
        tmp_path, ".mcp.json", _servers(f={"command": "uvx", "args": ["mcp-server-fetch"]})
    )
    assert findings and "mcp" in findings[0].tags and "agent" in findings[0].tags
    assert findings[0].scanner == "agent-config"


@pytest.mark.parametrize(
    "rel",
    [
        ".mcp.json",
        ".cursor/mcp.json",
        ".roo/mcp.json",
        "claude_desktop_config.json",
        "mcp_config.json",
        "cline_mcp_settings.json",
        ".gemini/settings.json",
        "sub/project/.mcp.json",
    ],
)
def test_every_config_location_is_read(tmp_path, rel):
    findings = _scan(tmp_path, rel, _servers(f={"command": "uvx", "args": ["mcp-server-fetch"]}))
    assert _rules(findings) == ["mcp-unpinned-package"]


def test_unrelated_json_is_ignored(tmp_path):
    assert (
        _scan(tmp_path, "config/mcp-servers.json", _servers(f={"command": "uvx", "args": ["x"]}))
        == []
    )


# --- hardcoded secrets ---------------------------------------------------------


def test_signature_secret_in_env_is_reported_and_redacted(tmp_path):
    findings = _scan(
        tmp_path,
        ".mcp.json",
        _servers(github={"command": "node", "args": ["s.js"], "env": {"GITHUB_TOKEN": TOKEN}}),
    )
    (f,) = findings
    assert f.rule_id == "agent-config.mcp-hardcoded-secret"
    assert f.severity.name == "CRITICAL"
    assert f.owasp == ["LLM02:2025-Sensitive Information Disclosure"]
    assert TOKEN not in f.location.snippet and TOKEN not in f.description
    assert TOKEN not in f.id
    assert f.location.start_line and "GITHUB_TOKEN" in f.location.snippet


@pytest.mark.parametrize(
    ("block", "value"),
    [
        ("env", {"BRAVE_API_KEY": "BSAq8Zx3LmN7pQ2rT5vW9yK1"}),
        ("headers", {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9xQ7mZ2pL9vK4"}),
    ],
)
def test_entropy_secret_in_env_or_headers(tmp_path, block, value):
    server = {"type": "http", "url": "https://x.example.com/mcp", block: value}
    findings = _scan(tmp_path, ".cursor/mcp.json", _servers(s=server))
    assert _rules(findings) == ["mcp-hardcoded-secret"]
    assert list(value.values())[0] not in findings[0].location.snippet


def test_secret_passed_as_argument(tmp_path):
    server = {"command": "node", "args": ["server.js", "--api-key", "sk-proj-" + "Q" * 30]}
    assert _rules(_scan(tmp_path, ".mcp.json", _servers(s=server))) == ["mcp-hardcoded-secret"]


@pytest.mark.parametrize(
    "env",
    [
        {"API_KEY": "${API_KEY}"},
        {"API_KEY": "${env:API_KEY}"},
        {"API_KEY": "${input:apiKey}"},
        {"TOKEN": "your-token-here"},
        {"API_KEY": "<YOUR_API_KEY>"},
        {"LOG_LEVEL": "debug", "WORKSPACE": "/srv/app/workspace-01"},
        {"PASSWORD": "short"},
    ],
)
def test_references_and_placeholders_are_not_secrets(tmp_path, env):
    server = {"command": "node", "args": ["s.js"], "env": env}
    assert _scan(tmp_path, ".mcp.json", _servers(s=server)) == []


def test_engine_reports_a_config_secret_once(tmp_path):
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            _servers(g={"command": "node", "args": ["s.js"], "env": {"GITHUB_TOKEN": TOKEN}})
        ),
        encoding="utf-8",
    )
    result = ScanEngine(Config(scanner_options={"dependencies": {"online": False}})).scan(
        Project.from_path(tmp_path)
    )
    hits = [f for f in result.findings if "CWE-798" in f.cwe]
    assert len(hits) == 1
    assert TOKEN not in json.dumps([f.model_dump(mode="json") for f in result.findings])


# --- unpinned packages ---------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "args", "spec"),
    [
        (
            "npx",
            ["-y", "@modelcontextprotocol/server-github"],
            "@modelcontextprotocol/server-github",
        ),
        ("npx", ["-y", "mcp-remote@latest", "https://x.example.com"], "mcp-remote@latest"),
        ("npx.cmd", ["--yes", "some-server@^1.2.0"], "some-server@^1.2.0"),
        ("cmd", ["/c", "npx", "-y", "@scope/srv"], "@scope/srv"),
        ("npx", ["-p", "@scope/pkg", "bin-name"], "@scope/pkg"),
        ("bunx", ["some-server"], "some-server"),
        ("pnpm", ["dlx", "some-server"], "some-server"),
        ("uvx", ["mcp-server-fetch"], "mcp-server-fetch"),
        ("uvx", ["--from", "mcp-server-git>=0.6", "mcp-server-git"], "mcp-server-git>=0.6"),
        ("uv", ["tool", "run", "mcp-server-time"], "mcp-server-time"),
        ("pipx", ["run", "mcp-server-fetch"], "mcp-server-fetch"),
        ("docker", ["run", "-i", "--rm", "-e", "TOKEN", "mcp/github"], "mcp/github"),
        ("docker", ["run", "-i", "ghcr.io/org/server:latest"], "ghcr.io/org/server:latest"),
    ],
)
def test_unpinned_launches(tmp_path, command, args, spec):
    findings = _scan(tmp_path, ".mcp.json", _servers(s={"command": command, "args": args}))
    assert _rules(findings) == ["mcp-unpinned-package"]
    assert findings[0].metadata["spec"] == spec
    assert findings[0].owasp == ["LLM03:2025-Supply Chain"]


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "@modelcontextprotocol/server-github@2025.4.8"]),
        ("npx", ["-y", "some-server@1.4.0"]),
        ("npx", ["-y", "./local/server"]),
        ("npx", ["-y", "github:org/repo"]),
        ("uvx", ["mcp-server-fetch==2025.4.7"]),
        ("uvx", ["mcp-server-fetch@2025.4.7"]),
        ("uvx", ["--from", "mcp-server-git==0.6.2", "mcp-server-git"]),
        ("uvx", ["--from", "git+https://github.com/org/repo@3f2a1b4", "srv"]),
        ("docker", ["run", "-i", "--rm", "mcp/github@sha256:" + "a" * 64]),
        ("docker", ["run", "-i", "--rm", "mcp/github:1.2.0"]),
        ("node", ["dist/index.js"]),
        ("python", ["-m", "my_server"]),
    ],
)
def test_pinned_or_local_launches(tmp_path, command, args):
    assert _scan(tmp_path, ".mcp.json", _servers(s={"command": command, "args": args})) == []


def test_disabled_server_is_not_run(tmp_path):
    server = {"command": "npx", "args": ["-y", "pkg"], "disabled": True}
    assert _scan(tmp_path, "cline_mcp_settings.json", _servers(s=server)) == []


# --- plaintext transport ------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "url", "hit"),
    [
        ("url", "http://mcp.example.com/mcp", True),
        ("serverUrl", "http://10.1.2.3:8080/sse", True),
        ("httpUrl", "http://tools.corp.example/mcp", True),
        ("url", "https://mcp.example.com/mcp", False),
        ("url", "http://localhost:3000/mcp", False),
        ("url", "http://127.0.0.1:8000/sse", False),
        ("url", "http://[::1]:8000/mcp", False),
        ("url", "${MCP_URL}", False),
    ],
)
def test_plaintext_http(tmp_path, key, url, hit):
    findings = _scan(tmp_path, "mcp_config.json", _servers(r={key: url}))
    assert _rules(findings) == (["mcp-plaintext-http"] if hit else [])


# --- broad filesystem roots ---------------------------------------------------


@pytest.mark.parametrize(
    ("path", "severity"),
    [
        ("/", "HIGH"),
        ("C:\\", "HIGH"),
        ("D:/", "HIGH"),
        ("/Users/alice", "MEDIUM"),
        ("/home/bob/", "MEDIUM"),
        ("C:\\Users\\carol", "MEDIUM"),
        ("~", "MEDIUM"),
        ("${userHome}", "MEDIUM"),
    ],
)
def test_broad_filesystem_root(tmp_path, path, severity):
    server = {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", path],
    }
    findings = _scan(tmp_path, "claude_desktop_config.json", _servers(fs=server))
    assert _rules(findings) == ["mcp-broad-filesystem-root"]
    assert findings[0].severity.name == severity
    assert findings[0].owasp == ["LLM06:2025-Excessive Agency"]


@pytest.mark.parametrize(
    "paths",
    [
        ["/Users/alice/Desktop", "/Users/alice/Downloads"],
        ["./docs", "C:\\Users\\carol\\projects\\app"],
    ],
)
def test_scoped_filesystem_roots(tmp_path, paths):
    server = {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", *paths],
    }
    assert _scan(tmp_path, "claude_desktop_config.json", _servers(fs=server)) == []


def test_docker_filesystem_mount_of_root(tmp_path):
    server = {
        "command": "docker",
        "args": [
            "run",
            "-i",
            "--rm",
            "--mount",
            "type=bind,src=/,dst=/projects/root",
            "mcp/filesystem@sha256:" + "b" * 64,
            "/projects",
        ],
    }
    assert _rules(_scan(tmp_path, ".mcp.json", _servers(fs=server))) == [
        "mcp-broad-filesystem-root"
    ]


def test_non_filesystem_server_paths_are_not_judged(tmp_path):
    server = {"command": "node", "args": ["/opt/srv/index.js", "/"]}
    assert _scan(tmp_path, ".mcp.json", _servers(s=server)) == []


# --- auto-approval ------------------------------------------------------------


@pytest.mark.parametrize(
    ("rel", "server"),
    [
        (
            "cline_mcp_settings.json",
            {"command": "node", "args": ["a.js"], "autoApprove": ["run_command"]},
        ),
        (".roo/mcp.json", {"command": "node", "args": ["a.js"], "alwaysAllow": ["write_file"]}),
        (".gemini/settings.json", {"command": "node", "args": ["a.js"], "trust": True}),
    ],
)
def test_per_server_auto_approval(tmp_path, rel, server):
    findings = _scan(tmp_path, rel, _servers(s=server))
    assert _rules(findings) == ["agent-auto-approve"]


@pytest.mark.parametrize(
    ("rel", "server"),
    [
        ("cline_mcp_settings.json", {"command": "node", "args": ["a.js"], "autoApprove": []}),
        (".gemini/settings.json", {"command": "node", "args": ["a.js"], "trust": False}),
    ],
)
def test_no_auto_approval(tmp_path, rel, server):
    assert _scan(tmp_path, rel, _servers(s=server)) == []


def test_claude_code_settings(tmp_path):
    settings = {
        "enableAllProjectMcpServers": True,
        "permissions": {
            "allow": ["Bash(npm run test *)", "Bash", "Read(./src/**)"],
            "additionalDirectories": ["../shared-lib", "/"],
            "defaultMode": "bypassPermissions",
        },
    }
    findings = _scan(tmp_path, ".claude/settings.json", settings)
    got = sorted((f.rule_id.split(".", 1)[1], f.severity.name) for f in findings)
    assert got == [
        ("agent-auto-approve", "HIGH"),
        ("agent-auto-approve", "LOW"),
        ("agent-auto-approve", "MEDIUM"),
        ("mcp-broad-filesystem-root", "HIGH"),
    ]


def test_scoped_claude_code_settings_are_clean(tmp_path):
    settings = {
        "enabledMcpjsonServers": ["github"],
        "permissions": {
            "allow": ["Bash(npm run lint)", "Bash(git diff *)", "mcp__github__get_issue"],
            "deny": ["Bash"],
            "additionalDirectories": ["../docs"],
            "defaultMode": "acceptEdits",
        },
    }
    assert _scan(tmp_path, ".claude/settings.local.json", settings) == []


# --- parsing --------------------------------------------------------------------


def test_jsonc_with_comments_and_trailing_commas(tmp_path):
    text = (
        '{\n  // VS Code config\n  "servers": {\n'
        '    "f": { "type": "stdio", "command": "uvx", "args": ["mcp-server-fetch",], },\n'
        "  },\n}\n"
    )
    findings = _scan(tmp_path, ".vscode/mcp.json", text)
    assert _rules(findings) == ["mcp-unpinned-package"]
    assert findings[0].location.start_line == 4


@pytest.mark.parametrize(
    "text",
    ["{not json", "[1, 2]", "", "[" * 100000 + "]" * 100000],
    ids=["broken", "not-an-object", "empty", "deeply-nested"],
)
def test_malformed_config_is_skipped(tmp_path, text):
    assert _scan(tmp_path, ".mcp.json", text) == []


def test_module_regexes_are_linear():
    import re
    import time

    inputs = ["a" * 2000, " " * 2000, "@" + "a" * 1998, "-" * 2000, "${" * 1000, "%a" * 1000]
    slow = []
    for name, val in vars(agent_config).items():
        if isinstance(val, re.Pattern):
            for s in inputs:
                start = time.perf_counter()
                val.search(s)
                if time.perf_counter() - start > 0.5:
                    slow.append(name)
    assert not slow


def test_jsonc_stripper_keeps_strings():
    raw = '{"a": "http://x//y", "b": "/* not a comment */", /* real */ "c": [1,],}'
    assert agent_config.load_config(raw) == {
        "a": "http://x//y",
        "b": "/* not a comment */",
        "c": [1],
    }
