"""Tests for the MCP (Model Context Protocol) stdio server dispatch."""

from __future__ import annotations

import json

from argus.mcp.server import handle_request


def test_mcp_help_lists_every_tool():
    from typer.testing import CliRunner

    from argus.cli.main import app
    from argus.mcp.server import TOOLS

    res = CliRunner().invoke(app, ["mcp", "--help"], terminal_width=200)
    assert res.exit_code == 0, res.output
    text = " ".join(res.output.split())
    for tool in TOOLS:
        assert tool["name"] in text, tool["name"]


def test_initialize_returns_capabilities_and_server_info():
    resp = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
    )
    assert resp["id"] == 1
    result = resp["result"]
    assert result["serverInfo"]["name"] == "argus-appsec"
    assert "tools" in result["capabilities"]
    assert result["protocolVersion"] == "2024-11-05"  # echoes the client's version


def test_tools_list_exposes_argus_scan():
    resp = handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools = resp["result"]["tools"]
    assert any(t["name"] == "argus_scan" for t in tools)
    scan = next(t for t in tools if t["name"] == "argus_scan")
    assert "path" in scan["inputSchema"]["required"]


def test_notification_gets_no_reply():
    assert handle_request({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_unknown_method_is_jsonrpc_error():
    resp = handle_request({"jsonrpc": "2.0", "id": 3, "method": "does/not/exist"})
    assert resp["error"]["code"] == -32601


def test_unknown_tool_is_reported_in_band():
    resp = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "bogus", "arguments": {}},
        }
    )
    assert resp["result"]["isError"] is True


def test_scan_tool_returns_structured_findings(vulnerable_project, monkeypatch):
    # The tool only scans inside its allowed roots (default: the working directory).
    monkeypatch.setenv("ARGUS_MCP_ROOTS", str(vulnerable_project.root))
    resp = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "argus_scan",
                "arguments": {"path": str(vulnerable_project.root), "min_severity": "low"},
            },
        }
    )
    assert resp["result"].get("isError") in (False, None)
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload["summary"]["total_findings"] > 0
    assert payload["findings"]
    assert {"rule_id", "scanner", "severity", "title", "location"} <= set(payload["findings"][0])


def test_scan_tool_bad_path_is_reported_in_band():
    resp = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "argus_scan", "arguments": {"path": "/no/such/path/argus-xyz"}},
        }
    )
    assert resp["result"]["isError"] is True
    assert "Scan failed" in resp["result"]["content"][0]["text"]
