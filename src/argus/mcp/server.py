"""A minimal MCP (Model Context Protocol) stdio server exposing Argus as a tool.

AI coding agents increasingly run scanners automatically after they generate
code. This server lets an agent call Argus over MCP, so "scan what you just wrote"
becomes a single tool call. It speaks JSON-RPC 2.0 over newline-delimited stdio
and implements the handful of methods a client needs (``initialize``,
``tools/list``, ``tools/call``), with no external SDK, so it stays dependency-light
and works offline like the rest of Argus.

The dispatch is a pure function (:func:`handle_request`) so it is fully testable
without touching real stdio.

The agent calling the tool is not fully trusted (it may be acting on prompt
injection), so the tool only scans paths inside the server's working directory
or the directories listed in ``ARGUS_MCP_ROOTS`` (``os.pathsep``-separated),
never honours rules shipped inside the scanned tree, and gives up on a scan
after ``ARGUS_MCP_SCAN_TIMEOUT`` seconds (default 600).
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import threading
from pathlib import Path
from typing import Any, TextIO

from argus import __version__

# A protocol version we implement; we echo the client's requested version when it
# sends one, which is what interoperable MCP servers do.
PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "argus-appsec", "version": __version__}

# Cap on findings returned in one tool call, so a huge scan does not overwhelm an
# agent's context. The summary always reports the true total and whether the list
# was truncated, so coverage is never silently hidden.
_MAX_FINDINGS = 200

ROOTS_ENV = "ARGUS_MCP_ROOTS"
TIMEOUT_ENV = "ARGUS_MCP_SCAN_TIMEOUT"
_DEFAULT_TIMEOUT = 600.0

TOOLS: list[dict[str, Any]] = [
    {
        "name": "argus_scan",
        "description": (
            "Scan a local path for security vulnerabilities across code (SAST + "
            "taint), dependencies (CVEs), secrets, infrastructure-as-code, and "
            "LLM/AI usage (OWASP Top 10 for LLM Apps). Returns findings with "
            "severity, CWE/OWASP mapping, location, and remediation. Read-only: it "
            "never modifies the scanned files."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Local directory or file to scan. Must be inside the "
                        "server's working directory (or ARGUS_MCP_ROOTS)."
                    ),
                },
                "min_severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                    "description": "Only return findings at or above this severity.",
                    "default": "low",
                },
            },
            "required": ["path"],
        },
    },
]


# --- JSON-RPC helpers ------------------------------------------------------
def _ok(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _err(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _tool_text(text: str, *, is_error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


# --- the scan tool ---------------------------------------------------------
def allowed_roots() -> list[Path]:
    """Directories the tool may scan: ARGUS_MCP_ROOTS, else the working directory."""
    raw = os.environ.get(ROOTS_ENV, "")
    roots = [Path(p).expanduser() for p in raw.split(os.pathsep) if p.strip()]
    return [r.resolve() for r in (roots or [Path.cwd()])]


def resolve_scan_path(path: str) -> Path:
    """Resolve ``path`` (relative to the working directory) and confine it to the roots.

    Symlinks and ``..`` are resolved first, so neither can step outside.
    """
    resolved = Path(path).expanduser().resolve()
    roots = allowed_roots()
    if not any(resolved == root or resolved.is_relative_to(root) for root in roots):
        shown = ", ".join(str(r) for r in roots)
        raise ValueError(
            f"path {path!r} is outside the allowed roots ({shown}); "
            f"set {ROOTS_ENV} to allow other directories"
        )
    if not resolved.exists():
        raise ValueError(f"path {path!r} does not exist")
    return resolved


def _scan_timeout() -> float:
    try:
        return max(1.0, float(os.environ.get(TIMEOUT_ENV, _DEFAULT_TIMEOUT)))
    except ValueError:
        return _DEFAULT_TIMEOUT


def _run_with_timeout(fn: Any, timeout: float) -> Any:
    """Run ``fn`` in a daemon thread; raise TimeoutError if it overruns.

    The scan cannot be interrupted, so it keeps running in the background, but
    the client gets an answer and the server keeps serving requests.
    """
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # re-raised in the caller's thread
            box["error"] = exc

    worker = threading.Thread(target=target, name="argus-mcp-scan", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise TimeoutError(f"scan did not finish within {timeout:g}s ({TIMEOUT_ENV})")
    if "error" in box:
        raise box["error"]
    return box["value"]


def _run_scan(arguments: dict[str, Any]) -> dict[str, Any]:
    """Run a scan and return a compact, structured result for an agent."""
    from argus.core.config import Config
    from argus.core.engine import ScanEngine
    from argus.core.models import Severity
    from argus.core.project import Project
    from argus.plugins import register_builtins

    path = arguments.get("path")
    if not path or not isinstance(path, str):
        raise ValueError("'path' (a local directory or file) is required")
    target = resolve_scan_path(path)

    register_builtins()
    min_sev = Severity.parse(str(arguments.get("min_severity", "low")))
    cfg = Config(min_severity=min_sev)
    # The scanned tree may be untrusted (the agent may have just cloned it), so
    # in-repo extension points such as .argus/rules are not honoured.
    cfg.trust_project_config = False
    result = _run_with_timeout(
        lambda: ScanEngine(cfg).scan(Project.from_path(target)),
        _scan_timeout(),
    )

    findings = result.sorted_findings()
    shown = findings[:_MAX_FINDINGS]
    return {
        "target": result.target,
        "summary": {
            "total_findings": len(findings),
            "returned": len(shown),
            "truncated": len(findings) > _MAX_FINDINGS,
            "by_severity": result.counts_by_severity(),
            "risk_score": result.aggregate_risk(),
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "scanner": f.scanner,
                "severity": f.severity.label,
                "title": f.title,
                "location": f.location.as_ref(),
                "cwe": f.cwe,
                "owasp": f.owasp,
                "remediation": f.remediation.summary if f.remediation else "",
            }
            for f in shown
        ],
    }


# --- dispatch --------------------------------------------------------------
def handle_request(req: dict[str, Any]) -> dict[str, Any] | None:
    """Handle one JSON-RPC request. Returns a response dict, or None for a
    notification (which has no id and expects no reply)."""
    method = req.get("method")
    req_id = req.get("id")

    if method == "initialize":
        params = req.get("params") or {}
        return _ok(
            req_id,
            {
                "protocolVersion": params.get("protocolVersion", PROTOCOL_VERSION),
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            },
        )

    if method == "tools/list":
        return _ok(req_id, {"tools": TOOLS})

    if method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        if name != "argus_scan":
            return _ok(req_id, _tool_text(f"Unknown tool: {name!r}", is_error=True))
        try:
            payload = _run_scan(params.get("arguments") or {})
        except Exception as exc:  # tool errors are reported in-band, not as protocol errors
            return _ok(req_id, _tool_text(f"Scan failed: {exc}", is_error=True))
        return _ok(req_id, _tool_text(json.dumps(payload, indent=2)))

    # Notifications (e.g. notifications/initialized) carry no id and get no reply.
    if req_id is None:
        return None
    return _err(req_id, -32601, f"Method not found: {method}")


def _force_utf8(stream: Any, **kwargs: str) -> None:
    """MCP is UTF-8 JSON; on Windows the console default (e.g. cp1252) mangles it."""
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is None:
        return
    with contextlib.suppress(ValueError, OSError):
        reconfigure(encoding="utf-8", **kwargs)


def run_stdio(stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
    """Serve MCP over newline-delimited JSON-RPC on stdio until EOF."""
    if stdin is None:
        stdin = sys.stdin
        _force_utf8(stdin, errors="replace")
    if stdout is None:
        stdout = sys.stdout
        _force_utf8(stdout, newline="\n")
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue  # ignore a malformed line rather than crash the server
        if not isinstance(req, dict):
            continue
        response = handle_request(req)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()
