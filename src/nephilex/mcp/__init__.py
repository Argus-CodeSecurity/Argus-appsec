"""Model Context Protocol (MCP) server for Nephilex.

Exposes Nephilex as a tool that AI coding agents can call, so a scan runs
automatically after code is generated. See :mod:`nephilex.mcp.server`.
"""

from nephilex.mcp.server import handle_request, run_stdio

__all__ = ["handle_request", "run_stdio"]
