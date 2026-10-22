"""Argus as a service: ``argus push``, ``argus dashboard`` and ``argus mcp``."""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.markup import escape

from argus.cli._common import (
    cli_severity,
    posture_result,
    progress_printer,
    resolve_target,
    split_csv,
)
from argus.cli._console import console, err_console
from argus.core.config import load_project_config
from argus.core.models import ScanResult, Severity


def mcp() -> None:
    """Run Argus as an MCP server (stdio) so AI coding agents can call it.

    Speaks the Model Context Protocol over stdin/stdout. Tools:
    argus_scan (scan a directory or file), argus_check_files (fast check of
    edited files), argus_check_snippet (check code text), argus_check_package
    (vet a dependency before adding it) and argus_fix (a verified fix as a
    diff, never applied). Point an MCP-capable client at ``argus mcp``; see
    docs/mcp.md.
    """
    from argus.mcp.server import run_stdio

    run_stdio()


def push(
    target: str = typer.Argument(
        ".", help="Local path, git URL, or website URL to scan and upload."
    ),
    report: Path | None = typer.Option(
        None,
        "--report",
        help="Upload an existing Argus JSON report instead of scanning "
        "('-' reads it from stdin, e.g. `argus scan . -f json | argus push --report -`).",
    ),
    url: str | None = typer.Option(
        None, "--url", help="Argus Cloud base URL (or set ARGUS_CLOUD_URL)."
    ),
    token: str | None = typer.Option(
        None, "--token", help="Cloud API token (or set ARGUS_CLOUD_TOKEN)."
    ),
    scanners_opt: str | None = typer.Option(
        None, "--scanners", "-s", help="Comma-separated scanners to run (default: all)."
    ),
    min_severity: str | None = typer.Option(
        None,
        "--min-severity",
        help="Only upload findings at/above this severity (default: low).",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output."),
) -> None:
    """Scan a target (or read a report) and upload the result to Argus Cloud.

    Sends only finding metadata (rule, severity, title, location, CWE), never
    source or secret values, to the cloud's `/api/scans` ingest endpoint so the
    scan shows up in your dashboard's history and trends.
    """
    import os

    from argus.upload import PushError, build_ingest_payload, push_result

    cloud_url = url or os.environ.get("ARGUS_CLOUD_URL")
    cloud_token = token or os.environ.get("ARGUS_CLOUD_TOKEN")
    if not cloud_url or not cloud_token:
        err_console.print(
            "[red]Error:[/red] provide the cloud URL and API token via --url/--token "
            "or the ARGUS_CLOUD_URL/ARGUS_CLOUD_TOKEN environment variables."
        )
        raise typer.Exit(2)

    floor = cli_severity(min_severity, "--min-severity") if min_severity else Severity.LOW

    if report is not None:
        raw = sys.stdin.read() if str(report) == "-" else report.read_text(encoding="utf-8")
        try:
            result = ScanResult.model_validate_json(raw)
        except Exception as exc:
            err_console.print(f"[red]Error:[/red] not a valid Argus JSON report: {exc}")
            raise typer.Exit(2) from exc
    else:
        from argus.core.engine import ScanEngine

        resolved = resolve_target(target)
        try:
            if resolved.web is not None:
                result = posture_result(resolved.web.url, quiet=quiet)
            else:
                project = resolved.project
                assert project is not None
                cfg = load_project_config(project)
                if scanners_opt:
                    cfg.scanners = split_csv(scanners_opt)
                result = ScanEngine(cfg, progress=progress_printer(quiet)).scan(project)
        finally:
            resolved.cleanup()

    payload = build_ingest_payload(result, min_severity=floor)
    try:
        resp = push_result(payload, url=cloud_url, token=cloud_token)
    except PushError as exc:
        err_console.print(f"[red]Upload failed:[/red] {exc}")
        raise typer.Exit(1) from exc

    dash = resp.get("url")
    location = (cloud_url.rstrip("/") + dash) if isinstance(dash, str) and dash else ""
    console.print(
        f"[green]Uploaded {len(payload['findings'])} finding(s) to Argus Cloud.[/green]"
        + (f"\nView it at {location}" if location else "")
    )


def dashboard(
    host: str = typer.Option("127.0.0.1", "--host", help="Address to bind."),
    port: int = typer.Option(8000, "--port", "-p", help="Port to listen on."),
) -> None:
    """Launch the web dashboard (scan history and trends).

    Requires the dashboard extra: pip install "argus-appsec[dashboard]".
    """
    try:
        from argus.dashboard.app import DashboardConfigError, configure, serve
    except ImportError as exc:
        err_console.print(
            "[red]The dashboard needs extra dependencies.[/red] Install them with:\n"
            '  pip install "argus-appsec[dashboard]"'
        )
        raise typer.Exit(1) from exc
    # Validate the bind before announcing a URL: a non-loopback host without a
    # token is refused, and the user should see why rather than a dead link.
    try:
        settings = configure(host)
    except DashboardConfigError as exc:
        err_console.print(f"[red]Error:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc
    console.print(f"Argus dashboard on [bold]http://{host}:{port}[/bold]  (Ctrl+C to stop)")
    if settings.token:
        console.print(
            "Token authentication is on. Open the dashboard with "
            f"[bold]http://{host}:{port}/?token=<ARGUS_DASHBOARD_TOKEN>[/bold] "
            "or send it as a bearer token."
        )
    serve(host=host, port=port)
