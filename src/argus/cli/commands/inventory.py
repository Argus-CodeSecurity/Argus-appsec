"""Asset inventory and drift: ``argus inventory`` and ``argus drift``."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.table import Table

from argus.cli._common import cli_severity, resolve_project
from argus.cli._console import console, err_console
from argus.cli.output import write_stdout
from argus.core.models import ScanResult


def inventory(
    target: str = typer.Argument(".", help="Local path or git URL to analyze."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write JSON inventory here."),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Export static asset inventory: languages, architecture, dependencies, infra files."""
    import json

    from argus.inventory.asset_map import build_inventory

    resolved, project = resolve_project(
        target, "inventory requires a source repository or local path."
    )
    try:
        payload = build_inventory(project)
        if output:
            output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            console.print(f"[green]Inventory:[/green] {output}")
        else:
            write_stdout(json.dumps(payload, indent=2) + "\n")
        if not quiet:
            c = payload["counts"]
            err_console.print(
                f"[dim]- {c['files']} files, {c['dependencies']} dependencies, "
                f"{c['ci_cd_files']} CI/CD, {c['container_files']} container, "
                f"{c['iac_files']} IaC[/dim]"
            )
    finally:
        resolved.cleanup()


def drift(
    before: Path = typer.Argument(..., help="Earlier Argus JSON report or inventory."),
    after: Path = typer.Argument(..., help="Later Argus JSON report or inventory."),
    inventory: bool = typer.Option(
        False,
        "--inventory",
        help="Compare inventory JSON files (from `argus inventory -o`).",
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write drift JSON here."),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Exit non-zero if added/changed findings meet this severity (scan mode).",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Detect configuration drift between two scan or inventory snapshots."""
    import json

    from argus.analysis.drift import (
        compare_inventories,
        compare_scans,
        highest_added_severity,
    )

    try:
        before_data = json.loads(before.read_text(encoding="utf-8"))
        after_data = json.loads(after.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        err_console.print(f"[red]Error:[/red] invalid JSON input: {exc}")
        raise typer.Exit(2) from exc

    if inventory or before_data.get("dependencies") is not None and "findings" not in before_data:
        payload = compare_inventories(before_data, after_data)
        if output:
            output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        if not quiet:
            s = payload["summary"]
            table = Table(title="Inventory drift")
            table.add_column("Change")
            table.add_column("Count")
            table.add_row("Dependencies added", str(s["deps_added"]))
            table.add_row("Dependencies removed", str(s["deps_removed"]))
            table.add_row("Dependencies changed", str(s["deps_changed"]))
            table.add_row("Architecture areas changed", str(s["arch_areas_changed"]))
            console.print(table)
        raise typer.Exit(0)

    try:
        before_scan = ScanResult.model_validate(before_data)
        after_scan = ScanResult.model_validate(after_data)
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] expected Argus scan JSON: {exc}")
        raise typer.Exit(2) from exc

    report = compare_scans(before_scan, after_scan)
    payload = report.to_dict()
    if output:
        output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if not quiet:
        s = report.summary()
        table = Table(title="Scan drift (configuration / posture change)")
        table.add_column("Change")
        table.add_column("Count")
        table.add_row("Findings added", str(s["added"]))
        table.add_row("Findings removed", str(s["removed"]))
        table.add_row("Severity escalations", str(s["severity_changed"]))
        console.print(table)
        for item in report.added[:15]:
            err_console.print(
                f"  [red]+[/red] {item.severity} {item.rule_id} {item.title} ({item.location})"
            )
        if len(report.added) > 15:
            err_console.print(f"  [dim]… and {len(report.added) - 15} more added[/dim]")

    if fail_on and highest_added_severity(report) >= cli_severity(fail_on, "--fail-on"):
        raise typer.Exit(1)
