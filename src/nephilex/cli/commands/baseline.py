"""``nephilex baseline``: record the current findings for diff-aware gating."""

from __future__ import annotations

from pathlib import Path

import typer

from nephilex.cli._common import CONFIG_FROM_REF_HELP, progress_printer, resolve_project
from nephilex.cli._console import console
from nephilex.core.config import load_project_config

baseline_app = typer.Typer(help="Security baseline: gate on new findings only.")


@baseline_app.command("create")
def baseline_create(
    target: str = typer.Argument(".", help="Local path or git URL to scan."),
    output: Path = typer.Option(..., "--output", "-o", help="Write baseline JSON here."),
    config: Path | None = typer.Option(None, "--config", "-c"),
    config_from_ref: str | None = typer.Option(
        None,
        "--config-from-ref",
        metavar="REF",
        help=CONFIG_FROM_REF_HELP,
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Scan a target and save the result as a baseline for diff-aware CI gating."""
    from nephilex.core.engine import ScanEngine

    resolved, project = resolve_project(target, "baseline create requires a source path or repo.")
    try:
        cfg = load_project_config(project, config, config_from_ref=config_from_ref)
        result = ScanEngine(cfg, progress=progress_printer(quiet)).scan(project)
        output.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
        console.print(
            f"[green]Baseline:[/green] {output} ({len(result.findings)} findings recorded)"
        )
    finally:
        resolved.cleanup()
