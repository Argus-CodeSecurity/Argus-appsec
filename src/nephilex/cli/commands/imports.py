"""``nephilex import``: bring SARIF from other scanners into Nephilex reports and gates.

The module is ``imports`` because ``import`` is a Python keyword; the command
itself is registered as ``nephilex import``.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.markup import escape

from nephilex.cli._common import apply_baseline, apply_diff, build_config, cli_severity
from nephilex.cli._console import err_console
from nephilex.cli.output import emit, print_posture

FORMAT_HELP = (
    "Output format(s): table, json, sarif, gitlab, markdown, html, csv, junit, badge, vex. "
    "Repeatable."
)


def load_imports(files: list[Path], project_root: Path, *, quiet: bool):
    """Parse SARIF files for a command, exiting 2 if any file is rejected.

    Shared by ``nephilex import`` and ``nephilex scan --import-sarif``. Warnings
    (dropped unsafe paths, missing version) are always printed: they explain
    why a result is missing from the report.
    """
    from nephilex.importers import SarifImportError, import_sarif

    try:
        imported = import_sarif(files, project_root=project_root)
    except SarifImportError as exc:
        err_console.print(f"[red]Error:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc
    for warning in imported.warnings:
        err_console.print(f"[yellow]Import warning:[/yellow] {escape(warning)}")
    if not quiet:
        stats = imported.stats
        skipped = {
            "suppressed by the tool": stats["suppressed"],
            "not a problem": stats["not_a_problem"],
            "absent from the baseline": stats["absent"],
            "unsafe path": stats["unsafe_path"],
            "duplicate": stats["duplicate"],
            "malformed": stats["invalid"],
        }
        detail = ", ".join(f"{n} {why}" for why, n in skipped.items() if n)
        err_console.print(
            f"[dim]- Imported {stats['imported']} of {stats['results']} SARIF result(s) "
            f"from {escape(', '.join(imported.tools) or 'no tools')}"
            + (f" (skipped: {escape(detail)})" if detail else "")
            + ".[/dim]"
        )
    return imported


def import_cmd(
    files: list[Path] = typer.Argument(
        ..., help="SARIF 2.1.0 file(s) from Semgrep, CodeQL, gitleaks, Trivy, Bandit, ..."
    ),
    project: Path = typer.Option(
        Path("."),
        "--project",
        "-p",
        help="Project root the SARIF paths are relative to. Results outside it are dropped.",
    ),
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to a .nephilex.yml config file."
    ),
    fmt: list[str] = typer.Option(["table"], "--format", "-f", help=FORMAT_HELP),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write reports here. A directory writes one file per non-table format.",
    ),
    min_severity: str | None = typer.Option(
        None, "--min-severity", help="Report findings at/above this severity."
    ),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help="Exit 1 if any finding is at/above this severity."
    ),
    baseline: Path | None = typer.Option(
        None,
        "--baseline",
        help="Path to a previous Nephilex JSON report; report only findings not in it.",
    ),
    diff_ref: str | None = typer.Option(
        None,
        "--diff",
        help="Git ref range (e.g. origin/main...HEAD); report only findings on changed lines.",
    ),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI enrichment entirely."),
    patches: bool = typer.Option(
        False, "--patches", help="Generate (and where possible verify) fix patches."
    ),
    audience: str | None = typer.Option(
        None, "--audience", help="Re-render the console output for: dev, exec, or auditor."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output."),
) -> None:
    """Import SARIF results from other scanners and report and gate on them."""
    from nephilex.cli._common import progress_printer
    from nephilex.core.engine import ScanEngine
    from nephilex.core.project import Project
    from nephilex.importers import import_result

    for value, flag in ((min_severity, "--min-severity"), (fail_on, "--fail-on")):
        if value:
            cli_severity(value, flag)
    if not project.is_dir():
        err_console.print(
            f"[red]Error:[/red] project root {escape(str(project))} is not a directory."
        )
        raise typer.Exit(2)

    proj = Project.from_path(project)
    imported = load_imports(files, proj.root, quiet=quiet)
    try:
        cfg = build_config(
            config=config,
            project=proj,
            scanners=None,
            exclude=None,
            ai_provider=None,
            ai_model=None,
            no_ai=no_ai,
            attack_sim=False,
            patches=patches,
            min_severity=min_severity,
            fail_on=fail_on,
        )
    except FileNotFoundError as exc:
        err_console.print(f"[red]Error:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc

    result = import_result(imported, proj, cfg, progress=progress_printer(quiet))
    merged = result.project_summary["imported_sarif"]["merged"]
    if merged and not quiet:
        err_console.print(
            f"[dim]- {merged} result(s) reported the same issue as another tool "
            "and were merged.[/dim]"
        )
    if baseline is not None:
        apply_baseline(result, baseline, quiet=quiet, project=proj, cfg=cfg)
    if diff_ref is not None:
        apply_diff(result, proj.root, diff_ref, quiet=quiet)

    emit(result, fmt, output, audience=audience)
    if not quiet and ("table" in fmt or audience):
        print_posture(result, cfg.fail_on)

    if ScanEngine(cfg).should_fail(result):
        err_console.print(
            f"[red]Failing:[/red] findings at/above {cfg.fail_on.label if cfg.fail_on else ''}."
        )
        if quiet:
            from nephilex.reporting.posture import evaluate_posture

            err_console.print(f"[dim]{evaluate_posture(result, cfg.fail_on).headline}[/dim]")
        raise typer.Exit(1)
