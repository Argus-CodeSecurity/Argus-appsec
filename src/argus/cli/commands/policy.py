"""``argus policy``: evaluate configured security policies against findings."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.table import Table

from argus.cli._common import (
    CONFIG_FROM_REF_HELP,
    fail_on_scanner_errors,
    progress_printer,
    resolve_project,
    split_csv,
)
from argus.cli._console import console, err_console
from argus.core.config import Config, load_project_config
from argus.core.models import ScanResult

policy_app = typer.Typer(help="Evaluate security policies against scan findings.")


def required_policies(cfg: Config) -> list[dict]:
    """Validated policies for `policy check`; exit 2 if there are none.

    Invalid policies raise PolicyError (a ConfigError, so exit 2). Having no
    policies at all is also a usage error: the user asked for a policy gate,
    and passing it with nothing to check would be a silent pass.
    """
    from argus.policy import load_policies

    policies = load_policies(cfg.policies)
    if not policies:
        err_console.print(
            "[red]Error:[/red] no policies configured. Add a ``policies:`` section "
            "to .argus.yml or pass --config (see docs/configuration.md)."
        )
        raise typer.Exit(2)
    return policies


@policy_app.command("check")
def policy_check(
    target: str = typer.Argument(".", help="Local path or git URL to scan."),
    config: Path | None = typer.Option(
        None, "--config", "-c", help="Path to an .argus.yml with policies:."
    ),
    config_from_ref: str | None = typer.Option(
        None,
        "--config-from-ref",
        metavar="REF",
        help=CONFIG_FROM_REF_HELP,
    ),
    report: Path | None = typer.Option(
        None,
        "--report",
        "-r",
        help="Evaluate policies against an existing Argus JSON report instead of scanning.",
    ),
    scanners_opt: str | None = typer.Option(
        None, "--scanners", "-s", help="Comma-separated scanners (when scanning)."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output."),
) -> None:
    """Run (or load) a scan and evaluate ``policies:`` from config."""
    from argus.core.engine import ScanEngine
    from argus.policy import evaluate

    if report is not None:
        try:
            result = ScanResult.model_validate_json(report.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            err_console.print(f"[red]Error:[/red] invalid report: {exc}")
            raise typer.Exit(2) from exc
        if config_from_ref:
            from argus.core.config import load_config_from_ref

            cfg = load_config_from_ref(Path.cwd(), config_from_ref, config)
        else:
            cfg = Config.load(path=config)
        policies = required_policies(cfg)
    else:
        resolved, project = resolve_project(target, "policy check requires a source repository.")
        try:
            cfg = load_project_config(project, config, config_from_ref=config_from_ref)
            # Validate before scanning so a broken policy fails fast.
            policies = required_policies(cfg)
            cfg.ai.enabled = False
            if scanners_opt:
                cfg.scanners = split_csv(scanners_opt)
            result = ScanEngine(cfg, progress=progress_printer(quiet)).scan(project)
        finally:
            resolved.cleanup()

    outcome = evaluate(result, policies)
    if outcome.blocked:
        table = Table(title="Policy violations (BLOCK)")
        table.add_column("Policy", style="bold")
        table.add_column("Finding")
        table.add_column("Location")
        for v in outcome.blocked:
            table.add_row(v.policy_id, v.finding.title, v.finding.location.as_ref())
        console.print(table)
    if outcome.warned and not quiet:
        for v in outcome.warned:
            err_console.print(
                f"[yellow]WARN[/yellow] {v.policy_id}: {v.finding.title} "
                f"({v.finding.location.as_ref()})"
            )

    # A policy check is always a gate, so a crashed scanner fails it unless
    # fail_on_error is explicitly false in the config.
    fail_on_scanner_errors(result, cfg, gating=True)
    if outcome.passed:
        console.print(f"[green]Policy check passed[/green] ({len(outcome.violations)} warning(s)).")
        raise typer.Exit(0)
    err_console.print(
        f"[red]Policy check failed:[/red] {len(outcome.blocked)} blocking violation(s)."
    )
    raise typer.Exit(1)
