"""Continuous monitoring: ``argus watch``, ``argus agent`` and ``argus server``."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.markup import escape

from argus.cli._common import cli_severity, split_csv
from argus.cli._console import console, err_console
from argus.cli.output import emit
from argus.core.config import Config, ConfigError, load_project_config
from argus.core.models import ScanResult


def watch(
    target: str = typer.Argument(".", help="Local path or git URL to monitor."),
    interval: int = typer.Option(300, "--interval", "-i", help="Seconds between scans."),
    state_dir: Path = typer.Option(
        Path(".argus/watch"),
        "--state-dir",
        help="Directory for scan snapshots and drift history.",
    ),
    once: bool = typer.Option(False, "--once", help="Run a single cycle and exit."),
    push: bool = typer.Option(False, "--push", help="Upload each scan to Argus Cloud."),
    url: str | None = typer.Option(None, "--url", help="Cloud base URL (or ARGUS_CLOUD_URL)."),
    token: str | None = typer.Option(
        None, "--token", help="Cloud API token (or ARGUS_CLOUD_TOKEN)."
    ),
    scanners_opt: str | None = typer.Option(
        None, "--scanners", "-s", help="Comma-separated scanners."
    ),
    config: Path | None = typer.Option(None, "--config", "-c", help="Optional .argus.yml path."),
    fail_on_drift: str | None = typer.Option(
        None,
        "--fail-on-drift",
        help="Exit non-zero when new/changed findings meet this severity.",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Run periodic scans, track drift locally, and optionally push to Argus Cloud."""
    import os

    from argus.core.engine import ScanEngine
    from argus.targets import ResolvedTarget, resolve
    from argus.upload import PushError, build_ingest_payload, push_result
    from argus.watch import run_watch_loop, state_dir_for

    drift_floor = cli_severity(fail_on_drift, "--fail-on-drift") if fail_on_drift else None
    store = state_dir_for(target, state_dir)
    cloud_url = url or os.environ.get("ARGUS_CLOUD_URL")
    cloud_token = token or os.environ.get("ARGUS_CLOUD_TOKEN")
    if push and (not cloud_url or not cloud_token):
        err_console.print(
            "[red]Error:[/red] --push requires --url/--token or ARGUS_CLOUD_URL/ARGUS_CLOUD_TOKEN."
        )
        raise typer.Exit(2)

    def load_cycle() -> tuple[ResolvedTarget, Config]:
        """Resolve the target and its config afresh.

        A Project caches its file list and file contents, so reusing one across
        cycles would scan the first cycle's snapshot forever and never see
        changes. Each cycle therefore re-resolves (re-cloning a remote) and
        re-reads the config, then cleans up.
        """
        resolved = resolve(target)
        try:
            if resolved.project is None:
                raise ValueError("watch requires a source repository or local path.")
            cfg = load_project_config(resolved.project, config)
            if scanners_opt:
                cfg.scanners = split_csv(scanners_opt)
        except BaseException:
            resolved.cleanup()
            raise
        return resolved, cfg

    # Resolve once up front so a bad target or config exits 2 immediately; the
    # first cycle then uses this resolution instead of resolving twice.
    try:
        pending = [load_cycle()]
    except ConfigError:
        raise
    except Exception as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc

    def scan_once() -> ScanResult:
        resolved, cfg = pending.pop() if pending else load_cycle()
        try:
            assert resolved.project is not None
            return ScanEngine(cfg).scan(resolved.project)
        finally:
            resolved.cleanup()

    def maybe_push(result: ScanResult) -> None:
        if not push:
            return
        payload = build_ingest_payload(result)
        push_result(payload, url=cloud_url, token=cloud_token)  # type: ignore[arg-type]

    def on_cycle(outcome) -> None:
        if quiet:
            return
        counts = outcome.scan.counts_by_severity()
        err_console.print(
            f"[dim]- watch {outcome.snapshot_path.name}: "
            f"{len(outcome.scan.findings)} findings "
            f"({counts.get('critical', 0)} critical)[/dim]"
        )
        if outcome.drift:
            ds = outcome.drift.summary()
            if ds["added"] or ds["severity_changed"]:
                err_console.print(
                    f"[yellow]drift[/yellow] +{ds['added']} added, "
                    f"{ds['severity_changed']} severity changes"
                )

    try:
        code = run_watch_loop(
            scan_fn=scan_once,
            state_dir=store,
            interval_seconds=interval,
            once=once,
            fail_on_drift=drift_floor,
            push_fn=maybe_push if push else None,
            on_cycle=on_cycle,
            # The loop keeps running after a failed cycle; say so rather than
            # going quiet, so a broken scan or push is visible to the operator.
            on_error=lambda exc: err_console.print(
                f"[red]watch cycle failed, retrying next interval:[/red] {escape(str(exc))}"
            ),
        )
    except PushError as exc:
        err_console.print(f"[red]Push failed:[/red] {exc}")
        raise typer.Exit(2) from exc
    finally:
        for resolved, _cfg in pending:
            resolved.cleanup()

    if code:
        raise typer.Exit(code)


def agent(
    config: Path = typer.Option(
        Path(".argus/agent.yml"),
        "--config",
        "-c",
        help="Agent config file (see examples/agent.yml).",
    ),
    init: bool = typer.Option(False, "--init", help="Write a starter agent config and exit."),
    once: bool = typer.Option(False, "--once", help="Run one cycle across all targets and exit."),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Run the server agent: monitor multiple paths on this host on a schedule.

    Designed for cron, systemd, or long-running deployment. Each target is scanned,
    drift is tracked locally, and results can be pushed to Argus Cloud.
    """
    from argus.agent import load_agent_config, run_agent_loop, write_default_agent_config
    from argus.upload import PushError

    if init:
        path = write_default_agent_config(config)
        console.print(f"[green]Agent config:[/green] {path}")
        raise typer.Exit(0)

    try:
        cfg = load_agent_config(config)
    except (OSError, ValueError, FileNotFoundError) as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        err_console.print("[dim]Run `argus agent --init` to create a starter config.[/dim]")
        raise typer.Exit(2) from exc

    if not quiet:
        err_console.print(
            f"[dim]- agent monitoring {len(cfg.targets)} target(s) "
            f"every {cfg.interval}s (host: {cfg.host_label})[/dim]"
        )

    def on_cycle(summary) -> None:
        # Step failures are always shown: they mean part of the host went
        # unmonitored this cycle.
        for error in summary.errors:
            err_console.print(f"[red]agent step failed:[/red] {escape(error)}")
        if quiet:
            return
        err_console.print(
            f"[dim]- agent cycle: {summary.targets_scanned} targets, "
            f"{summary.total_findings} findings[/dim]"
        )

    try:
        code = run_agent_loop(cfg, once=once, on_cycle=on_cycle)
    except PushError as exc:
        err_console.print(f"[red]Push failed:[/red] {exc}")
        raise typer.Exit(2) from exc

    if code:
        raise typer.Exit(code)


server_app = typer.Typer(help="Authorized host/server posture (read-only).")


@server_app.command("scan")
def server_scan(
    label: str | None = typer.Option(None, "--label", help="Host label in reports."),
    fmt: list[str] = typer.Option(["table"], "--format", "-f"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    fail_on: str | None = typer.Option(None, "--fail-on"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Read-only host posture: listeners, SSH config, and exposure signals."""
    from argus.agent.host_posture import assess_host

    if not quiet:
        err_console.print(
            "[dim]- Read-only host checks on this machine. "
            "Only run on systems you are authorized to assess.[/dim]"
        )
    result = assess_host(label=label)
    emit(result, fmt, output)
    if fail_on and result.highest_severity() >= cli_severity(fail_on, "--fail-on"):
        raise typer.Exit(1)
