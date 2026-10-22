"""Information and setup commands.

``argus scanners``, ``reporters``, ``providers``, ``version`` and ``init``.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

import typer
from rich.markup import escape
from rich.table import Table

from argus import __version__
from argus.cli._console import console, err_console
from argus.core.plugin import registry


def starter_config() -> str:
    """The ``.argus.yml`` text that ``argus init`` writes (package data)."""
    return (resources.files("argus.cli") / "starter_config.yml").read_text(encoding="utf-8")


def scanners() -> None:
    """List available scanners."""
    table = Table(title="Scanners", show_lines=False)
    table.add_column("Name", style="bold")
    table.add_column("Category")
    table.add_column("Description")
    for name, cls in sorted(registry.scanners().items()):
        table.add_row(name, cls.category, escape(cls.description))
    console.print(table)


def reporters() -> None:
    """List available report formats."""
    table = Table(title="Reporters")
    table.add_column("Name", style="bold")
    table.add_column("Extension")
    table.add_column("Description")
    for name, cls in sorted(registry.reporters().items()):
        table.add_row(name, cls.extension, escape(cls.description))
    console.print(table)


def providers() -> None:
    """List AI providers and whether each is currently usable."""
    table = Table(title="AI providers")
    table.add_column("Name", style="bold")
    table.add_column("Location")
    table.add_column("Default model")
    table.add_column("Available")
    for name, cls in sorted(registry.ai_providers().items()):
        loc = "remote" if cls.is_remote else "local"
        ok = "[green]yes[/green]" if cls.is_available() else "[dim]no[/dim]"
        table.add_row(name, loc, escape(cls.default_model or "-"), ok)
    console.print(table)
    console.print(
        "[dim]Argus defaults to 'heuristic' (offline) if the requested "
        "provider is unavailable.[/dim]"
    )


def init(
    path: Path = typer.Argument(Path(".argus.yml"), help="Where to write the config."),
) -> None:
    """Write a starter .argus.yml configuration file."""
    if path.exists():
        err_console.print(f"[yellow]{path} already exists; not overwriting.[/yellow]")
        raise typer.Exit(1)
    path.write_text(starter_config(), encoding="utf-8")
    console.print(f"[green]Wrote {path}.[/green] Edit it to tune your scans.")


def version() -> None:
    """Print the Argus version."""
    console.print(f"Argus v{__version__}")
