"""Information and setup commands.

``nephilex scanners``, ``reporters``, ``providers``, ``version`` and ``init``.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

import typer
from rich.markup import escape

from nephilex import __version__
from nephilex.cli._console import console, err_console
from nephilex.core.plugin import registry


def starter_config() -> str:
    """The ``.nephilex.yml`` text that ``nephilex init`` writes (package data)."""
    return (resources.files("nephilex.cli") / "starter_config.yml").read_text(encoding="utf-8")


def scanners() -> None:
    """List available scanners."""
    from rich.table import Table

    table = Table(title="Scanners", show_lines=False)
    table.add_column("Name", style="bold")
    table.add_column("Category")
    table.add_column("Description")
    for name, cls in sorted(registry.scanners().items()):
        table.add_row(name, cls.category, escape(cls.description))
    console.print(table)


def reporters() -> None:
    """List available report formats."""
    from rich.table import Table

    table = Table(title="Reporters")
    table.add_column("Name", style="bold")
    table.add_column("Extension")
    table.add_column("Description")
    for name, cls in sorted(registry.reporters().items()):
        table.add_row(name, cls.extension, escape(cls.description))
    console.print(table)


def providers() -> None:
    """List AI providers and whether each is currently usable."""
    from rich.table import Table

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
        "[dim]Nephilex defaults to 'heuristic' (offline) if the requested "
        "provider is unavailable.[/dim]"
    )


def init(
    path: Path = typer.Argument(
        Path(".nephilex.yml"), help="Where to write the config (not used with --editor)."
    ),
    editor: list[str] = typer.Option(
        None,
        "--editor",
        help="Set up an editor or AI assistant: claude, cursor or vscode. "
        "Repeatable. Writes that editor's MCP and hook config in the project "
        "instead of .nephilex.yml.",
        show_default=False,
    ),
    project_dir: Path = typer.Option(
        Path("."), "--project-dir", help="Project directory for --editor files."
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Replace existing files. Existing JSON configs keep their other "
        "settings; only the Nephilex entries are added or replaced.",
    ),
) -> None:
    """Write a starter .nephilex.yml, or editor config with --editor."""
    if editor:
        _init_editors(editor, project_dir, force=force)
        return
    if path.exists() and not force:
        err_console.print(
            f"[yellow]{escape(str(path))} already exists; not overwriting (use --force).[/yellow]"
        )
        raise typer.Exit(1)
    path.write_text(starter_config(), encoding="utf-8")
    console.print(f"[green]Wrote {escape(str(path))}.[/green] Edit it to tune your scans.")


def _init_editors(editors: list[str], project_dir: Path, *, force: bool) -> None:
    """Write the editor files, or nothing at all if any of them conflicts."""
    from nephilex.integrations.editors import EDITORS, plan, write

    chosen = list(dict.fromkeys(e.strip().lower() for e in editors))
    unknown = [e for e in chosen if e not in EDITORS]
    if unknown:
        raise typer.BadParameter(
            f"unknown editor(s) {', '.join(unknown)} (choose from: {', '.join(EDITORS)})",
            param_hint="--editor",
        )
    if not project_dir.is_dir():
        err_console.print(
            f"[red]Error:[/red] --project-dir {escape(str(project_dir))} is not a directory."
        )
        raise typer.Exit(2)

    planned = plan(project_dir, chosen, force=force)
    blocked = [p for p in planned if p.action in ("exists", "error")]
    if blocked:
        for p in blocked:
            err_console.print(f"[yellow]{escape(p.file.path)} {escape(p.problem)}.[/yellow]")
        hint = " Use --force to merge the Nephilex entries into them." if not force else ""
        err_console.print(f"Nothing written.{hint}")
        raise typer.Exit(1)
    write(planned)
    verbs = {"create": "Wrote", "merge": "Updated", "overwrite": "Replaced"}
    for p in planned:
        console.print(f"{verbs[p.action]} {escape(p.file.path)}")
    console.print(
        "Next: restart the editor, approve the nephilex MCP server when asked, and "
        "run the checks in docs/editors.md."
    )


def version() -> None:
    """Print the Nephilex version."""
    console.print(f"Nephilex v{__version__}")
