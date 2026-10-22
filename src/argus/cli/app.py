"""The ``argus`` Typer application.

This module builds the root command group: the ``--version`` flag, the
configuration-error handling shared by every command, the built-in plugin
registration, the built-in commands (see :mod:`argus.cli.commands`) and any
third-party commands from the ``argus.commands`` entry-point group.
"""

from __future__ import annotations

from typing import Any

import typer
from rich.markup import escape
from typer.core import TyperGroup

from argus import __version__
from argus.cli._console import console, err_console
from argus.cli.commands import imports, register_commands
from argus.cli.plugins import load_plugin_commands
from argus.core.config import ConfigError
from argus.plugins import register_builtins

# Register built-in plugins up front so `scanners`/`reporters`/`providers` work
# even without the entry-point discovery path (e.g. running from source).
register_builtins()


class _ArgusGroup(TyperGroup):
    """Root command group that turns configuration errors into exit status 2.

    A config problem (bad type in .argus.yml, unknown scanner name, invalid
    policy) can surface in any command, sometimes deep inside the engine.
    Catching it once here keeps every command consistent: the run stops with a
    clear message and exit 2, never a traceback that CI could confuse with a
    gate decision.
    """

    def invoke(self, ctx: Any) -> Any:
        try:
            return super().invoke(ctx)
        except ConfigError as exc:
            err_console.print(f"[red]Configuration error:[/red] {escape(str(exc))}")
            raise typer.Exit(2) from exc


app = typer.Typer(
    name="argus",
    help="Argus, an open-source AI Security Engineer.",
    add_completion=False,
    no_args_is_help=True,
    cls=_ArgusGroup,
)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"Argus v{__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show the Argus version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """Argus, an open-source AI Security Engineer.

    Point Argus at a codebase and it finds vulnerabilities, explains them, and can
    fix them. Run `argus COMMAND --help` for details on any command, e.g.
    `argus scan --help`.
    """


register_commands(app)
app.command(name="import")(imports.import_cmd)
load_plugin_commands(app)
