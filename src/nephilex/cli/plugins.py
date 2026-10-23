"""Third-party CLI commands from the ``nephilex.commands`` entry-point group."""

from __future__ import annotations

import warnings

import typer

from nephilex.core.plugin import plugin_entry_points
from nephilex.plugins.signing import verify_plugin_entry

#: Entry-point group that add-on packages use to contribute CLI commands.
COMMANDS_GROUP = "nephilex.commands"


def load_plugin_commands(app: typer.Typer) -> None:
    """Let installed add-on packages contribute CLI commands.

    Each entry point in the ``nephilex.commands`` group is a callable that receives
    the Typer ``app`` and registers one or more commands on it. This is how
    optional/commercial add-ons (for example the Kubernetes assessment package)
    add a subcommand without the core shipping or depending on their code. A
    failing plugin is skipped with a warning; it never breaks the core CLI.

    Command plugins go through the same allowlist/blocklist/pins as scanner
    plugins (NEPHILEX_PLUGIN_ALLOWLIST and friends, see nephilex.plugins.signing).
    """
    try:
        eps = plugin_entry_points(COMMANDS_GROUP)
    except Exception:  # pragma: no cover - environment dependent
        return
    for ep in eps:
        if not verify_plugin_entry(ep):
            warnings.warn(
                f"Blocked Nephilex command plugin {ep.name!r} "
                "(not allowed by NEPHILEX_PLUGIN_* settings)",
                stacklevel=2,
            )
            continue
        try:
            ep.load()(app)
        except Exception as exc:  # pragma: no cover - defensive
            warnings.warn(
                f"Failed to load Nephilex command plugin {ep.name!r}: {exc}", stacklevel=2
            )
