"""Third-party CLI commands from the ``argus.commands`` entry-point group."""

from __future__ import annotations

import warnings
from importlib import metadata

import typer

from argus.plugins.signing import verify_plugin_entry

#: Entry-point group that add-on packages use to contribute CLI commands.
COMMANDS_GROUP = "argus.commands"


def load_plugin_commands(app: typer.Typer) -> None:
    """Let installed add-on packages contribute CLI commands.

    Each entry point in the ``argus.commands`` group is a callable that receives
    the Typer ``app`` and registers one or more commands on it. This is how
    optional/commercial add-ons (for example the Kubernetes assessment package)
    add a subcommand without the core shipping or depending on their code. A
    failing plugin is skipped with a warning; it never breaks the core CLI.

    Command plugins go through the same allowlist/blocklist/pins as scanner
    plugins (ARGUS_PLUGIN_ALLOWLIST and friends, see argus.plugins.signing).
    """
    try:
        eps = metadata.entry_points(group=COMMANDS_GROUP)
    except Exception:  # pragma: no cover - environment dependent
        return
    for ep in eps:
        if not verify_plugin_entry(ep):
            warnings.warn(
                f"Blocked Argus command plugin {ep.name!r} "
                "(not allowed by ARGUS_PLUGIN_* settings)",
                stacklevel=2,
            )
            continue
        try:
            ep.load()(app)
        except Exception as exc:  # pragma: no cover - defensive
            warnings.warn(f"Failed to load Argus command plugin {ep.name!r}: {exc}", stacklevel=2)
