"""Entry point of the ``argus`` console script.

The CLI is assembled in :mod:`argus.cli.app` from the command modules in
:mod:`argus.cli.commands`. This module exists so the console-script target
``argus.cli.main:app`` and ``python -m argus.cli.main`` keep working.
"""

from __future__ import annotations

from argus.cli.app import app

__all__ = ["app"]


if __name__ == "__main__":  # pragma: no cover
    app()
