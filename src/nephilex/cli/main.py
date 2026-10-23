"""Entry point of the ``nephilex`` console script.

The CLI is assembled in :mod:`nephilex.cli.app` from the command modules in
:mod:`nephilex.cli.commands`. This module exists so the console-script target
``nephilex.cli.main:app`` and ``python -m nephilex.cli.main`` keep working.
"""

from __future__ import annotations

from nephilex.cli.app import app

__all__ = ["app"]


if __name__ == "__main__":  # pragma: no cover
    app()
