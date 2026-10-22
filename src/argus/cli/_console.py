"""Terminal streams shared by every CLI module.

Human-facing output goes to ``console`` (stdout) and diagnostics to
``err_console`` (stderr). Machine-readable output (JSON, SARIF, CSV) never goes
through Rich; see :func:`argus.cli.output.write_stdout`.
"""

from __future__ import annotations

import contextlib
import sys

from rich.console import Console

# On Windows the legacy console defaults to a codepage that can't encode the
# Unicode Argus uses in reports/tables. Force UTF-8 on the streams when possible.
for _stream in (sys.stdout, sys.stderr):
    with contextlib.suppress(AttributeError, ValueError):
        _stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]

console = Console()
err_console = Console(stderr=True)
