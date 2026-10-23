"""Fuzz the project context parser (``.nephilex/context.yml``).

The context file declares sanitizers and trusted sources for the taint engines,
so a malformed one must fail with ``ConfigError`` rather than be half-applied.
Any other exception, a hang, or a crash is a bug.

Run locally on Linux:  pip install atheris && python fuzz/fuzz_context.py
"""

from __future__ import annotations

import contextlib
import sys

import atheris

with atheris.instrument_imports():
    from nephilex.context.schema import parse_context
    from nephilex.core.config import ConfigError


def TestOneInput(data: bytes) -> None:
    text = data.decode("utf-8", "replace")
    with contextlib.suppress(ConfigError):
        parse_context(text, source="<fuzz>")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
