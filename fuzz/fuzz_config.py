"""Fuzz the repository config parser (``.nephilex.yml``).

The config is read from the working tree, from an explicit ``--config`` file,
or from a git ref with ``--config-from-ref``, so the parser must reject
anything malformed with ``ConfigError``. Any other exception, a hang, or a
crash is a bug.

Run locally on Linux:  pip install atheris && python fuzz/fuzz_config.py
"""

from __future__ import annotations

import contextlib
import sys

import atheris

with atheris.instrument_imports():
    from nephilex.core.config import Config, ConfigError


def TestOneInput(data: bytes) -> None:
    text = data.decode("utf-8", "replace")
    with contextlib.suppress(ConfigError):
        Config.from_yaml(text, source="<fuzz>")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
