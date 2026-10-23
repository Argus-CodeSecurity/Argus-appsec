"""Fuzz the SARIF importer: untrusted JSON from other scanners and CI artifacts.

Bad input must be rejected with ``ImportFormatError`` (``SarifImportError`` is a
subclass). Any other exception, a hang, or a crash is a bug.

Run locally on Linux:  pip install atheris && python fuzz/fuzz_sarif.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import atheris

with atheris.instrument_imports():
    from nephilex.importers._safejson import ImportFormatError, loads_untrusted
    from nephilex.importers.sarif import parse_sarif

# An empty project root: locations resolve against it and any path that leaves
# it is dropped, so the harness never reads real files.
_ROOT = Path(tempfile.mkdtemp(prefix="nephilex-fuzz-"))


def TestOneInput(data: bytes) -> None:
    try:
        doc = loads_untrusted(data, source="<fuzz>")
        parse_sarif(doc, project_root=_ROOT, source="<fuzz>")
    except ImportFormatError:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
