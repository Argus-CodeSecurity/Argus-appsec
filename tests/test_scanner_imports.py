"""Import hygiene of the scanner package.

``argus.inventory`` imports ``argus.scanners.dependencies``, which loads the
whole scanner package; the dependency-diff scanner used to import
``argus.inventory`` back at module level, so a fresh ``import argus.inventory``
failed with a circular import. Scanner modules also should not load the HTTP
helpers they only need while probing.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SRC = str(Path(__file__).resolve().parents[1] / "src")


def _fresh(code: str) -> subprocess.CompletedProcess[str]:
    prelude = f"import sys; sys.path.insert(0, {SRC!r}); "
    return subprocess.run(
        [sys.executable, "-I", "-c", prelude + code], capture_output=True, text=True, timeout=120
    )


def test_fresh_import_of_inventory_has_no_cycle():
    proc = _fresh("import argus.inventory; import argus.scanners.dependency_diff")
    assert proc.returncode == 0, proc.stderr


def test_registering_scanners_does_not_load_the_dast_http_client():
    proc = _fresh(
        "import argus.scanners, sys; "
        "print('argus.dynamic.posture' in sys.modules, 'argus.inventory.dependency_diff' in sys.modules)"
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == ["False", "False"]


def test_lazy_wrappers_keep_the_scanner_set():
    proc = _fresh(
        "import argus.scanners; from argus.core.plugin import registry; "
        "print(' '.join(sorted(registry.scanners())))"
    )
    names = set(proc.stdout.split())
    assert {"dast", "dependency-diff", "supply-chain", "ast-python", "patterns"} <= names
