#!/usr/bin/env python3
"""Held-out benchmark on real fix commits: Nephilex vs Bandit vs Semgrep.

    python benchmarks/heldout/run.py select --api-command "python gh_get.py"
    python benchmarks/heldout/run.py fetch            # download files listed in the manifest
    python benchmarks/heldout/run.py scan --bandit PATH --semgrep PATH
    python benchmarks/heldout/run.py score            # re-score cached tool output

``select`` applies the rule in ``selection.py`` and rewrites ``manifest.json``;
outside contributors reproducing the published numbers start at ``fetch``.
Methodology and caveats: ``docs/benchmarks.md``.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Same import shim as benchmarks/public/run.py: make ``benchmarks`` importable
# and keep this directory's module names from shadowing installed packages.
_here = str(Path(__file__).resolve().parent)
sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != Path(_here)]
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.heldout.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
