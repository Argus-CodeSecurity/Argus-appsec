#!/usr/bin/env python3
"""Public labeled-dataset accuracy benchmark: Argus vs Bandit vs Semgrep.

    python benchmarks/public/run.py                                   # everything
    python benchmarks/public/run.py --dataset owasp-python --tools argus,bandit,semgrep
    python benchmarks/public/run.py --offline                         # re-score only

Datasets are pinned to exact commits (``datasets.py``) and downloaded into
``benchmarks/.corpora/`` (git-ignored). Results go to
``benchmarks/results/public/<dataset>.json`` plus a generated ``SUMMARY.md``.
Methodology and caveats: ``docs/benchmarks.md``.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make ``benchmarks.public`` importable when run as a script from any cwd, and
# drop this directory from the path so its module names (tools, report, ...)
# cannot shadow installed packages.
_here = str(Path(__file__).resolve().parent)
sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != Path(_here)]
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.public.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
