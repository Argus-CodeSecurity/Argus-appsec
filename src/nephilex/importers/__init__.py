"""Import results from other security tools into Nephilex.

Only SARIF 2.1.0 is supported. Imported results become ordinary
:class:`~nephilex.core.models.Finding` objects in a normal
:class:`~nephilex.core.models.ScanResult`, so baselines, allowlists, policy and
every reporter apply to them unchanged. See ``docs/importing.md``.
"""

from __future__ import annotations

from nephilex.importers.merge import DEDUPE_WINDOW, merge_findings
from nephilex.importers.pipeline import import_result, merge_into, process_imported
from nephilex.importers.sarif import (
    MAX_RESULTS,
    SarifImport,
    SarifImportError,
    import_sarif,
    load_sarif,
    parse_sarif,
)

__all__ = [
    "DEDUPE_WINDOW",
    "MAX_RESULTS",
    "SarifImport",
    "SarifImportError",
    "import_result",
    "import_sarif",
    "load_sarif",
    "merge_findings",
    "merge_into",
    "parse_sarif",
    "process_imported",
]
