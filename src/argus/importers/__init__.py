"""Import results from other security tools into Argus.

Only SARIF 2.1.0 is supported. Imported results become ordinary
:class:`~argus.core.models.Finding` objects in a normal
:class:`~argus.core.models.ScanResult`, so baselines, allowlists, policy and
every reporter apply to them unchanged. See ``docs/importing.md``.
"""

from __future__ import annotations

from argus.importers.merge import DEDUPE_WINDOW, merge_findings
from argus.importers.pipeline import import_result, merge_into, process_imported
from argus.importers.sarif import (
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
