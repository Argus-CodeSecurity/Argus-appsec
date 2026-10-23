"""JSON and CSV reporters.

JSON is the canonical machine-readable format, a faithful serialization of the
whole ``ScanResult``, suitable for a dashboard, diffing across scans, or feeding
another tool. CSV is a flat, one-row-per-finding view for spreadsheets.
"""

from __future__ import annotations

import csv
import io

from nephilex.core.models import ScanResult
from nephilex.core.plugin import Reporter, reporter


@reporter
class JSONReporter(Reporter):
    name = "json"
    extension = "json"
    description = "Full machine-readable scan result."

    def render(self, result: ScanResult) -> str:
        # pydantic handles nested models, enums, and datetimes cleanly.
        return result.model_dump_json(indent=2)


@reporter
class CSVReporter(Reporter):
    name = "csv"
    extension = "csv"
    description = "Flat one-row-per-finding export for spreadsheets."

    _COLUMNS = [
        "id",
        "scanner",
        "rule_id",
        "severity",
        "confidence",
        "likelihood",
        "risk_score",
        "title",
        "path",
        "line",
        "cwe",
        "owasp",
        "remediation",
        "docs_url",
    ]

    def render(self, result: ScanResult) -> str:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=self._COLUMNS)
        writer.writeheader()
        for f in result.sorted_findings():
            writer.writerow(
                {
                    "id": f.id,
                    "scanner": f.scanner,
                    "rule_id": f.rule_id,
                    "severity": f.severity.label,
                    "confidence": f.confidence.label,
                    "likelihood": f.likelihood.label,
                    "risk_score": f.risk_score(),
                    "title": f.title,
                    "path": f.location.path,
                    "line": f.location.start_line or "",
                    "cwe": ";".join(f.cwe),
                    "owasp": ";".join(f.owasp),
                    "remediation": f.remediation.summary if f.remediation else "",
                    "docs_url": f.docs_url,
                }
            )
        return buf.getvalue()
