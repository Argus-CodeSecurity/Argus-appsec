"""GitLab SAST report reporter.

Emits the GitLab Secure "SAST report" JSON (schema 15.x) that GitLab ingests
via a ``sast`` report artifact, surfacing findings in the merge-request security
widget and the Vulnerability Report. This opens the GitLab ecosystem with a
single reporter, no core changes, the same way the SARIF reporter serves
GitHub.
"""

from __future__ import annotations

import json

from argus import __version__
from argus.core.models import ScanResult, Severity
from argus.core.plugin import Reporter, reporter

# Argus severity -> GitLab severity vocabulary.
_SEVERITY = {
    Severity.INFO: "Info",
    Severity.LOW: "Low",
    Severity.MEDIUM: "Medium",
    Severity.HIGH: "High",
    Severity.CRITICAL: "Critical",
}
# Argus confidence -> GitLab confidence vocabulary.
_CONFIDENCE = {"low": "Low", "medium": "Medium", "high": "High"}

_SCANNER = {"id": "argus", "name": "Argus",
            "vendor": {"name": "Argus"}, "version": __version__}


@reporter
class GitLabReporter(Reporter):
    name = "gitlab"
    extension = "json"
    description = "GitLab SAST report (schema 15.x) for GitLab CI security widgets."

    def render(self, result: ScanResult) -> str:
        doc = {
            "version": "15.0.6",
            "scan": {
                "scanner": _SCANNER,
                "analyzer": _SCANNER,
                "type": "sast",
                "start_time": self._ts(result.started_at),
                "end_time": self._ts(result.finished_at or result.started_at),
                "status": "success",
            },
            "vulnerabilities": self._vulns(result),
        }
        return json.dumps(doc, indent=2)

    def _vulns(self, result: ScanResult) -> list[dict]:
        """One entry per finding with a unique ``id``.

        The fingerprint is content-based, so identical lines in one file share
        it; GitLab requires unique ids. Repeats get an occurrence suffix
        ("<fingerprint>#2"), numbered in line order, while the first keeps the
        plain fingerprint so existing ids stay stable.
        """
        seen: dict[str, int] = {}
        out: list[dict] = []
        ordered = sorted(result.sorted_findings(),
                         key=lambda f: (f.fingerprint(), f.location.start_line or 0))
        ids: dict[int, str] = {}
        for f in ordered:
            fp = f.fingerprint()
            seen[fp] = seen.get(fp, 0) + 1
            ids[id(f)] = fp if seen[fp] == 1 else f"{fp}#{seen[fp]}"
        for f in result.sorted_findings():
            vuln = self._vuln(f)
            vuln["id"] = ids[id(f)]
            out.append(vuln)
        return out

    @staticmethod
    def _ts(dt) -> str:
        # GitLab wants ISO 8601 without timezone suffix, second precision.
        return dt.strftime("%Y-%m-%dT%H:%M:%S")

    def _vuln(self, f) -> dict:
        vuln: dict = {
            "id": f.fingerprint(),
            "category": "sast",
            "name": f.title,
            "message": f.title,
            "description": f.why_vulnerable or f.description,
            "severity": _SEVERITY[f.severity],
            "confidence": _CONFIDENCE.get(f.confidence.label.lower(), "Unknown"),
            "scanner": {"id": "argus", "name": "Argus"},
            "location": {"file": f.location.path},
            "identifiers": self._identifiers(f),
        }
        if f.location.start_line:
            vuln["location"]["start_line"] = f.location.start_line
        if f.location.end_line:
            vuln["location"]["end_line"] = f.location.end_line
        if f.remediation:
            vuln["solution"] = f.remediation.summary
        return vuln

    def _identifiers(self, f) -> list[dict]:
        ids: list[dict] = []
        for cwe in f.cwe:
            num = cwe.replace("CWE-", "")
            ids.append({
                "type": "cwe", "name": cwe, "value": num,
                "url": f"https://cwe.mitre.org/data/definitions/{num}.html",
            })
        # GitLab requires at least one identifier; fall back to the rule id.
        if not ids:
            ids.append({"type": "argus_rule", "name": f.rule_id, "value": f.rule_id})
        return ids
