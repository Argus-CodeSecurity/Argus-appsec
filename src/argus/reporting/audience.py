"""Audience views: the same findings, re-rendered for who is reading.

Argus already produces the reasoning (why, attacker path, business impact,
remediation, taxonomy). Re-presenting it costs nothing and meets three very
different readers where they are:

* **dev**      what to change, and where.
* **exec**     what it means for the business, no code.
* **auditor**  the CWE/OWASP taxonomy and coverage caveats, for evidence.

These return plain text (with light Rich markup) so the CLI can print them.
Every interpolated value is passed through ``rich.markup.escape``: titles,
paths and model prose can contain "[...]" that Rich would otherwise parse as
markup (and crash on a stray closing tag).
"""

from __future__ import annotations

from collections import Counter

from rich.markup import escape

from argus.core.models import ScanResult, Severity

AUDIENCES = ("dev", "exec", "auditor")

_SEV_COLOR = {
    Severity.CRITICAL: "red", Severity.HIGH: "dark_orange", Severity.MEDIUM: "yellow",
    Severity.LOW: "green", Severity.INFO: "dim",
}


def render_for_audience(result: ScanResult, audience: str) -> str:
    findings = result.sorted_findings()
    if audience == "exec":
        return _exec_view(result, findings)
    if audience == "auditor":
        return _auditor_view(result, findings)
    return _dev_view(result, findings)


def _counts_line(result: ScanResult) -> str:
    c = {str(k).lower(): v for k, v in result.counts_by_severity().items()}
    return (f"critical {c.get('critical', 0)}, high {c.get('high', 0)}, "
            f"medium {c.get('medium', 0)}, low {c.get('low', 0)}")


def _exec_view(result: ScanResult, findings) -> str:
    lines = [
        "[bold]Security summary[/bold]",
        f"Target: {escape(str(result.target))}",
        f"Risk score: [bold]{result.aggregate_risk()}[/bold]/100",
        f"Findings: {len(findings)}  ({_counts_line(result)})",
        "",
        "[bold]Top business risks[/bold]",
    ]
    top = sorted(findings, key=lambda f: f.risk_score(), reverse=True)[:5]
    if not top:
        lines.append("  None at the configured severity threshold.")
    for f in top:
        color = _SEV_COLOR.get(f.severity, "white")
        impact = f.business_impact or f.why_vulnerable or f.title
        lines.append(f"  [{color}]{escape(f.severity.label.upper())}[/{color}]  "
                     f"{escape(f.title)}")
        first = impact.splitlines()[0] if impact.strip() else impact
        lines.append(f"      {escape(first[:160])}")
    return "\n".join(lines)


def _auditor_view(result: ScanResult, findings) -> str:
    langs = escape(", ".join((result.project_summary or {}).get("languages", {}) or [])
                   or "the scanned files")
    by_cwe = Counter(c for f in findings for c in f.cwe)
    by_owasp = Counter(o for f in findings for o in f.owasp)
    lines = [
        "[bold]Audit view[/bold]",
        f"Target: {escape(str(result.target))}",
        f"Coverage: static analysis of {langs}; no runtime/DAST testing performed.",
        "",
        "[bold]By CWE[/bold]: "
        + escape(", ".join(f"{k} ({n})" for k, n in by_cwe.most_common()) or "none"),
        "[bold]By OWASP[/bold]: "
        + escape(", ".join(f"{k} ({n})" for k, n in by_owasp.most_common()) or "none"),
        "",
        "[bold]Findings[/bold]",
    ]
    for f in findings:
        tax = ", ".join(f.cwe + f.owasp) or "-"
        lines.append(f"  {f.severity.label.upper():8} {escape(f.rule_id)}  "
                     f"{escape('[' + tax + ']')}  {escape(f.location.as_ref())}")
    return "\n".join(lines)


def _dev_view(result: ScanResult, findings) -> str:
    lines = [f"[bold]Developer view[/bold]  ({len(findings)} finding(s))", ""]
    for f in findings:
        color = _SEV_COLOR.get(f.severity, "white")
        lines.append(f"[{color}]{escape(f.severity.label.upper())}[/{color}]  "
                     f"{escape(f.title)}  [dim]{escape(f.location.as_ref())}[/dim]")
        if f.why_vulnerable.strip():
            lines.append(f"    Why: {escape(f.why_vulnerable.splitlines()[0][:180])}")
        if f.remediation:
            lines.append(f"    Fix: {escape(f.remediation.summary)}")
        lines.append(f"    Docs: {escape(str(f.docs_url))}")
        lines.append("")
    return "\n".join(lines).rstrip()
