"""`argus learn`: turn the findings in your own code into security lessons.

Security training on a generic vulnerable app is abstract; the same lesson taught
on the code you just wrote sticks. This reuses the reasoning Argus already
produces (why, attacker path, exploit walkthrough, fix) and re-frames each finding
as a short, hands-on lesson.
"""

from __future__ import annotations

from rich.markup import escape

from argus.core.models import ScanResult, Severity

_SEV_COLOR = {
    Severity.CRITICAL: "red", Severity.HIGH: "dark_orange", Severity.MEDIUM: "yellow",
    Severity.LOW: "green", Severity.INFO: "dim",
}


def render_lessons(result: ScanResult) -> str:
    findings = result.sorted_findings()
    if not findings:
        return ("No findings to learn from, either the scanned code is clean or "
                "nothing matched. Try `argus learn` on a project with known issues.")

    out = [f"[bold]Argus learn[/bold]  {len(findings)} lesson(s) from your code", ""]
    for i, f in enumerate(findings, 1):
        color = _SEV_COLOR.get(f.severity, "white")
        # Every value comes from scanned code or a model: escape it so text
        # such as "[/bold]" or "[link=...]" cannot break or restyle the output.
        out.append(f"[bold]Lesson {i}: {escape(f.title)}[/bold]  "
                   f"[{color}]{escape(f.severity.label.upper())}[/{color}]")
        out.append(f"  Where: {escape(f.location.as_ref())}")
        if f.location.snippet:
            out.append(f"    [dim]{escape(f.location.snippet.strip()[:200])}[/dim]")
        if f.why_vulnerable:
            out.append(f"  Why it matters: {escape(f.why_vulnerable)}")
        if f.attacker_perspective:
            out.append(f"  How it is exploited: {escape(f.attacker_perspective)}")
        if f.exploit and getattr(f.exploit, "exploit_walkthrough", None):
            out.append(f"  Walkthrough: {escape(f.exploit.exploit_walkthrough)}")
        if f.remediation:
            fix = f.remediation.guidance or f.remediation.summary
            out.append(f"  How to fix it: {escape(fix)}")
        out.append(f"  Learn more: {escape(str(f.docs_url))}")
        out.append("")
    out.append("[dim]Fix these, re-run `argus learn`, and watch the lessons "
               "disappear.[/dim]")
    return "\n".join(out)
