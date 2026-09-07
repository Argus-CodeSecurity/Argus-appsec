"""Markdown reporter.

A human-readable report suitable for PR comments, issue bodies, or committing into
a repo. Leads with a summary table, then one section per finding including the
attack simulation and any generated patch.
"""

from __future__ import annotations

from argus.core.models import ScanResult, Severity
from argus.core.plugin import Reporter, reporter

_SEV_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


def _fence(content: str, lang: str = "") -> list[str]:
    """Wrap untrusted content in a code fence that it cannot break out of.

    Scanned source (snippets, diffs) can itself contain backtick runs; we pick a
    fence longer than the longest run inside so the block stays intact when the
    Markdown is rendered (e.g. as a PR comment).
    """
    longest = run = 0
    for ch in content:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    ticks = "`" * max(3, longest + 1)
    return [f"{ticks}{lang}", content, ticks]


def _inline(text: str) -> str:
    """Neutralize characters that would break inline code spans, table cells, or
    the single-line structure of a Markdown bullet."""
    return (
        text.replace("\\", "\\\\")
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("`", "'")
        .replace("|", "\\|")
    )


@reporter
class MarkdownReporter(Reporter):
    name = "markdown"
    extension = "md"
    description = "Human-readable Markdown report for PRs and issues."

    def render(self, result: ScanResult) -> str:
        out: list[str] = []
        summary = result.project_summary
        out.append(f"# Argus Security Report, {summary.get('name', result.target)}")
        out.append("")
        out.append(self._overview(result))
        out.append("")
        out.append(self._severity_table(result))
        out.append("")

        findings = result.sorted_findings()
        if not findings:
            out.append("No findings at or above the configured severity threshold.")
            return "\n".join(out)

        out.append("## Findings")
        out.append("")
        for i, f in enumerate(findings, start=1):
            out.append(self._finding(i, f))
            out.append("")
        return "\n".join(out)

    def _overview(self, result: ScanResult) -> str:
        s = result.project_summary
        langs = ", ".join(f"{k} ({v})" for k, v in (s.get("languages") or {}).items())
        arch = s.get("architecture", {}) or {}
        lines = [
            f"**Target:** `{result.target}`  ",
            f"**Scanned:** {result.started_at:%Y-%m-%d %H:%M UTC}  ",
            f"**Argus:** v{result.argus_version}  ",
            f"**Aggregate risk:** {result.aggregate_risk()} / 100  ",
            f"**Files:** {s.get('file_count', 'n/a')}  ",
            f"**Languages:** {langs or 'n/a'}  ",
        ]
        if s.get("frameworks"):
            lines.append(f"**Frameworks:** {', '.join(s['frameworks'])}  ")
        if arch.get("apis"):
            lines.append(f"**APIs:** {', '.join(arch['apis'])}  ")
        if arch.get("datastores"):
            lines.append(f"**Datastores:** {', '.join(arch['datastores'])}  ")
        if result.errors:
            lines.append(f"**Scan warnings:** {len(result.errors)}  ")
        return "\n".join(lines)

    def _severity_table(self, result: ScanResult) -> str:
        counts = result.counts_by_severity()
        header = "| " + " | ".join(counts.keys()) + " | Total |"
        divider = "|" + "|".join(["---"] * (len(counts) + 1)) + "|"
        row = "| " + " | ".join(str(v) for v in counts.values()) + \
              f" | {sum(counts.values())} |"
        return "\n".join(["## Summary", "", header, divider, row])

    def _finding(self, index: int, f) -> str:
        label = _SEV_LABEL.get(f.severity, f.severity.label)
        lines = [
            f"### {index}. [{label}] {_inline(f.title)}",
            "",
            f"- **Severity:** {f.severity.label} "
            f"(risk {f.risk_score()}/100) · **Confidence:** {f.confidence.label} · "
            f"**Likelihood:** {f.likelihood.label}",
            f"- **Location:** `{_inline(f.location.as_ref())}`",
            f"- **Scanner/Rule:** `{_inline(f.scanner)}` / `{_inline(f.rule_id)}`",
        ]
        if f.cwe or f.owasp:
            lines.append(f"- **Mapping:** {_inline(', '.join(f.cwe + f.owasp))}")
        lines.append("")
        if f.location.snippet:
            lines.extend(_fence(f.location.snippet))
            lines.append("")
        if f.why_vulnerable:
            lines.append(f"**Why it's a vulnerability:** {f.why_vulnerable}")
            lines.append("")
        if f.attacker_perspective:
            lines.append(f"**How an attacker exploits it:** {f.attacker_perspective}")
            lines.append("")
        if f.business_impact:
            lines.append(f"**Business impact:** {f.business_impact}")
            lines.append("")

        if f.exploit:
            lines.append(self._exploit(f.exploit))

        if f.remediation:
            lines.append("**Remediation:** " + f.remediation.summary)
            if f.remediation.guidance and f.remediation.guidance != f.remediation.summary:
                lines.append("")
                lines.append(f.remediation.guidance)
            if f.remediation.patch:
                status = "verified" if f.remediation.verified else "proposed"
                lines.append("")
                lines.append(f"**Suggested patch ({status}):**")
                lines.extend(_fence(f.remediation.patch.rstrip(), "diff"))
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _exploit(ex) -> str:
        lines = ["<details><summary>Attack simulation</summary>", ""]
        rows = [
            ("Discovery", ex.discovery),
            ("Walkthrough", ex.exploit_walkthrough),
            ("Data at risk", ex.data_at_risk),
            ("Business impact", ex.business_impact),
            ("How the fix blocks it", ex.fix_blocks_attack),
            ("Before / after", ex.before_after),
        ]
        for label, value in rows:
            if value:
                lines.append(f"- **{label}:** {_inline(value)}")
        lines.append("")
        lines.append("_Simulation generated in an isolated context; no live target "
                     "was contacted._")
        lines.append("</details>")
        lines.append("")
        return "\n".join(lines)
