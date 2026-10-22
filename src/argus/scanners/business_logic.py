"""Business-logic and workflow abuse pattern detection (spec §6)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from argus.core.models import Confidence, Finding, Likelihood, Location, Remediation, Severity
from argus.core.plugin import Scanner, ScannerContext, scanner
from argus.scanners._text import MAX_SCAN_LINE, match_columns

_PRICE_MUTATION = re.compile(
    r"(?:price|amount|total|cost|fee)\s*[=:]\s*(?:req\.|request\.|params\.|body\.|input\.)",
    re.IGNORECASE,
)
_QUANTITY_MUTATION = re.compile(
    r"(?:quantity|qty|count|units?)\s*[=:]\s*(?:req\.|request\.|params\.|body\.)",
    re.IGNORECASE,
)
_COUPON_BYPASS = re.compile(
    r"(?:coupon|discount|promo)[^;\n]{0,80}(?:100|999999|true\s*;\s*return\s*true)",
    re.IGNORECASE,
)
_STATE_SKIP = re.compile(
    r"(?:status|state)\s*=\s*['\"]?(?:approved|paid|completed|shipped)['\"]?",
    re.IGNORECASE,
)
_ADMIN_NO_GUARD = re.compile(
    r"def\s+(?:admin|delete_user|grant_role|impersonate)\w*\(",
    re.IGNORECASE,
)
_RACE_HINT = re.compile(
    r"if\s+[^:\n]+:\s*\n\s+(?:await\s+)?(?:update|delete|transfer|charge)",
    re.IGNORECASE,
)


#: ``(start_column, end_column, end_line)`` of a match; see :func:`_f`.
_Span = tuple[int, int, int]


def _line_span(m: re.Match[str] | None, line: int) -> _Span | None:
    if m is None:
        return None
    start, end = match_columns(m)
    return start, end, line


def _f(
    rule: str,
    path: str,
    line: int,
    snippet: str,
    title: str,
    why: str,
    sev: Severity,
    span: _Span | None = None,
) -> Finding:
    return Finding(
        id=f"business-logic:{rule}:{path}:{line}",
        rule_id=rule,
        scanner="business-logic",
        title=title,
        description=why,
        location=Location(
            path=path,
            start_line=line,
            end_line=span[2] if span else None,
            start_column=span[0] if span else None,
            end_column=span[1] if span else None,
            snippet=snippet[:200],
        ),
        severity=sev,
        confidence=Confidence.MEDIUM,
        likelihood=Likelihood.POSSIBLE,
        cwe=["CWE-840"],
        owasp=["A04:2021-Insecure Design"],
        why_vulnerable=why,
        remediation=Remediation(
            summary="Validate workflow transitions server-side with authorization checks.",
            guidance="Never trust client-supplied price, quantity, or state fields.",
        ),
        tags=["business-logic", "workflow"],
        metadata={"verification": "detected"},
    )


def _multiline_span(m: re.Match[str], text: str, first_len: int, line: int) -> _Span | None:
    """Span of a match in ``text`` (lines joined from ``line`` on), if it starts on ``line``."""
    if m.start() >= first_len:
        return None  # the match starts on a later line than the one reported
    end_line = line + text.count("\n", 0, m.end())
    line_start = text.rfind("\n", 0, m.end()) + 1
    return m.start() + 1, m.end() - line_start + 1, end_line


@scanner
class BusinessLogicScanner(Scanner):
    name = "business-logic"
    category = "logic"
    description = (
        "Detects workflow abuse patterns: price/qty manipulation, coupon abuse, state bypass."
    )
    file_local = True

    def applies_to(self, project) -> bool:
        return any(
            f.suffix in (".py", ".js", ".ts", ".java", ".php", ".rb") for f in project.files()
        )

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        for f in ctx.project.files():
            if f.suffix not in (".py", ".js", ".ts", ".java", ".php", ".rb"):
                continue
            # Cut to the shared scan limit: _RACE_HINT runs on a window of these.
            lines = [ln[:MAX_SCAN_LINE] for ln in f.text().splitlines()]
            for i, line in enumerate(lines, 1):
                m = _PRICE_MUTATION.search(line)
                if m:
                    yield _f(
                        "logic.price-from-request",
                        f.rel_path,
                        i,
                        line,
                        "Price derived from user-controlled input",
                        "Client-controlled pricing enables purchase at arbitrary amounts.",
                        Severity.HIGH,
                        _line_span(m, i),
                    )
                m = _QUANTITY_MUTATION.search(line)
                if m:
                    yield _f(
                        "logic.quantity-from-request",
                        f.rel_path,
                        i,
                        line,
                        "Quantity derived from user-controlled input",
                        "Attackers can manipulate order quantities or inventory.",
                        Severity.MEDIUM,
                        _line_span(m, i),
                    )
                m = _COUPON_BYPASS.search(line)
                if m:
                    yield _f(
                        "logic.coupon-abuse",
                        f.rel_path,
                        i,
                        line,
                        "Suspicious coupon/discount logic",
                        "Discount validation may be bypassed.",
                        Severity.HIGH,
                        _line_span(m, i),
                    )
                window = "\n".join(lines[max(0, i - 5) : i])
                m = _STATE_SKIP.search(line)
                if m and not re.search(r"auth|permission|role|owner", window, re.I):
                    yield _f(
                        "logic.state-transition",
                        f.rel_path,
                        i,
                        line,
                        "State transition without obvious authorization guard",
                        "Workflow state may be advanced without proper checks.",
                        Severity.MEDIUM,
                        _line_span(m, i),
                    )
                m = _ADMIN_NO_GUARD.search(line)
                if m:
                    ctx_window = "\n".join(lines[i : min(len(lines), i + 8)])
                    if not re.search(r"admin|superuser|permission|role", ctx_window, re.I):
                        yield _f(
                            "logic.admin-function",
                            f.rel_path,
                            i,
                            line,
                            "Sensitive administrative function",
                            "Verify strong authorization before administrative actions.",
                            Severity.HIGH,
                            _line_span(m, i),
                        )
                race_text = "\n".join(lines[max(0, i - 1) : min(len(lines), i + 3)])
                m = _RACE_HINT.search(race_text)
                if m:
                    yield _f(
                        "logic.race-hint",
                        f.rel_path,
                        i,
                        line,
                        "Possible check-then-act race",
                        "Concurrent requests may bypass validation (TOCTOU).",
                        Severity.LOW,
                        _multiline_span(m, race_text, len(line), i),
                    )
