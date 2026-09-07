"""Business-logic and workflow abuse pattern detection (spec §6)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from argus.core.models import Confidence, Finding, Likelihood, Location, Remediation, Severity
from argus.core.plugin import Scanner, ScannerContext, scanner

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


def _f(rule: str, path: str, line: int, snippet: str, title: str, why: str, sev: Severity) -> Finding:
    return Finding(
        id=f"business-logic:{rule}:{path}:{line}",
        rule_id=rule,
        scanner="business-logic",
        title=title,
        description=why,
        location=Location(path=path, start_line=line, snippet=snippet[:200]),
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


@scanner
class BusinessLogicScanner(Scanner):
    name = "business-logic"
    category = "logic"
    description = "Detects workflow abuse patterns: price/qty manipulation, coupon abuse, state bypass."
    file_local = True

    def applies_to(self, project) -> bool:
        return any(f.suffix in (".py", ".js", ".ts", ".java", ".php", ".rb") for f in project.files())

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        for f in ctx.project.files():
            if f.suffix not in (".py", ".js", ".ts", ".java", ".php", ".rb"):
                continue
            lines = f.text().splitlines()
            for i, line in enumerate(lines, 1):
                if _PRICE_MUTATION.search(line):
                    yield _f("logic.price-from-request", f.rel_path, i, line,
                             "Price derived from user-controlled input",
                             "Client-controlled pricing enables purchase at arbitrary amounts.",
                             Severity.HIGH)
                if _QUANTITY_MUTATION.search(line):
                    yield _f("logic.quantity-from-request", f.rel_path, i, line,
                             "Quantity derived from user-controlled input",
                             "Attackers can manipulate order quantities or inventory.",
                             Severity.MEDIUM)
                if _COUPON_BYPASS.search(line):
                    yield _f("logic.coupon-abuse", f.rel_path, i, line,
                             "Suspicious coupon/discount logic",
                             "Discount validation may be bypassed.",
                             Severity.HIGH)
                window = "\n".join(lines[max(0, i - 5):i])
                if _STATE_SKIP.search(line) and not re.search(r"auth|permission|role|owner", window, re.I):
                    yield _f("logic.state-transition", f.rel_path, i, line,
                             "State transition without obvious authorization guard",
                             "Workflow state may be advanced without proper checks.",
                             Severity.MEDIUM)
                if _ADMIN_NO_GUARD.search(line):
                    ctx_window = "\n".join(lines[i:min(len(lines), i + 8)])
                    if not re.search(r"admin|superuser|permission|role", ctx_window, re.I):
                        yield _f("logic.admin-function", f.rel_path, i, line,
                                 "Sensitive administrative function",
                                 "Verify strong authorization before administrative actions.",
                                 Severity.HIGH)
                if _RACE_HINT.search("\n".join(lines[max(0, i - 1):min(len(lines), i + 3)])):
                    yield _f("logic.race-hint", f.rel_path, i, line,
                             "Possible check-then-act race",
                             "Concurrent requests may bypass validation (TOCTOU).",
                             Severity.LOW)
