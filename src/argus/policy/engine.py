"""Deterministic security policy engine.

Policies are declared in ``.argus.yml`` under ``policies:`` and evaluated against
a :class:`~argus.core.models.ScanResult`. The engine is intentionally simple and
evidence-based: it matches finding attributes, never LLM output.

Example::

    policies:
      - id: block-critical
        when:
          severity: critical
        action: block
      - id: block-secrets
        when:
          scanner: secrets
        action: block
      - id: warn-root-container
        when:
          rule: iac.docker-user-root
        action: warn
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from argus.core.models import Finding, ScanResult, Severity


@dataclass
class PolicyViolation:
    policy_id: str
    action: str
    finding: Finding
    reason: str


@dataclass
class PolicyResult:
    violations: list[PolicyViolation] = field(default_factory=list)

    @property
    def blocked(self) -> list[PolicyViolation]:
        return [v for v in self.violations if v.action == "block"]

    @property
    def warned(self) -> list[PolicyViolation]:
        return [v for v in self.violations if v.action == "warn"]

    @property
    def passed(self) -> bool:
        return not self.blocked


def load_policies(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract policy rules from config dict."""
    raw = data.get("policies", [])
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for entry in raw:
        if isinstance(entry, dict) and entry.get("id") and entry.get("action"):
            out.append(entry)
    return out


def _matches(finding: Finding, when: dict[str, Any]) -> bool:
    if not when:
        return False
    for key, expected in when.items():
        if expected is None:
            continue
        if key == "severity":
            floor = Severity.parse(str(expected))
            if finding.severity < floor:
                return False
        elif key == "scanner":
            if finding.scanner != str(expected):
                return False
        elif key == "rule":
            target = str(expected)
            if not (finding.rule_id == target or finding.rule_id.endswith("." + target)
                    or finding.rule_id.split(".")[-1] == target):
                return False
        elif key == "tag":
            if str(expected) not in finding.tags:
                return False
        elif key == "cwe":
            if str(expected) not in finding.cwe:
                return False
        else:
            return False
    return True


def evaluate(result: ScanResult, policies: list[dict[str, Any]]) -> PolicyResult:
    """Evaluate ``policies`` against ``result.findings``."""
    violations: list[PolicyViolation] = []
    for policy in policies:
        pid = str(policy["id"])
        action = str(policy.get("action", "warn")).lower()
        when = policy.get("when") or {}
        if not isinstance(when, dict):
            continue
        for finding in result.findings:
            if _matches(finding, when):
                violations.append(PolicyViolation(
                    policy_id=pid,
                    action=action,
                    finding=finding,
                    reason=f"Policy '{pid}' matched {finding.rule_id} "
                           f"({finding.location.as_ref()})",
                ))
    return PolicyResult(violations=violations)
