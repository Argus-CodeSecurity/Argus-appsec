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

Policies are validated before use. A policy that cannot do what it says (an
unknown ``when`` key, an unknown action, a missing id) is a :class:`PolicyError`
rather than a rule that silently never matches, because a policy gate that
quietly ignores a typo passes everything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from argus.core.config import ConfigError
from argus.core.models import Finding, ScanResult, Severity

#: Recognized ``action`` values.
ACTIONS = ("block", "warn")
#: Recognized ``when`` keys. All given keys must match (logical AND).
WHEN_KEYS = ("severity", "scanner", "rule", "tag", "cwe")


class PolicyError(ConfigError):
    """A policy definition is invalid."""


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


def _validate(entry: Any, index: int, seen: set[str]) -> dict[str, Any]:
    where = f"policies[{index}]"
    if not isinstance(entry, dict):
        raise PolicyError(f"{where}: expected a mapping, got {type(entry).__name__}")
    pid = entry.get("id")
    if not isinstance(pid, (str, int)) or isinstance(pid, bool) or not str(pid).strip():
        raise PolicyError(f"{where}: 'id' is required")
    pid = str(pid).strip()
    where = f"policy {pid!r}"
    if pid in seen:
        raise PolicyError(f"{where}: duplicate id")
    seen.add(pid)

    unknown_fields = set(entry) - {"id", "when", "action", "description"}
    if unknown_fields:
        raise PolicyError(f"{where}: unknown field(s): {', '.join(sorted(unknown_fields))}")

    action = entry.get("action")
    if not isinstance(action, str) or action.strip().lower() not in ACTIONS:
        raise PolicyError(
            f"{where}: action must be one of {', '.join(ACTIONS)}, got {action!r}"
        )

    when = entry.get("when")
    if not isinstance(when, dict) or not when:
        raise PolicyError(f"{where}: 'when' must be a non-empty mapping")
    for key, value in when.items():
        if key not in WHEN_KEYS:
            raise PolicyError(
                f"{where}: unknown condition {key!r} "
                f"(supported: {', '.join(WHEN_KEYS)})"
            )
        if value is None or isinstance(value, (dict, list, bool)) or not str(value).strip():
            raise PolicyError(f"{where}: condition {key!r} needs a single value")
        if key == "severity":
            try:
                Severity.parse(str(value))
            except ValueError as exc:
                raise PolicyError(f"{where}: {exc}") from exc

    return {**entry, "id": pid, "action": action.strip().lower(), "when": dict(when)}


def load_policies(data: dict[str, Any] | list[Any] | None) -> list[dict[str, Any]]:
    """Validate and normalize policy definitions.

    Accepts either the ``policies`` list itself or a whole config mapping that
    contains one. Raises :class:`PolicyError` on any invalid entry.
    """
    raw: Any = data.get("policies", []) if isinstance(data, dict) else data
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise PolicyError(f"policies: expected a list, got {type(raw).__name__}")
    seen: set[str] = set()
    return [_validate(entry, i, seen) for i, entry in enumerate(raw)]


def _matches(finding: Finding, when: dict[str, Any]) -> bool:
    for key, expected in when.items():
        if key == "severity":
            if finding.severity < Severity.parse(str(expected)):
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
        else:  # unreachable after validation; never treat it as a match
            raise PolicyError(f"unknown policy condition {key!r}")
    return True


def evaluate(result: ScanResult, policies: list[dict[str, Any]]) -> PolicyResult:
    """Evaluate ``policies`` against ``result.findings``.

    The policies are validated first (see :func:`load_policies`).
    """
    violations: list[PolicyViolation] = []
    for policy in load_policies(policies):
        pid = policy["id"]
        action = policy["action"]
        for finding in result.findings:
            if _matches(finding, policy["when"]):
                violations.append(PolicyViolation(
                    policy_id=pid,
                    action=action,
                    finding=finding,
                    reason=f"Policy '{pid}' matched {finding.rule_id} "
                           f"({finding.location.as_ref()})",
                ))
    return PolicyResult(violations=violations)
