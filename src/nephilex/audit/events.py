"""Builders for the audit events Nephilex records, and the switch that turns them off."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from nephilex.audit.log import AppendResult, AuditEvent, append_events

if TYPE_CHECKING:
    from nephilex.core.models import Finding

#: Setting this environment variable to 0/off/false/no disables the audit log,
#: for throwaway runs that should leave the tree untouched.
ENV_SWITCH = "NEPHILEX_AUDIT_LOG"


def audit_enabled(config: Any = None) -> bool:
    """Whether audit events should be written (config ``audit_log`` and the env switch)."""
    if os.environ.get(ENV_SWITCH, "").strip().lower() in ("0", "off", "false", "no"):
        return False
    return bool(getattr(config, "audit_log", True)) if config is not None else True


def suppression_matched(kind: str, finding: Finding, reason: str, **details: Any) -> AuditEvent:
    """A finding was suppressed (or accepted) by ``kind``; recorded once per content."""
    if finding.location.start_line is not None:
        details.setdefault("line", finding.location.start_line)
    details.setdefault("severity", finding.severity.name.lower())
    return AuditEvent(
        action="suppression.matched",
        kind=kind,
        fingerprint=finding.fingerprint(),
        rule=finding.rule_id,
        path=finding.location.path,
        reason=reason,
        details=details,
        once=True,
    )


def suppression_added(
    kind: str,
    selector: str,
    reason: str,
    *,
    rule: str | None = None,
    path: str | None = None,
    **details: Any,
) -> AuditEvent:
    """A suppression definition was first seen; recorded once per content."""
    details["selector"] = selector
    return AuditEvent(
        action="suppression.added",
        kind=kind,
        rule=rule,
        path=path,
        reason=reason,
        details=details,
        once=True,
    )


def record_baseline(
    root: str | Path,
    baseline: str | Path,
    suppressed: list[Finding],
    *,
    config: Any = None,
) -> AppendResult:
    """Record a baseline being applied and each finding it hid.

    For callers that filter findings through a baseline report (``--baseline``):
    one ``suppression.added`` per distinct baseline file content and one
    ``suppression.matched`` per hidden finding, both de-duplicated. With
    ``config``, its ``audit_log`` setting is honoured as well as the
    environment switch. Deciding whether the project is trusted is the
    caller's job.
    """
    if not audit_enabled(config):
        return AppendResult()
    base = Path(baseline)
    try:
        digest = hashlib.sha256(base.read_bytes()).hexdigest()[:16]
    except OSError:
        digest = "unreadable"
    reason = f"present in baseline {base.name}"
    events = [suppression_added("baseline", f"baseline sha256:{digest}", reason, file=base.name)]
    events += [suppression_matched("baseline", f, reason) for f in suppressed]
    return append_events(root, events)
