"""Tamper-evident audit trail of fixes and suppressions.

Nephilex appends a record to ``.nephilex/audit.log`` whenever it applies a fix,
opens a fix pull request, or sees a suppression (allowlist entry, exception,
inline ``nephilex-ignore`` comment, baseline) hide or accept a finding. Records
are hash-chained; ``nephilex audit verify`` detects edits, deletions and
reordering. See ``docs/audit-log.md``.
"""

from __future__ import annotations

from nephilex.audit.events import (
    ENV_SWITCH,
    audit_enabled,
    record_baseline,
    suppression_added,
    suppression_matched,
)
from nephilex.audit.log import (
    ACTIONS,
    AUDIT_PATH,
    FIELDS,
    GENESIS_HASH,
    SUPPRESSION_KINDS,
    AppendResult,
    AuditEvent,
    AuditLogError,
    VerifyResult,
    append_events,
    canonical,
    iter_records,
    record_hash,
    redact,
    resolve_actor,
    verify_log,
)

__all__ = [
    "ACTIONS",
    "AUDIT_PATH",
    "ENV_SWITCH",
    "FIELDS",
    "GENESIS_HASH",
    "SUPPRESSION_KINDS",
    "AppendResult",
    "AuditEvent",
    "AuditLogError",
    "VerifyResult",
    "append_events",
    "audit_enabled",
    "canonical",
    "iter_records",
    "record_baseline",
    "record_hash",
    "redact",
    "resolve_actor",
    "suppression_added",
    "suppression_matched",
    "verify_log",
]
