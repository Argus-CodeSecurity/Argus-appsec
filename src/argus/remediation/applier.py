"""Apply deterministic fixes to real files.

The patch agent proposes fixes against a stored *snippet* (which is stripped and
truncated). To actually change a file we must operate on its real content, so the
applier re-reads each file and rewrites the exact offending line, preserving
indentation and trailing content automatically, because the rewrite runs on the
real line.

Only findings whose rewrite verifies (the detection no longer fires on the fixed
line) are applied by default; unverified rewrites can be opted in. The applier
writes each file at most once, even when it fixes several findings in it.
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from argus.core.models import Finding
from argus.core.project import Project
from argus.remediation.rewrites import fix_line, verify_line_fixed

# Finding.metadata key set once the applier has actually written a fix for the
# finding to disk. Proposing a patch is not the same as applying it.
APPLIED_KEY = "remediation_applied"

# Split on real line breaks only, keeping each separator. str.splitlines() also
# breaks on \x0c, \x1c-\x1e, \x85, \u2028 and \u2029, which would shift line
# numbers and, once rejoined, rewrite those characters as newlines.
_LINE_BREAK = re.compile(r"(\r?\n)")


@dataclass
class AppliedFix:
    """One line-level change the applier made (or would make, when dry-run)."""

    path: str  # project-relative path
    rule_id: str
    line: int  # 1-indexed
    before: str
    after: str
    finding_id: str
    verified: bool
    # The finding's fingerprint, taken before the fix (it is keyed on the
    # offending code); used by the audit log.
    fingerprint: str = ""

    def unified_diff(self) -> str:
        return "".join(
            difflib.unified_diff(
                [self.before + "\n"],
                [self.after + "\n"],
                fromfile=f"a/{self.path}",
                tofile=f"b/{self.path}",
                lineterm="\n",
            )
        )


@dataclass
class ApplyReport:
    fixes: list[AppliedFix] = field(default_factory=list)
    changed_files: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # human-readable reasons
    dry_run: bool = False
    # Records appended to .argus/audit.log for these fixes, and any warning
    # (an unwritable log never fails a fix).
    audit_records: int = 0
    audit_warning: str | None = None

    @property
    def any_changes(self) -> bool:
        return bool(self.fixes)

    def summary(self) -> str:
        verb = "would fix" if self.dry_run else "fixed"
        return f"{verb} {len(self.fixes)} finding(s) across {len(self.changed_files)} file(s)"


def apply_fixes(
    project: Project,
    findings: list[Finding],
    *,
    include_unverified: bool = False,
    dry_run: bool = False,
    only_rules: set[str] | None = None,
    audit: bool = True,
) -> ApplyReport:
    """Apply deterministic fixes for the given findings to the project's files.

    When ``only_rules`` is given, only findings whose ``rule_id`` is in that set
    are fixed (used by ``argus fix --auto`` to apply just the auto-tier rules);
    others are left untouched.

    Each fix written to disk is recorded as a ``fix.applied`` event in
    ``.argus/audit.log`` unless ``audit`` is False or the log is switched off
    (``ARGUS_AUDIT_LOG=off``). Dry runs record nothing.
    """
    report = ApplyReport(dry_run=dry_run)

    # Group findings that have a line by file so each file is read/written once.
    # Whether a rule is actually fixable is decided per-line below via fix_line().
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        if f.location.start_line is None:
            continue
        if only_rules is not None and f.rule_id not in only_rules:
            continue
        by_file.setdefault(f.location.path, []).append(f)

    root = project.root.resolve()
    for rel_path, file_findings in by_file.items():
        abs_path = project.root / rel_path
        # Containment guard: the fix engine writes code back to disk, so a crafted
        # path (traversal, or a symlink pointing outside the tree) must never be
        # able to redirect that write beyond the project root.
        try:
            resolved = abs_path.resolve()
        except OSError:
            report.skipped.append(f"{rel_path}: path could not be resolved")
            continue
        if not resolved.is_relative_to(root) or abs_path.is_symlink():
            report.skipped.append(
                f"{rel_path}: refusing to write outside the project or through a symlink"
            )
            continue
        if not abs_path.exists():
            report.skipped.append(f"{rel_path}: file not found")
            continue
        try:
            with abs_path.open(encoding="utf-8", newline="") as fh:
                text = fh.read()
        except UnicodeDecodeError:
            report.skipped.append(f"{rel_path}: not UTF-8 text, skipped")
            continue
        except OSError as exc:
            report.skipped.append(f"{rel_path}: unreadable ({exc})")
            continue

        parts = _LINE_BREAK.split(text)
        lines, breaks = parts[0::2], parts[1::2]
        if text.endswith("\n"):
            lines.pop()  # the empty remainder after the final newline
        pending: list[AppliedFix] = []
        fixed_findings: list[Finding] = []

        # Apply the most severe / lowest line first is irrelevant since each fix is
        # confined to its own line; process in line order for determinism.
        for finding in sorted(file_findings, key=lambda f: f.location.start_line or 0):
            idx = (finding.location.start_line or 0) - 1
            if idx < 0 or idx >= len(lines):
                report.skipped.append(
                    f"{rel_path}:{finding.location.start_line}: line out of range"
                )
                continue
            original = lines[idx]
            fixed = fix_line(finding.rule_id, original)
            if fixed is None or fixed == original:
                report.skipped.append(
                    f"{rel_path}:{finding.location.start_line}: "
                    f"no deterministic fix for {finding.rule_id}"
                )
                continue
            verified = verify_line_fixed(finding.rule_id, fixed)
            if not verified and not include_unverified:
                report.skipped.append(
                    f"{rel_path}:{finding.location.start_line}: "
                    f"fix for {finding.rule_id} did not verify (use --include-unverified)"
                )
                continue

            lines[idx] = fixed
            pending.append(
                AppliedFix(
                    path=rel_path,
                    rule_id=finding.rule_id,
                    line=finding.location.start_line or 0,
                    before=original,
                    after=fixed,
                    finding_id=finding.id,
                    verified=verified,
                    fingerprint=finding.fingerprint(),
                )
            )
            fixed_findings.append(finding)

        if not pending:
            continue

        # Rejoin with each line's original separator (LF or CRLF).
        new_text = "".join(
            line + (breaks[i] if i < len(breaks) else "") for i, line in enumerate(lines)
        )

        # Guard against a rewrite that clears the detection but breaks the file.
        # For languages we can cheaply parse, reject the whole file's changes if
        # the result no longer parses.
        syntax_error = _syntax_error(rel_path, new_text)
        if syntax_error is not None:
            report.skipped.append(
                f"{rel_path}: fix reverted, would introduce a syntax error ({syntax_error})"
            )
            continue

        report.fixes.extend(pending)
        report.changed_files.append(rel_path)
        if not dry_run:
            _write(abs_path, new_text)
            for finding in fixed_findings:
                finding.metadata[APPLIED_KEY] = True
                finding.metadata["verification"] = "fixed"

    if audit and not dry_run and report.fixes:
        record_fix_events(project.root, "fix.applied", report.fixes, report)
    return report


def record_fix_events(
    root: Path,
    action: str,
    fixes: list[AppliedFix],
    report: ApplyReport | None = None,
    **details: object,
) -> None:
    """Append one audit record per fix. Never raises; a problem becomes a warning.

    Only the rule, location, fingerprint and verification state are recorded,
    never the changed source lines, which may contain the very secret a fix
    removed.
    """
    from argus.audit import AuditEvent, append_events, audit_enabled

    if not audit_enabled():
        return
    events = [
        AuditEvent(
            action=action,
            fingerprint=fix.fingerprint or None,
            rule=fix.rule_id,
            path=fix.path,
            reason=("verified" if fix.verified else "unverified") + " deterministic fix",
            details={"line": fix.line, "verified": fix.verified, **details},
        )
        for fix in fixes
    ]
    outcome = append_events(root, events)
    if report is not None:
        report.audit_records += outcome.written
        if outcome.warning:
            report.audit_warning = outcome.warning


def _syntax_error(rel_path: str, text: str) -> str | None:
    """Return a message if applying fixes made ``text`` invalid, else None.

    Languages with a fast, in-tree parser are validated so a rewrite can never
    write a structurally broken file. Formats without one are trusted, since the
    line-level rewrites are conservative.
    """
    lower = rel_path.lower()
    try:
        if lower.endswith(".py"):
            compile(text, rel_path, "exec")
        elif lower.endswith(".json"):
            json.loads(text)
        elif lower.endswith((".yml", ".yaml")):
            import yaml

            yaml.safe_load(text)
    except (SyntaxError, ValueError) as exc:
        return str(exc)
    except Exception as exc:  # yaml.YAMLError and friends
        return str(exc)
    return None


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="")
