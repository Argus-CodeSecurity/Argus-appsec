"""Unified-diff patches for findings, built from the deterministic rewrites.

The :class:`~nephilex.agents.patch.PatchAgent` uses this for its deterministic
tier, and the engine uses it directly when the AI agents are off (including
``nephilex check``). It depends only on the models and the rewrites, so
attaching a verified fix never loads the agents or a model client.
"""

from __future__ import annotations

import difflib
import re

from nephilex.core.models import Finding, Remediation
from nephilex.remediation.rewrites import fix_line, verify_line_fixed

_HUNK_HEADER = re.compile(r"^@@ -(\d+)((?:,\d+)?) \+(\d+)((?:,\d+)?) @@")


def unified_diff(path: str, before: str, after: str, start_line: int) -> str:
    """A unified diff replacing ``before`` with ``after`` at ``start_line``.

    Built with difflib so multi-line snippets get correct per-line markers
    and hunk lengths; hunk headers are shifted to the snippet's real line.
    """
    offset = max(start_line, 1) - 1
    out: list[str] = []
    for line in difflib.unified_diff(
        before.split("\n"),
        after.split("\n"),
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
        lineterm="",
    ):
        m = _HUNK_HEADER.match(line)
        if m:
            old_start = int(m.group(1)) + offset
            new_start = int(m.group(3)) + offset
            line = f"@@ -{old_start}{m.group(2)} +{new_start}{m.group(4)} @@"
        out.append(line)
    return "\n".join(out) + "\n"


def attach_deterministic_patch(finding: Finding) -> bool:
    """Attach the rule's deterministic fix to ``finding``; True when one applies.

    The patch is marked verified only when the rewritten line no longer
    triggers the detection. Findings without a rewrite are left unchanged.
    """
    original = finding.location.snippet or ""
    fixed = fix_line(finding.rule_id, original) if original else None
    if not fixed or fixed == original:
        return False
    if finding.remediation is None:
        finding.remediation = Remediation(summary="See remediation guidance.")
    finding.remediation.patch = unified_diff(
        finding.location.path, original, fixed, start_line=finding.location.start_line or 1
    )
    finding.remediation.verified = verify_line_fixed(finding.rule_id, fixed)
    finding.metadata["patch_source"] = "deterministic"
    return True
