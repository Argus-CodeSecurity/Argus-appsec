"""Remediation: turning findings into applied fixes and pull requests.

This package holds the deterministic fix rewrites (shared by the patch agent and
the fix applier), the applier that writes fixes to real files, and the git /
hosting plumbing that opens a pull request with those fixes.
"""

from nephilex.remediation.rewrites import detection_pattern, fix_line, verify_line_fixed

__all__ = ["detection_pattern", "fix_line", "verify_line_fixed"]
