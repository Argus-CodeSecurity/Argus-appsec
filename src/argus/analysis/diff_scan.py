"""Git diff-aware scanning helpers.

Supports ``argus scan --diff origin/main...HEAD``: report only findings that
touch lines or files the diff introduces. Dependency findings on changed lock
files or manifests are included even when the finding is file-level.

Reuses the same three-dot diff semantics as :mod:`argus.remediation.pr_review`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from argus.core.models import Finding
from argus.remediation import git_ops
from argus.remediation.pr_review import parse_changed_lines

# Manifests whose changes can introduce supply-chain risk without a line number.
DEPENDENCY_MANIFESTS = frozenset({
    "requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
    "Gemfile", "Gemfile.lock", "composer.json", "composer.lock",
    "pom.xml", "build.gradle", "build.gradle.kts",
})


@dataclass
class DiffScope:
    """Files and line numbers touched by a git revision range."""

    changed_lines: dict[str, set[int]]
    changed_files: frozenset[str]

    @property
    def empty(self) -> bool:
        return not self.changed_files and not self.changed_lines


def resolve_diff(root: Path, ref_spec: str, *, head: str = "HEAD") -> DiffScope:
    """Build a :class:`DiffScope` from a git ref spec such as ``origin/main...HEAD``.

    Accepts either a full three-dot range (``base...head``) or a base ref alone
    (``origin/main``), in which case ``base...head`` is used.
    """
    spec = ref_spec.strip()
    if "..." not in spec:
        spec = f"{spec}...{head}"
    text = git_ops.diff(root, "--unified=0", "--no-color", spec)
    changed_lines = parse_changed_lines(text)
    changed_files = frozenset(changed_lines.keys())
    return DiffScope(changed_lines=changed_lines, changed_files=changed_files)


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def finding_in_diff(finding: Finding, scope: DiffScope) -> bool:
    """Return True if a finding should be reported under diff-aware scanning."""
    path = finding.location.path or ""
    if not path:
        return False

    # Dependency / supply-chain findings on changed manifests or lock files.
    if _basename(path) in DEPENDENCY_MANIFESTS and path in scope.changed_files:
        return True

    # File-level finding on any changed file.
    if path in scope.changed_files and finding.location.start_line is None:
        return True

    line = finding.location.start_line
    if line is None:
        return False

    lines = scope.changed_lines.get(path)
    if lines is None:
        return False
    end = finding.location.end_line or line
    return any(n in lines for n in range(line, end + 1))


def filter_findings(findings: list[Finding], scope: DiffScope) -> tuple[list[Finding], int]:
    """Keep findings that fall inside ``scope``; return (kept, suppressed_count)."""
    if scope.empty:
        return findings, 0
    kept = [f for f in findings if finding_in_diff(f, scope)]
    return kept, len(findings) - len(kept)
