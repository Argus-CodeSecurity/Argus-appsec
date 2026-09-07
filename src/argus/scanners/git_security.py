"""Git repository security analysis (spec §16)."""

from __future__ import annotations

import subprocess
from collections.abc import Iterable
from pathlib import Path

from argus.core.models import Confidence, Finding, Likelihood, Location, Remediation, Severity
from argus.core.plugin import Scanner, ScannerContext, scanner


def _run_git(root: Path, *args: str) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), *args],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return None


@scanner
class GitSecurityScanner(Scanner):
    name = "git-security"
    category = "git"
    description = "Analyzes git history for dependency changes, dangerous files, and author anomalies."

    def applies_to(self, project) -> bool:
        return (project.root / ".git").is_dir()

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        root = ctx.project.root
        log = _run_git(root, "log", "--oneline", "-20")
        if not log:
            return

        authors = _run_git(root, "log", "-20", "--format=%ae")
        if authors:
            emails = [e.strip() for e in authors.splitlines() if e.strip()]
            domains = {e.split("@")[-1] for e in emails if "@" in e}
            if len(domains) > 4:
                yield Finding(
                    id="git-security:author-diversity",
                    rule_id="git.author-diversity",
                    scanner="git-security",
                    title="Recent commits from many email domains",
                    description="Unusual author diversity may indicate compromised contributors.",
                    location=Location(path=".git", snippet=f"{len(domains)} domains"),
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    likelihood=Likelihood.UNLIKELY,
                    why_vulnerable="Sudden contributor changes can precede supply-chain incidents.",
                    remediation=Remediation(summary="Review recent commits and enforce signed commits."),
                    tags=["git", "supply-chain"],
                    metadata={"verification": "detected"},
                )

        for pattern, title, sev in (
            ("requirements.txt", "Dependency manifest changed recently", Severity.MEDIUM),
            ("package.json", "npm manifest changed recently", Severity.MEDIUM),
            ("go.mod", "Go module manifest changed recently", Severity.MEDIUM),
            ("Cargo.toml", "Rust manifest changed recently", Severity.MEDIUM),
        ):
            diff = _run_git(root, "log", "-5", "--name-only", "--", pattern)
            if diff and pattern in diff:
                yield Finding(
                    id=f"git-security:dep-change:{pattern}",
                    rule_id="git.dependency-manifest-change",
                    scanner="git-security",
                    title=title,
                    description=f"{pattern} modified in recent commits; review for supply-chain risk.",
                    location=Location(path=pattern, snippet=pattern),
                    severity=sev,
                    confidence=Confidence.HIGH,
                    likelihood=Likelihood.POSSIBLE,
                    why_vulnerable="Dependency manifest edits are high-value supply-chain targets.",
                    remediation=Remediation(summary="Require PR review for dependency manifest changes."),
                    tags=["git", "supply-chain"],
                    metadata={"verification": "confirmed"},
                )

        tracked = _run_git(root, "ls-files")
        if tracked:
            dangerous = [
                p for p in tracked.splitlines()
                if p.endswith((".pem", ".key", ".p12", ".env", "id_rsa"))
            ]
            for path in dangerous[:10]:
                yield Finding(
                    id=f"git-security:tracked-secret:{path}",
                    rule_id="git.dangerous-tracked-file",
                    scanner="git-security",
                    title=f"Dangerous file tracked in git: {path}",
                    description="Private keys or env files in version control expose credentials.",
                    location=Location(path=path, snippet=path),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    likelihood=Likelihood.LIKELY,
                    why_vulnerable="Tracked secrets persist in history even after deletion.",
                    remediation=Remediation(summary="Remove from git history and rotate credentials."),
                    tags=["git", "secrets"],
                    metadata={"verification": "confirmed"},
                )
