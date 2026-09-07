"""CI/CD pipeline security scanner (GitHub Actions, GitLab CI, Jenkinsfile)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from argus.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from argus.core.plugin import Scanner, ScannerContext, scanner

_WORKFLOW_PATH = re.compile(
    r"(^|/)\.github/workflows/.+\.(ya?ml)$"
    r"|\.gitlab-ci\.ya?ml$"
    r"|Jenkinsfile$"
    r"|bitbucket-pipelines\.ya?ml$"
    r"|azure-pipelines\.ya?ml$"
    r"|(^|/)\.circleci/config\.ya?ml$",
    re.I,
)

_RULES: list[tuple[str, str, re.Pattern[str], Severity, str, str]] = [
    (
        "cicd.pull-request-target",
        "Workflow uses pull_request_target (dangerous with untrusted code)",
        re.compile(r"pull_request_target\s*:"),
        Severity.HIGH,
        "pull_request_target runs with base-branch permissions while checking out "
        "PR code, a common path to secret exfiltration.",
        "Prefer pull_request with explicit permissions, or restrict checkout and "
        "never run untrusted code with elevated tokens.",
    ),
    (
        "cicd.unpinned-action",
        "Mutable action reference (@branch instead of SHA)",
        re.compile(r"uses:\s*[\w./-]+@[a-zA-Z]"),
        Severity.MEDIUM,
        "Floating action tags can change without notice (supply-chain risk).",
        "Pin actions to a full commit SHA.",
    ),
    (
        "cicd.excessive-permissions",
        "Workflow grants write-all or contents: write globally",
        re.compile(r"permissions:\s*\n\s*contents:\s*write|permissions:\s*write-all"),
        Severity.MEDIUM,
        "Broad write permissions increase blast radius if the workflow is abused.",
        "Grant least privilege per job; use OIDC instead of long-lived tokens.",
    ),
    (
        "cicd.script-injection",
        "Expression interpolated directly into run script",
        re.compile(
            r"run:\s*[^\n]*\$\{\{\s*github\.(event\.(issue|comment|discussion)|head_ref)"
        ),
        Severity.HIGH,
        "Untrusted event fields in run scripts enable command injection.",
        "Pass values through env vars and quote them, or use action inputs.",
    ),
    (
        "cicd.hardcoded-secret",
        "Possible secret in workflow environment",
        re.compile(
            r"(?i)(password|secret|token|api_key)\s*:\s*['\"]?[A-Za-z0-9_./+=-]{8,}"
        ),
        Severity.CRITICAL,
        "Secrets in workflow YAML are visible in git history and fork PRs.",
        "Use platform secret stores (GitHub Secrets, GitLab CI variables).",
    ),
    (
        "cicd.curl-pipe-bash",
        "Downloads and pipes remote script in CI",
        re.compile(r"(?i)(curl|wget)[^\n|]*\|\s*(sudo\s+)?(bash|sh)\b"),
        Severity.HIGH,
        "Remote script execution in CI is a supply-chain pivot point.",
        "Vendor scripts with checksum verification or mirror internally.",
    ),
    (
        "cicd.privileged-container",
        "CI job runs a privileged Docker container",
        re.compile(r"(?i)privileged:\s*true|options:\s*.*--privileged"),
        Severity.HIGH,
        "Privileged CI containers can escape to the host runner.",
        "Drop --privileged unless strictly required; use rootless builds.",
    ),
]


@scanner
class CicdScanner(Scanner):
    name = "cicd"
    category = "cicd"
    description = "Flags risky patterns in GitHub Actions, GitLab CI, Jenkins, and other CI configs."

    file_local = True

    def applies_to(self, project) -> bool:
        return any(_WORKFLOW_PATH.search(f.rel_path) for f in project.files())

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        counter = 0
        for f in ctx.project.files():
            if not _WORKFLOW_PATH.search(f.rel_path):
                continue
            lines = f.lines()
            for rule_id, title, pattern, severity, why, fix in _RULES:
                for lineno, line in enumerate(lines, start=1):
                    if not pattern.search(line):
                        continue
                    counter += 1
                    yield Finding(
                        id=f"cicd:{rule_id}:{counter}",
                        rule_id=rule_id,
                        scanner="cicd",
                        title=title,
                        description=why,
                        location=Location(path=f.rel_path, start_line=lineno, snippet=line.strip()[:200]),
                        severity=severity,
                        confidence=Confidence.MEDIUM,
                        likelihood=Likelihood.POSSIBLE,
                        cwe=["CWE-94"] if "injection" in rule_id else (
                            ["CWE-250"] if "privileged" in rule_id else ["CWE-798"]
                        ),
                        owasp=["A05:2021-Security Misconfiguration"],
                        why_vulnerable=why,
                        remediation=Remediation(summary=fix, guidance=fix),
                        tags=["cicd"],
                    )
