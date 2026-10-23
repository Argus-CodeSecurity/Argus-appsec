"""Infrastructure-as-code scanner: Docker, Kubernetes, and Terraform.

Checks configuration files for common insecure defaults and misconfigurations,
running as root, privileged containers, world-open security groups, unencrypted
storage, and similar. Rules are line-oriented so a finding points at the exact
offending line.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from nephilex.core.models import (
    Confidence,
    Finding,
    Likelihood,
    Location,
    Remediation,
    Severity,
)
from nephilex.core.plugin import Scanner, ScannerContext, scanner
from nephilex.scanners._text import (
    CURL_PIPE_SHELL_RE,
    iter_scan_lines,
    iter_scan_windows,
    match_columns,
    snippet_line,
)


@dataclass
class IaCRule:
    id: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    cwe: list[str]
    why: str
    fix: str
    # File selector: which files this rule applies to (by name/glob substring).
    applies_when: str  # "dockerfile" | "kubernetes" | "terraform"
    confidence: Confidence = Confidence.MEDIUM
    negate: bool = False  # if True, finding fires when the pattern is ABSENT
    owasp: list[str] = field(default_factory=lambda: ["A05:2021-Security Misconfiguration"])


DOCKER_RULES = [
    IaCRule(
        id="docker-user-root",
        title="Container runs as root (no USER directive)",
        pattern=re.compile(r"(?i)^\s*USER\s"),
        negate=True,
        severity=Severity.MEDIUM,
        cwe=["CWE-250"],
        applies_when="dockerfile",
        why="Without a USER directive the container process runs as root, so a "
        "container breakout or app compromise starts with root privileges.",
        fix="Add a non-root USER (create a dedicated user and switch to it before the app runs).",
    ),
    IaCRule(
        id="docker-latest-tag",
        title="Base image pinned to ':latest' (or unpinned)",
        pattern=re.compile(r"(?im)^\s*FROM\s+\S+:latest\b|^\s*FROM\s+[^:@\s]+\s*$"),
        severity=Severity.LOW,
        cwe=["CWE-1104"],
        applies_when="dockerfile",
        confidence=Confidence.MEDIUM,
        why="An unpinned or :latest base image makes builds non-reproducible and can "
        "silently pull in a vulnerable or malicious image.",
        fix="Pin the base image to a specific version and, ideally, a digest.",
    ),
    IaCRule(
        id="docker-add-remote",
        title="Use of ADD with a remote URL",
        pattern=re.compile(r"(?im)^\s*ADD\s+https?://"),
        severity=Severity.LOW,
        cwe=["CWE-494"],
        applies_when="dockerfile",
        why="ADD with a URL fetches remote content into the image without integrity verification.",
        fix="Download with a pinned checksum, or use COPY for local files.",
    ),
    IaCRule(
        id="docker-curl-bash",
        title="Piping a downloaded script straight into a shell",
        pattern=CURL_PIPE_SHELL_RE,
        severity=Severity.MEDIUM,
        cwe=["CWE-494"],
        applies_when="dockerfile",
        why="curl | bash executes remote code with no verification; a compromised or "
        "MITM'd URL leads to a poisoned image.",
        fix="Download to a file, verify a checksum/signature, then execute.",
    ),
]

K8S_RULES = [
    IaCRule(
        id="k8s-privileged",
        title="Privileged container",
        pattern=re.compile(r"(?i)privileged:\s*true"),
        severity=Severity.HIGH,
        cwe=["CWE-250"],
        applies_when="kubernetes",
        why="A privileged container has almost all host capabilities, making a "
        "container escape trivial.",
        fix="Set privileged: false and grant only the specific capabilities needed.",
    ),
    IaCRule(
        id="k8s-run-as-root",
        title="Container allowed to run as root",
        pattern=re.compile(r"(?i)runAsNonRoot:\s*false"),
        severity=Severity.MEDIUM,
        cwe=["CWE-250"],
        applies_when="kubernetes",
        why="Allowing the container to run as root increases blast radius on compromise.",
        fix="Set runAsNonRoot: true and specify a non-zero runAsUser.",
    ),
    IaCRule(
        id="k8s-host-network",
        title="Pod uses host network namespace",
        pattern=re.compile(r"(?i)hostNetwork:\s*true"),
        severity=Severity.MEDIUM,
        cwe=["CWE-668"],
        applies_when="kubernetes",
        why="hostNetwork exposes the node's network stack to the pod, weakening isolation.",
        fix="Avoid hostNetwork unless strictly required; use a Service instead.",
    ),
]

TERRAFORM_RULES = [
    IaCRule(
        id="tf-sg-open-world",
        title="Security group open to 0.0.0.0/0",
        pattern=re.compile(r'cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"'),
        severity=Severity.HIGH,
        cwe=["CWE-284"],
        applies_when="terraform",
        why="An ingress rule open to the entire internet exposes the resource to "
        "everyone; combined with an open sensitive port this is directly "
        "exploitable.",
        fix="Restrict cidr_blocks to the specific networks that need access.",
    ),
    IaCRule(
        id="tf-s3-public",
        title="S3 bucket ACL set to public",
        pattern=re.compile(r'acl\s*=\s*"public-read(-write)?"'),
        severity=Severity.HIGH,
        cwe=["CWE-284"],
        applies_when="terraform",
        why="A public bucket ACL exposes stored objects to anyone.",
        fix="Use private ACLs and grant access through explicit policies or pre-signed URLs.",
    ),
    IaCRule(
        id="tf-unencrypted-storage",
        title="Storage resource without encryption",
        pattern=re.compile(r"(?i)encrypted\s*=\s*false"),
        severity=Severity.MEDIUM,
        cwe=["CWE-311"],
        applies_when="terraform",
        why="Disabling encryption at rest leaves stored data readable if the "
        "underlying media or snapshot is exposed.",
        fix="Set encrypted = true and manage keys via KMS.",
    ),
]

ALL_RULES = DOCKER_RULES + K8S_RULES + TERRAFORM_RULES


@scanner
class IaCScanner(Scanner):
    name = "iac"
    category = "iac"
    file_local = True
    description = "Detects insecure Docker, Kubernetes, and Terraform configuration."

    def applies_to(self, project) -> bool:
        arch = project.architecture or {}
        return bool(arch.get("containers") or arch.get("iac")) or bool(
            project.files_matching("Dockerfile*", "*.tf", "*.yaml", "*.yml")
        )

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        counter = 0
        for f in ctx.project.files():
            kind = self._classify(f)
            if kind is None:
                continue
            lines = f.lines()
            for rule in ALL_RULES:
                if rule.applies_when != kind:
                    continue
                if rule.negate:
                    # Line by line: a multiline `^\s*` over the whole file is
                    # quadratic on a file of blank lines.
                    if not any(rule.pattern.search(seg) for _, seg in iter_scan_lines(lines)):
                        counter += 1
                        yield self._finding(rule, counter, f.rel_path, 1, "(directive absent)")
                    continue
                reported: set[int] = set()
                for lineno, offset, line in iter_scan_windows(lines):
                    if lineno in reported:
                        continue
                    m = rule.pattern.search(line)
                    if m:
                        reported.add(lineno)
                        counter += 1
                        yield self._finding(
                            rule,
                            counter,
                            f.rel_path,
                            lineno,
                            snippet_line(line, 200),
                            match_columns(m, offset),
                        )

    @staticmethod
    def _classify(f) -> str | None:
        if f.name.startswith("Dockerfile") or f.name == "Containerfile":
            return "dockerfile"
        if f.suffix in (".tf", ".hcl"):
            return "terraform"
        if f.suffix in (".yml", ".yaml"):
            head = f.text()[:400]
            if "apiVersion:" in head and "kind:" in head:
                return "kubernetes"
        return None

    def _finding(
        self,
        rule: IaCRule,
        index: int,
        path: str,
        lineno: int,
        snippet: str,
        cols: tuple[int, int] | None = None,
    ) -> Finding:
        return Finding(
            id=f"{self.name}:{rule.id}:{index}",
            rule_id=f"{self.name}.{rule.id}",
            scanner=self.name,
            title=rule.title,
            description=rule.why,
            location=Location(
                path=path,
                start_line=lineno,
                end_line=lineno if cols else None,
                start_column=cols[0] if cols else None,
                end_column=cols[1] if cols else None,
                snippet=snippet,
            ),
            severity=rule.severity,
            confidence=rule.confidence,
            likelihood=Likelihood.POSSIBLE,
            cwe=rule.cwe,
            owasp=rule.owasp,
            why_vulnerable=rule.why,
            business_impact="Weakens the security posture of the deployed "
            "infrastructure and can enable or amplify a breach.",
            remediation=Remediation(summary=rule.fix, guidance=rule.fix),
            tags=["iac", rule.applies_when],
        )
