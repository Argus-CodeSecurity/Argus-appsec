"""Cloud configuration patterns (AWS/Azure/GCP via Terraform and CloudFormation)."""

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

_CLOUD_FILES = re.compile(
    r"\.(tf|tfvars|hcl)$|cloudformation\.(ya?ml|json)$|/template\.(ya?ml|json)$",
    re.I,
)


def _is_cloudformation(f) -> bool:
    if f.suffix not in (".yml", ".yaml", ".json", ".template"):
        return False
    head = f.text()[:500]
    return "AWSTemplateFormatVersion" in head or "AWS::CloudFormation" in head

_RULES: list[tuple[str, str, re.Pattern[str], Severity, str, str]] = [
    (
        "cloud.public-s3-acl",
        "Public S3 ACL or public access block disabled",
        re.compile(r'acl\s*=\s*"public-read|public_access_block\s*\{[^}]*block_public_acls\s*=\s*false'),
        Severity.HIGH,
        "Public object storage exposes data to the internet.",
        "Enable block public access and use private ACLs with IAM policies.",
    ),
    (
        "cloud.open-security-group",
        "Security group or firewall open to 0.0.0.0/0",
        re.compile(r'0\.0\.0\.0/0|cidr\s*=\s*"0\.0\.0\.0/0"|source_ranges\s*=\s*\["0\.0\.0\.0/0"\]'),
        Severity.HIGH,
        "World-open ingress allows anyone to reach the service.",
        "Restrict to known CIDR ranges or private networks.",
    ),
    (
        "cloud.unencrypted-rds",
        "Database storage encryption disabled",
        re.compile(r"(?i)storage_encrypted\s*=\s*false|encrypt\s*=\s*false"),
        Severity.MEDIUM,
        "Unencrypted databases leak data if snapshots or disks are exposed.",
        "Set storage_encrypted / encrypt = true with KMS keys.",
    ),
    (
        "cloud.iam-wildcard",
        "IAM policy allows Action: * on Resource: *",
        re.compile(r'Action\s*=\s*"\*".*Resource\s*=\s*"\*"', re.S),
        Severity.CRITICAL,
        "Overly broad IAM policies enable full account takeover.",
        "Scope actions and resources to least privilege.",
    ),
    (
        "cloud.azure-public-blob",
        "Azure storage allows public blob access",
        re.compile(r"allow_blob_public_access\s*=\s*true"),
        Severity.HIGH,
        "Anonymous blob access can expose sensitive objects.",
        "Set allow_blob_public_access = false.",
    ),
    (
        "cloud.gcp-public-bucket",
        "GCP bucket IAM allUsers or allAuthenticatedUsers",
        re.compile(r"allUsers|allAuthenticatedUsers"),
        Severity.HIGH,
        "Public bucket IAM bindings expose objects globally.",
        "Remove allUsers bindings; use signed URLs or IAP.",
    ),
]


@scanner
class CloudScanner(Scanner):
    name = "cloud"
    category = "cloud"
    description = "Detects risky AWS/Azure/GCP patterns in Terraform and CloudFormation."

    file_local = True

    def applies_to(self, project) -> bool:
        arch = project.architecture or {}
        if arch.get("cloud") or arch.get("iac"):
            return True
        return any(_CLOUD_FILES.search(f.rel_path) or _is_cloudformation(f) for f in project.files())

    def scan(self, ctx: ScannerContext) -> Iterable[Finding]:
        counter = 0
        for f in ctx.project.files():
            if not (_CLOUD_FILES.search(f.rel_path) or _is_cloudformation(f)):
                continue
            text = f.text()
            for rule_id, title, pattern, severity, why, fix in _RULES:
                if rule_id == "cloud.iam-wildcard":
                    match = pattern.search(text)
                    if match:
                        counter += 1
                        snippet = match.group(0).replace("\n", " ").strip()[:200]
                        yield self._mk(
                            f.rel_path, rule_id, title, severity, why, fix, 1, snippet, counter,
                        )
                    continue
                for lineno, line in enumerate(f.lines(), start=1):
                    if pattern.search(line):
                        counter += 1
                        yield self._mk(f.rel_path, rule_id, title, severity, why, fix, lineno, line, counter)

    @staticmethod
    def _mk(path, rule, title, severity, why, fix, lineno, line, counter) -> Finding:
        snippet = line.strip()[:200] if isinstance(line, str) else "(policy block)"
        return Finding(
            id=f"cloud:{rule}:{counter}",
            rule_id=rule,
            scanner="cloud",
            title=title,
            description=why,
            location=Location(path=path, start_line=lineno, snippet=snippet),
            severity=severity,
            confidence=Confidence.MEDIUM,
            likelihood=Likelihood.POSSIBLE,
            cwe=["CWE-284"],
            owasp=["A05:2021-Security Misconfiguration"],
            why_vulnerable=why,
            remediation=Remediation(summary=fix, guidance=fix),
            tags=["cloud"],
        )
